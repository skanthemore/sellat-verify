import { createHash } from 'node:crypto';
import { anchorPayload, computeLeaf, verifyPath } from './merkle.mjs';

/**
 * sellat-proof/2 verification, in two independent halves:
 *
 *   1. verifyProofOffline() — pure math, no network, no SELLAT:
 *      file hash → leaf → Merkle path → root → expected on-chain payload.
 *   2. checkAnchorOnChain() — asks any JSON-RPC node whether the anchoring
 *      transaction really carries that payload.
 *
 * If both halves pass, the file provably existed no later than the anchor's
 * block timestamp — and nothing in that conclusion depends on trusting
 * SELLAT, this package's author, or any database. That time is the one
 * checkAnchorOnChain() returns, read from the block itself: the proof's own
 * `block_timestamp` is only a claim, and a proof whose claim differs fails.
 * The offline half proves no date at all.
 */

const HEX_64 = /^[0-9a-f]{64}$/;

/** Default public JSON-RPC endpoints per EVM chain id. Any node works. */
export const DEFAULT_RPC = {
  1: 'https://ethereum-rpc.publicnode.com',
  137: 'https://polygon-bor-rpc.publicnode.com',
  80002: 'https://polygon-amoy-bor-rpc.publicnode.com',
};

export function sha256HexFromBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Verify everything that can be verified without a network.
 *
 * @param {object} proof - parsed proof.json
 * @param {string} [fileHashHex] - SHA-256 of the file being verified; omit to
 *   validate only the artifact's internal consistency.
 * @returns {{ ok: boolean, checks: Array<{ name: string, ok: boolean, detail: string }> }}
 */
export function verifyProofOffline(proof, fileHashHex) {
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok, detail });

  add('schema', proof?.schema === 'sellat-proof/2', `schema is "${proof?.schema}"`);

  const contentHash = proof?.content?.hash ?? '';
  add(
    'content hash format',
    proof?.content?.algorithm === 'SHA-256' && HEX_64.test(contentHash),
    `${proof?.content?.algorithm} ${contentHash.slice(0, 16)}…`
  );

  if (fileHashHex !== undefined) {
    add(
      'file matches proof',
      fileHashHex === contentHash,
      fileHashHex === contentHash
        ? 'SHA-256 of the file equals content.hash'
        : `file is ${fileHashHex.slice(0, 16)}…, proof says ${contentHash.slice(0, 16)}…`
    );
  }

  let leaf = '';
  try {
    leaf = computeLeaf(proof?.proof_id ?? '', contentHash);
  } catch {
    /* leaf stays empty and the check below fails */
  }
  add(
    'leaf recomputation',
    leaf !== '' && leaf === proof?.leaf?.value,
    leaf === proof?.leaf?.value ? 'leaf formula reproduces leaf.value' : 'leaf.value does not match the formula'
  );

  const root = proof?.merkle?.root ?? '';
  const pathOk =
    leaf !== '' && Array.isArray(proof?.merkle?.path) && verifyPath(leaf, proof.merkle.path, root);
  add(
    'merkle path',
    pathOk,
    pathOk ? `path folds to root ${root.slice(0, 16)}…` : 'path does not fold to merkle.root'
  );

  const anchors = Array.isArray(proof?.anchors) ? proof.anchors : [];
  add('has anchors', anchors.length > 0, `${anchors.length} anchor(s)`);

  let expectedPayload = '';
  try {
    expectedPayload = anchorPayload(root);
  } catch {
    /* covered by the merkle path check */
  }
  for (const [i, anchor] of anchors.entries()) {
    add(
      `anchor[${i}] payload`,
      expectedPayload !== '' && anchor?.payload === expectedPayload,
      anchor?.payload === expectedPayload
        ? `payload commits to the root (${anchor?.network ?? anchor?.chain_id})`
        : `payload "${anchor?.payload}" ≠ expected "${expectedPayload}"`
    );
  }

  return { ok: checks.every((c) => c.ok), checks };
}

function hexToUtf8(hex) {
  return Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex').toString('utf8');
}

/**
 * Ask a JSON-RPC node for the anchoring transaction and compare what the
 * chain says with what the proof claims. Works with any node for the right
 * chain — pass your own rpcUrl to avoid trusting the defaults.
 *
 * On success `blockTimestamp` is the anchoring block's time as the chain
 * states it (ISO-8601 UTC): the only time a verifier may present as proven.
 *
 * @param {object} anchor - one entry of proof.anchors
 * @param {{ rpcUrl?: string, fetchImpl?: typeof fetch }} [options]
 */
export async function checkAnchorOnChain(anchor, options = {}) {
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC[anchor?.chain_id];
  const fetchImpl = options.fetchImpl ?? fetch;

  if (!rpcUrl) {
    return { ok: false, detail: `no RPC endpoint known for chain_id ${anchor?.chain_id}; pass --rpc` };
  }

  const call = async (method, params) => {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    if (!response.ok) {
      return { error: `RPC ${rpcUrl} answered HTTP ${response.status}` };
    }
    const body = await response.json();
    return { result: body?.result ?? null };
  };

  const byHash = await call('eth_getTransactionByHash', [anchor.tx_hash]);
  if (byHash.error) {
    return { ok: false, detail: byHash.error };
  }
  let tx = byHash.result;
  let block = null;

  // Many public nodes keep every block but index transactions by hash only
  // for recent ones, so an anchor a few weeks old comes back as null. The
  // proof names its block: read that block and look for the transaction in it.
  if (!tx && anchor.block_number != null) {
    const named = await call('eth_getBlockByNumber', ['0x' + Number(anchor.block_number).toString(16), true]);
    if (named.error) {
      return { ok: false, detail: named.error };
    }
    const wanted = String(anchor.tx_hash).toLowerCase();
    const found = (named.result?.transactions ?? []).find(
      (candidate) => typeof candidate === 'object' && String(candidate.hash).toLowerCase() === wanted,
    );
    if (found) {
      tx = { ...found, blockNumber: found.blockNumber ?? named.result.number };
      block = named.result;
    }
  }

  if (!tx) {
    return { ok: false, detail: `transaction ${anchor.tx_hash} not found on chain ${anchor.chain_id}` };
  }

  const onChainPayload = hexToUtf8(tx.input ?? tx.data ?? '0x');
  if (onChainPayload !== anchor.payload) {
    return { ok: false, detail: `on-chain payload "${onChainPayload}" ≠ proof payload "${anchor.payload}"` };
  }

  const blockNumber = tx.blockNumber ? parseInt(tx.blockNumber, 16) : null;
  if (blockNumber === null) {
    return { ok: false, detail: 'transaction exists but is not yet included in a block' };
  }
  if (anchor.block_number != null && blockNumber !== anchor.block_number) {
    return { ok: false, detail: `chain says block ${blockNumber}, proof says ${anchor.block_number}` };
  }

  // The time comes from the block, never from the proof: a proof.json is
  // plain text, and its block_timestamp can say anything.
  if (!block) {
    const header = await call('eth_getBlockByNumber', ['0x' + blockNumber.toString(16), false]);
    if (header.error) {
      return { ok: false, detail: header.error };
    }
    block = header.result;
  }
  const seconds = block?.timestamp != null ? parseInt(block.timestamp, 16) : NaN;
  if (!Number.isFinite(seconds)) {
    return { ok: false, detail: `could not read the time of block ${blockNumber}; retry, or pass --rpc` };
  }
  const blockTimestamp = new Date(seconds * 1000).toISOString();
  if (anchor.block_timestamp != null && Date.parse(anchor.block_timestamp) !== seconds * 1000) {
    return { ok: false, detail: `block ${blockNumber} is from ${blockTimestamp}, proof says ${anchor.block_timestamp}` };
  }

  return {
    ok: true,
    detail: `chain ${anchor.chain_id} confirms payload in block ${blockNumber} of ${blockTimestamp} (from ${tx.from})`,
    blockNumber,
    blockTimestamp,
    from: tx.from,
  };
}
