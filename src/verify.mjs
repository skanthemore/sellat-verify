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
 * SELLAT, this package's author, or any database.
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
 * @param {object} anchor - one entry of proof.anchors
 * @param {{ rpcUrl?: string, fetchImpl?: typeof fetch }} [options]
 */
export async function checkAnchorOnChain(anchor, options = {}) {
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC[anchor?.chain_id];
  const fetchImpl = options.fetchImpl ?? fetch;

  if (!rpcUrl) {
    return { ok: false, detail: `no RPC endpoint known for chain_id ${anchor?.chain_id}; pass --rpc` };
  }

  const response = await fetchImpl(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_getTransactionByHash',
      params: [anchor.tx_hash],
    }),
  });

  if (!response.ok) {
    return { ok: false, detail: `RPC ${rpcUrl} answered HTTP ${response.status}` };
  }

  const body = await response.json();
  const tx = body?.result;
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

  return {
    ok: true,
    detail: `chain ${anchor.chain_id} confirms payload in block ${blockNumber} (from ${tx.from})`,
    blockNumber,
    from: tx.from,
  };
}
