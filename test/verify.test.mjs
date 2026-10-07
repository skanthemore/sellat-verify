import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAnchorOnChain, sha256HexFromBytes, verifyProofOffline } from '../src/verify.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const exampleFile = readFileSync(path.join(here, '../example/example.txt'));
const exampleProof = JSON.parse(
  readFileSync(path.join(here, '../example/example.proof.json'), 'utf8')
);

test('the shipped example verifies offline against its file', () => {
  const fileHash = sha256HexFromBytes(exampleFile);
  const result = verifyProofOffline(exampleProof, fileHash);
  for (const check of result.checks) {
    assert.equal(check.ok, true, `${check.name}: ${check.detail}`);
  }
  assert.equal(result.ok, true);
});

test('a different file fails the file-match check only', () => {
  const result = verifyProofOffline(exampleProof, sha256HexFromBytes(Buffer.from('other bytes')));
  assert.equal(result.ok, false);
  const fileCheck = result.checks.find((c) => c.name === 'file matches proof');
  assert.equal(fileCheck.ok, false);
});

test('tampering with the stored leaf value is detected', () => {
  const tampered = structuredClone(exampleProof);
  tampered.leaf.value = tampered.leaf.value.replace(/^./, tampered.leaf.value[0] === 'a' ? 'b' : 'a');
  const result = verifyProofOffline(tampered, sha256HexFromBytes(exampleFile));
  assert.equal(result.ok, false);
});

test('a payload not committing to the root is detected', () => {
  const tampered = structuredClone(exampleProof);
  tampered.anchors[0].payload = 'sellat:v2:' + '0'.repeat(64);
  const result = verifyProofOffline(tampered, sha256HexFromBytes(exampleFile));
  assert.equal(result.ok, false);
});

const rpcRouter = (answers, calls = []) => async (_url, init) => {
  const { method } = JSON.parse(init.body);
  calls.push(method);
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: answers[method] ?? null }));
};

// The example's block, as the chain states it (Polygon 91797318).
const chainTime = '0x' + (Date.parse(exampleProof.anchors[0].block_timestamp) / 1000).toString(16);
const exampleTx = {
  input: '0x' + Buffer.from(exampleProof.anchors[0].payload, 'utf8').toString('hex'),
  blockNumber: '0x' + exampleProof.anchors[0].block_number.toString(16),
  from: '0x33167f8eeb4299d0b357a7687b0fdda1f0d46972',
};
const exampleChain = (calls) =>
  rpcRouter(
    {
      eth_getTransactionByHash: exampleTx,
      eth_getBlockByNumber: { number: exampleTx.blockNumber, timestamp: chainTime, transactions: [] },
    },
    calls,
  );

test('on-chain check accepts a transaction carrying the payload, and returns the block time from the chain', async () => {
  const anchor = exampleProof.anchors[0];
  const calls = [];
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl: exampleChain(calls) });
  assert.equal(result.ok, true);
  assert.equal(result.blockNumber, anchor.block_number);
  assert.equal(result.blockTimestamp, '2026-08-10T22:30:04.000Z');
  assert.deepEqual(calls, ['eth_getTransactionByHash', 'eth_getBlockByNumber']);
});

// Security audit 2026-10-06, F01: the content and the anchor were real, only
// the date had been edited, and the verifier repeated the edited date.
test('on-chain check rejects a proof whose block_timestamp is not the block\'s time', async () => {
  const anchor = { ...exampleProof.anchors[0], block_timestamp: '1970-01-01T00:00:00Z' };
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl: exampleChain() });
  assert.equal(result.ok, false);
  assert.match(result.detail, /2026-08-10T22:30:04\.000Z.*1970-01-01/);
});

test('on-chain check takes the time from the chain when the proof states none', async () => {
  const { block_timestamp: _omitted, ...anchor } = exampleProof.anchors[0];
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl: exampleChain() });
  assert.equal(result.ok, true);
  assert.equal(result.blockTimestamp, '2026-08-10T22:30:04.000Z');
});

test('on-chain check proves nothing when the block\'s time cannot be read', async () => {
  const fetchImpl = rpcRouter({ eth_getTransactionByHash: exampleTx, eth_getBlockByNumber: null });
  const result = await checkAnchorOnChain(exampleProof.anchors[0], { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, false);
  assert.equal(result.blockTimestamp, undefined);
});

test('on-chain check rejects a transaction with a different payload', async () => {
  const anchor = exampleProof.anchors[0];
  const fakeTx = {
    input: '0x' + Buffer.from('sellat:v2:' + '0'.repeat(64), 'utf8').toString('hex'),
    blockNumber: '0x' + anchor.block_number.toString(16),
  };
  const fetchImpl = async () =>
    new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: fakeTx }));
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, false);
});

test('on-chain check rejects a missing transaction', async () => {
  const fetchImpl = async () =>
    new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: null }));
  const result = await checkAnchorOnChain(exampleProof.anchors[0], {
    rpcUrl: 'https://fake.rpc',
    fetchImpl,
  });
  assert.equal(result.ok, false);
});

// Public nodes often answer null to eth_getTransactionByHash for anything but
// recent transactions, while still serving the block. The proof's block
// number is enough to find the anchor anyway.

test('on-chain check finds an old anchor through its block when the node lost the hash index', async () => {
  const anchor = exampleProof.anchors[0];
  const inBlock = {
    hash: anchor.tx_hash.toUpperCase().replace('0X', '0x'),
    input: '0x' + Buffer.from(anchor.payload, 'utf8').toString('hex'),
    from: '0x33167f8eeb4299d0b357a7687b0fdda1f0d46972',
  };
  const fetchImpl = rpcRouter({
    eth_getTransactionByHash: null,
    eth_getBlockByNumber: { number: '0x' + anchor.block_number.toString(16), timestamp: chainTime, transactions: [{ hash: '0x' + 'a'.repeat(64) }, inBlock] },
  });
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, true);
  assert.equal(result.blockNumber, anchor.block_number);
  assert.equal(result.blockTimestamp, anchor.block_timestamp);
});

test('on-chain check still rejects an anchor that is not in the named block', async () => {
  const anchor = exampleProof.anchors[0];
  const fetchImpl = rpcRouter({
    eth_getTransactionByHash: null,
    eth_getBlockByNumber: { number: '0x' + anchor.block_number.toString(16), transactions: [{ hash: '0x' + 'b'.repeat(64) }] },
  });
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, false);
});

test('on-chain check still rejects a payload found through the block that does not match', async () => {
  const anchor = exampleProof.anchors[0];
  const fetchImpl = rpcRouter({
    eth_getTransactionByHash: null,
    eth_getBlockByNumber: {
      number: '0x' + anchor.block_number.toString(16),
      transactions: [{ hash: anchor.tx_hash, input: '0x' + Buffer.from('sellat:v2:' + '0'.repeat(64), 'utf8').toString('hex') }],
    },
  });
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, false);
});
