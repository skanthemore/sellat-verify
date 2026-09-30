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

test('on-chain check accepts a transaction carrying the payload', async () => {
  const anchor = exampleProof.anchors[0];
  const fakeTx = {
    input: '0x' + Buffer.from(anchor.payload, 'utf8').toString('hex'),
    blockNumber: '0x' + anchor.block_number.toString(16),
    from: '0x33167f8eeb4299d0b357a7687b0fdda1f0d46972',
  };
  const fetchImpl = async () =>
    new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: fakeTx }));
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, true);
  assert.equal(result.blockNumber, anchor.block_number);
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
const rpcRouter = (answers) => async (_url, init) => {
  const { method } = JSON.parse(init.body);
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: answers[method] ?? null }));
};

test('on-chain check finds an old anchor through its block when the node lost the hash index', async () => {
  const anchor = exampleProof.anchors[0];
  const inBlock = {
    hash: anchor.tx_hash.toUpperCase().replace('0X', '0x'),
    input: '0x' + Buffer.from(anchor.payload, 'utf8').toString('hex'),
    from: '0x33167f8eeb4299d0b357a7687b0fdda1f0d46972',
  };
  const fetchImpl = rpcRouter({
    eth_getTransactionByHash: null,
    eth_getBlockByNumber: { number: '0x' + anchor.block_number.toString(16), transactions: [{ hash: '0x' + 'a'.repeat(64) }, inBlock] },
  });
  const result = await checkAnchorOnChain(anchor, { rpcUrl: 'https://fake.rpc', fetchImpl });
  assert.equal(result.ok, true);
  assert.equal(result.blockNumber, anchor.block_number);
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
