#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { verifyProofOffline, checkAnchorOnChain } from '../src/verify.mjs';

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--') && !a.includes('=')));
const rpcArg = args.find((a) => a.startsWith('--rpc='))?.slice(6);
const positional = args.filter((a) => !a.startsWith('--'));

if (positional.length !== 2 || flags.has('--help')) {
  console.log(`Usage: sellat-verify <file> <proof.json> [--offline] [--rpc=<url>]

Verifies a sellat-proof/2 artifact against a file, then (unless --offline)
asks a public JSON-RPC node whether the anchoring transaction really carries
the proof's Merkle root, and reads the block's time from the chain.
--offline checks the file and the proof's math only: it proves no date.
Exit code 0 = everything verified.`);
  process.exit(positional.length === 2 ? 0 : 2);
}

const [filePath, proofPath] = positional;

const fileHash = await new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  createReadStream(filePath)
    .on('data', (chunk) => hash.update(chunk))
    .on('end', () => resolve(hash.digest('hex')))
    .on('error', reject);
});

const proof = JSON.parse(await readFile(proofPath, 'utf8'));

const mark = (ok) => (ok ? '✓' : '✗');
let allOk = true;
// Times read from the chain, never the proof's own block_timestamp.
const provenTimes = [];

console.log(`file   ${filePath}`);
console.log(`sha256 ${fileHash}\n`);

const offline = verifyProofOffline(proof, fileHash);
for (const check of offline.checks) {
  console.log(` ${mark(check.ok)} ${check.name.padEnd(22)} ${check.detail}`);
  allOk &&= check.ok;
}

if (!flags.has('--offline')) {
  console.log('');
  for (const [i, anchor] of (proof.anchors ?? []).entries()) {
    try {
      const result = await checkAnchorOnChain(anchor, rpcArg ? { rpcUrl: rpcArg } : {});
      console.log(` ${mark(result.ok)} anchor[${i}] on-chain     ${result.detail}`);
      allOk &&= result.ok;
      if (result.ok) provenTimes.push(result.blockTimestamp);
    } catch (error) {
      console.log(` ${mark(false)} anchor[${i}] on-chain     ${String(error?.message ?? error)}`);
      allOk = false;
    }
  }
}

const earliest = provenTimes.sort()[0];
console.log(
  !allOk
    ? '\nVERIFICATION FAILED — at least one check did not pass.'
    : flags.has('--offline')
      ? '\nCONSISTENT (offline) — the file matches the proof and its math holds. No date is proven: run without --offline to read the anchoring block\'s time from the chain.'
      : `\nVERIFIED — this exact file existed no later than ${earliest} (the anchoring block's time, read from the chain).`
);
process.exit(allOk ? 0 : 1);
