# sellat-verify

**Don't trust SELLAT. Verify.**

`sellat-verify` is a standalone, **zero-dependency** verifier for
[SELLAT](https://sellat.app) proof-of-existence artifacts
(`sellat-proof/2`). Given a file and its `proof.json`, it proves — using only
math and the public blockchain — that the exact bytes of that file existed no
later than a specific moment in time.

No SELLAT server, database or goodwill is involved in verification. If
sellat.app disappeared tomorrow, every proof it ever issued would still
verify. That is the point.

## Try it now — on a real proof

This repository ships a real example: a file whose proof was anchored on
**Polygon mainnet** in transaction
[`0xdeb68fad…`](https://polygonscan.com/tx/0xdeb68fad7312db74275cbcc72533f3a60899aea2f35da660c15e5867b9f41903).

```console
$ git clone https://github.com/skanthemore/sellat-verify && cd sellat-verify
$ node bin/sellat-verify.mjs example/example.txt example/example.proof.json

 ✓ schema                 schema is "sellat-proof/2"
 ✓ content hash format    SHA-256 2ad295bdf52f661a…
 ✓ file matches proof     SHA-256 of the file equals content.hash
 ✓ leaf recomputation     leaf formula reproduces leaf.value
 ✓ merkle path            path folds to root 3c6e1005a0cb2699…
 ✓ has anchors            1 anchor(s)
 ✓ anchor[0] payload      payload commits to the root (Polygon Mainnet)

 ✓ anchor[0] on-chain     chain 137 confirms payload in block 91797318 (from 0x33167f8e…)

VERIFIED — this exact file existed no later than 2026-08-10T22:30:04.000Z.
```

Change a single byte of `example.txt` and verification fails.

### Too much code? Verify it by hand

This example's batch has a single leaf, so you can check it with nothing but
`sha256sum` and a block explorer:

```console
# 1. Hash the file
$ sha256sum example/example.txt
2ad295bdf52f661acda66158a7b20fc7c982e190b2645117ea6a77583703e291

# 2. Compute the leaf (single-leaf batch ⇒ the leaf IS the Merkle root)
$ printf '%s' 'sellat-leaf:v2:d268831c-4c70-4226-97d9-bf1cd703d365:2ad295bdf52f661acda66158a7b20fc7c982e190b2645117ea6a77583703e291' | sha256sum
3c6e1005a0cb26993e3b445e5c755d75bc89ab60012cf8670cdd9c279b78b05c
```

3. Open the [transaction on Polygonscan](https://polygonscan.com/tx/0xdeb68fad7312db74275cbcc72533f3a60899aea2f35da660c15e5867b9f41903),
view its input data as UTF-8, and read:

```
sellat:v2:3c6e1005a0cb26993e3b445e5c755d75bc89ab60012cf8670cdd9c279b78b05c
```

That root sits in Polygon block **91797318**, timestamped
**2026-08-10 22:30:04 UTC**. Nobody — including SELLAT — can rewrite that.

## Usage

```console
$ sellat-verify <file> <proof.json>              # offline checks + on-chain check
$ sellat-verify <file> <proof.json> --offline    # math only, no network
$ sellat-verify <file> <proof.json> --rpc=<url>  # use your own JSON-RPC node
```

Exit code `0` means every check passed. By default the on-chain check uses
public RPC endpoints; pass `--rpc=` to use a node you control, so the
verification trusts nothing chosen by anyone else.

As a library:

```js
import { verifyProofOffline, checkAnchorOnChain } from 'sellat-verify';
```

## How verification works

1. `SHA-256(file)` must equal `content.hash`;
2. the leaf is recomputed as `SHA-256('sellat-leaf:v2:' + proof_id + ':' + content.hash)`;
3. the Merkle path folds the leaf back to `merkle.root`;
4. every anchor's payload must be exactly `sellat:v2:<merkle.root>`;
5. the anchoring transaction is fetched from the chain and must carry that
   payload in its input data.

Steps 1–4 are pure computation. Step 5 works against any node or explorer.
The full format is specified in [SPEC.md](SPEC.md) and is frozen: issued
proofs verify forever; format changes require a new schema version.

## Trust layers

Artifacts can carry more than one independent layer over the same Merkle
root: EVM anchors (`anchors[]`, e.g. Polygon in minutes) and optional
`attestations[]` — currently **Bitcoin via OpenTimestamps**, a standard
`.ots` file you can verify with OTS tooling, at no cost. Layers verify
separately; none depends on SELLAT or on each other. See SPEC.md §7.

## What a proof does and does not claim

A sellat-proof/2 artifact proves **existence and integrity at a point in
time**: these exact bytes existed no later than the anchor's block timestamp.
It deliberately does **not** claim authorship, ownership, or that the
content is true or authentic. In a world where anything can be fabricated
*now*, the only unforgeable thing is the past — that is exactly what this
verifies, and nothing more.

## About

Built by [SELLAT](https://sellat.app) — proof of existence for one file or a
million, on the same engine. The hosted product is rolling out `proof.json`
downloads for every proof; this verifier and the format specification are the
stable, public reference.

MIT licensed. Issues and PRs welcome.
