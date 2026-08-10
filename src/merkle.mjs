import { createHash } from 'node:crypto';

/**
 * Merkle core for the sellat-proof/2 format — reference implementation.
 * The full format is documented in SPEC.md.
 *
 * The rules in this file ARE the proof format. Once a proof.json referencing
 * them has been issued, they can never change — only a new schema version can
 * introduce different rules. Keep them boring:
 *
 *   leaf         = SHA-256(utf8("sellat-leaf:v2:" + proofId + ":" + contentHash))
 *   digest leaf  = SHA-256(utf8("sellat-digest-leaf:v2:" + batchId + ":" + batchRoot))
 *   parent       = SHA-256(leftBytes || rightBytes)        (32-byte buffers)
 *   odd node     = promoted unchanged to the next level (never duplicated)
 *   root of [x]  = x
 *
 * Including proofId in the leaf makes two proofs of identical bytes distinct
 * leaves, so a Merkle path can never be replayed for a different proof.
 *
 *
 * @typedef {{ position: 'left' | 'right', hash: string }} MerklePathStep
 *   `position` is which side the SIBLING hash sits on when recomputing the
 *   parent.
 * @typedef {{ root: string, paths: MerklePathStep[][] }} MerkleTree
 *   `paths[i]` proves `leaves[i]`; same order as the input.
 */

const HEX_64 = /^[0-9a-f]{64}$/;

/** @param {Uint8Array | string} data */
function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/** @param {string} value @param {string} what */
function assertHex64(value, what) {
  if (!HEX_64.test(value)) {
    throw new Error(`${what} must be 64 lowercase hex characters, got: ${value}`);
  }
}

/** @param {string} proofId @param {string} contentHash */
export function computeLeaf(proofId, contentHash) {
  assertHex64(contentHash, 'contentHash');
  return sha256Hex(`sellat-leaf:v2:${proofId}:${contentHash}`);
}

/** @param {string} batchId @param {string} batchRoot */
export function computeDigestLeaf(batchId, batchRoot) {
  assertHex64(batchRoot, 'batchRoot');
  return sha256Hex(`sellat-digest-leaf:v2:${batchId}:${batchRoot}`);
}

/** @param {string} left @param {string} right */
function parent(left, right) {
  return sha256Hex(Buffer.concat([Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));
}

/**
 * @param {readonly string[]} leaves
 * @returns {MerkleTree}
 */
export function buildTree(leaves) {
  if (leaves.length === 0) {
    throw new Error('cannot build a Merkle tree with no leaves');
  }
  leaves.forEach((leaf, i) => assertHex64(leaf, `leaf[${i}]`));

  /** @type {MerklePathStep[][]} */
  const paths = leaves.map(() => []);
  // Track, for every original leaf, which node at the current level its
  // partial proof has reached. Odd nodes are promoted, so several leaves can
  // sit under the same current node.
  let level = [...leaves];
  let leafToNode = leaves.map((_, i) => i);

  while (level.length > 1) {
    const next = [];
    for (let n = 0; n < level.length; n += 2) {
      if (n + 1 === level.length) {
        // Odd node: promote unchanged, no path step for its leaves.
        next.push(level[n]);
        continue;
      }
      /** @type {Record<number, MerklePathStep>} */
      const step = {
        [n]: { position: 'right', hash: level[n + 1] },
        [n + 1]: { position: 'left', hash: level[n] },
      };
      leafToNode.forEach((node, leafIndex) => {
        if (node === n || node === n + 1) {
          paths[leafIndex].push(step[node]);
        }
      });
      next.push(parent(level[n], level[n + 1]));
    }
    leafToNode = leafToNode.map((node) => Math.floor(node / 2));
    level = next;
  }

  return { root: level[0], paths };
}

/**
 * @param {string} leaf
 * @param {readonly MerklePathStep[]} path
 * @param {string} root
 */
export function verifyPath(leaf, path, root) {
  if (!HEX_64.test(leaf) || !HEX_64.test(root)) {
    return false;
  }
  let current = leaf;
  for (const step of path) {
    if (!HEX_64.test(step.hash)) {
      return false;
    }
    current = step.position === 'left' ? parent(step.hash, current) : parent(current, step.hash);
  }
  return current === root;
}

/**
 * The exact bytes anchored on-chain for a batch root (SPEC.md §4).
 * @param {string} merkleRoot
 */
export function anchorPayload(merkleRoot) {
  assertHex64(merkleRoot, 'merkleRoot');
  return `sellat:v2:${merkleRoot}`;
}
