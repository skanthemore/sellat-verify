import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { anchorPayload, buildTree, computeLeaf, verifyPath } from '../src/merkle.mjs';

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const parent = (l, r) =>
  sha256(Buffer.concat([Buffer.from(l, 'hex'), Buffer.from(r, 'hex')]));
const leafOf = (i) => sha256(`leaf-${i}`);

test('leaf formula matches SPEC.md §2 exactly', () => {
  const id = 'd268831c-4c70-4226-97d9-bf1cd703d365';
  const hash = sha256('bytes');
  assert.equal(computeLeaf(id, hash), sha256(`sellat-leaf:v2:${id}:${hash}`));
});

test('single-leaf tree: root === leaf, empty path', () => {
  const leaf = leafOf(0);
  const tree = buildTree([leaf]);
  assert.equal(tree.root, leaf);
  assert.deepEqual(tree.paths[0], []);
  assert.equal(verifyPath(leaf, [], tree.root), true);
});

test('parent = SHA-256(left || right) over raw bytes (SPEC.md §3)', () => {
  const [a, b] = [leafOf(1), leafOf(2)];
  const tree = buildTree([a, b]);
  assert.equal(tree.root, parent(a, b));
});

test('odd node counts promote the last node without duplication', () => {
  const [a, b, c] = [leafOf(1), leafOf(2), leafOf(3)];
  const tree = buildTree([a, b, c]);
  assert.equal(tree.root, parent(parent(a, b), c));
  [a, b, c].forEach((leaf, i) => assert.equal(verifyPath(leaf, tree.paths[i], tree.root), true));
});

test('every path verifies for larger trees; tampering is detected', () => {
  const leaves = Array.from({ length: 100 }, (_, i) => leafOf(i));
  const tree = buildTree(leaves);
  leaves.forEach((leaf, i) => assert.equal(verifyPath(leaf, tree.paths[i], tree.root), true));

  assert.equal(verifyPath(leafOf(999), tree.paths[42], tree.root), false);
  const flipped = tree.paths[42].map((s, i) =>
    i === 0 ? { ...s, position: s.position === 'left' ? 'right' : 'left' } : s
  );
  assert.equal(verifyPath(leaves[42], flipped, tree.root), false);
});

test('anchor payload format (SPEC.md §4)', () => {
  const root = leafOf(7);
  assert.equal(anchorPayload(root), `sellat:v2:${root}`);
});
