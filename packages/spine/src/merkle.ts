import type { InclusionProof } from '@attestor/types';
import { sha256Bytes } from './hash.js';

/**
 * RFC 6962 (Certificate Transparency) Merkle tree hashing.
 *
 * We do not hand-roll tree storage; we compute the tree hash and audit paths
 * deterministically from the ordered list of leaf data on demand. Domain
 * separation (0x00 for leaves, 0x01 for internal nodes) prevents second-preimage
 * attacks where a leaf could masquerade as an internal node.
 */

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

/** Hash of an empty tree: SHA-256 of the empty string. */
export function emptyRootBytes(): Buffer {
  return sha256Bytes(Buffer.alloc(0));
}

/** Leaf hash: SHA-256(0x00 || data). */
export function leafHash(data: Buffer): Buffer {
  return sha256Bytes(Buffer.concat([LEAF_PREFIX, data]));
}

/** Internal node hash: SHA-256(0x01 || left || right). */
export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256Bytes(Buffer.concat([NODE_PREFIX, left, right]));
}

/** Largest power of two strictly less than n (requires n > 1). */
export function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k << 1 < n) {
    k <<= 1;
  }
  return k;
}

/** RFC 6962 Merkle Tree Hash over `leaves` (leaf-data buffers). */
export function merkleRootBytes(leaves: readonly Buffer[]): Buffer {
  if (leaves.length === 0) {
    return emptyRootBytes();
  }
  if (leaves.length === 1) {
    return leafHash(leaves[0] as Buffer);
  }
  const k = largestPowerOfTwoBelow(leaves.length);
  const left = merkleRootBytes(leaves.slice(0, k));
  const right = merkleRootBytes(leaves.slice(k));
  return nodeHash(left, right);
}

/** Hex Merkle root over a list of leaf-data buffers. */
export function merkleRootHex(leaves: readonly Buffer[]): string {
  return merkleRootBytes(leaves).toString('hex');
}

/** RFC 6962 audit path for the leaf at `index`, ordered leaf-to-root. */
function auditPath(index: number, leaves: readonly Buffer[]): Buffer[] {
  if (leaves.length <= 1) {
    return [];
  }
  const k = largestPowerOfTwoBelow(leaves.length);
  if (index < k) {
    // Leaf is in the left subtree; its sibling is the right subtree root.
    return [...auditPath(index, leaves.slice(0, k)), merkleRootBytes(leaves.slice(k))];
  }
  // Leaf is in the right subtree; its sibling is the left subtree root.
  return [
    ...auditPath(index - k, leaves.slice(k)),
    merkleRootBytes(leaves.slice(0, k)),
  ];
}

/**
 * The side each audit-path sibling sits on, derived purely from (index, size)
 * with no leaf data — this is what makes verification O(log n). Returned
 * leaf-to-root, matching `auditPath` ordering. 'R' = sibling is the right child
 * (so the running hash is the left input); 'L' = sibling is the left child.
 */
function siblingSides(index: number, size: number): ('L' | 'R')[] {
  if (size <= 1) {
    return [];
  }
  const k = largestPowerOfTwoBelow(size);
  if (index < k) {
    return [...siblingSides(index, k), 'R'];
  }
  return [...siblingSides(index - k, size - k), 'L'];
}

/**
 * Build an inclusion proof for the leaf at `index` against the tree of `leaves`.
 * `leaves` are the raw leaf-data buffers (e.g. record-hash bytes).
 */
export function buildInclusionProof(
  index: number,
  leaves: readonly Buffer[],
): InclusionProof {
  if (index < 0 || index >= leaves.length) {
    throw new RangeError(
      `leaf index ${index} out of range for tree size ${leaves.length}`,
    );
  }
  return {
    leafIndex: index,
    treeSize: leaves.length,
    auditPath: auditPath(index, leaves).map((b) => b.toString('hex')),
    merkleRoot: merkleRootHex(leaves),
  };
}

/**
 * Verify an inclusion proof: recompute the root from the leaf data and audit
 * path and compare against the claimed root. Uses the same structural recursion
 * as generation, so the two cannot drift. O(log n) work, no leaves required.
 */
export function verifyInclusionProof(leafData: Buffer, proof: InclusionProof): boolean {
  if (proof.leafIndex < 0 || proof.leafIndex >= proof.treeSize) {
    return false;
  }
  const sides = siblingSides(proof.leafIndex, proof.treeSize);
  if (sides.length !== proof.auditPath.length) {
    return false;
  }
  let hash = leafHash(leafData);
  for (let i = 0; i < proof.auditPath.length; i++) {
    const sibling = Buffer.from(proof.auditPath[i] as string, 'hex');
    hash = sides[i] === 'R' ? nodeHash(hash, sibling) : nodeHash(sibling, hash);
  }
  return hash.toString('hex') === proof.merkleRoot;
}
