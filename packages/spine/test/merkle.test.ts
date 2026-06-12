import { describe, expect, it } from 'vitest';
import { sha256Bytes } from '../src/hash.js';
import {
  buildInclusionProof,
  emptyRootBytes,
  largestPowerOfTwoBelow,
  leafHash,
  merkleRootBytes,
  merkleRootHex,
  nodeHash,
  verifyInclusionProof,
} from '../src/merkle.js';

function leaf(n: number): Buffer {
  return Buffer.from(`leaf-${n}`, 'utf8');
}

describe('RFC 6962 Merkle tree', () => {
  it('empty tree root is SHA-256 of empty string', () => {
    expect(merkleRootHex([])).toBe(sha256Bytes(Buffer.alloc(0)).toString('hex'));
    expect(emptyRootBytes().toString('hex')).toBe(merkleRootHex([]));
  });

  it('single-leaf root is the leaf hash', () => {
    expect(merkleRootBytes([leaf(0)]).toString('hex')).toBe(
      leafHash(leaf(0)).toString('hex'),
    );
  });

  it('two-leaf root composes the node hash', () => {
    const expected = nodeHash(leafHash(leaf(0)), leafHash(leaf(1)));
    expect(merkleRootBytes([leaf(0), leaf(1)]).toString('hex')).toBe(
      expected.toString('hex'),
    );
  });

  it('largestPowerOfTwoBelow', () => {
    expect(largestPowerOfTwoBelow(2)).toBe(1);
    expect(largestPowerOfTwoBelow(3)).toBe(2);
    expect(largestPowerOfTwoBelow(5)).toBe(4);
    expect(largestPowerOfTwoBelow(8)).toBe(4);
    expect(largestPowerOfTwoBelow(9)).toBe(8);
  });

  it('inclusion proofs verify for every leaf across many tree sizes', () => {
    for (let size = 1; size <= 33; size++) {
      const leaves = Array.from({ length: size }, (_, i) => leaf(i));
      const root = merkleRootHex(leaves);
      for (let i = 0; i < size; i++) {
        const proof = buildInclusionProof(i, leaves);
        expect(proof.merkleRoot).toBe(root);
        expect(verifyInclusionProof(leaves[i] as Buffer, proof)).toBe(true);
      }
    }
  });

  it('rejects a proof against the wrong leaf', () => {
    const leaves = [leaf(0), leaf(1), leaf(2), leaf(3), leaf(4)];
    const proof = buildInclusionProof(2, leaves);
    expect(verifyInclusionProof(leaf(99), proof)).toBe(false);
  });

  it('rejects a proof with a corrupted audit path', () => {
    const leaves = [leaf(0), leaf(1), leaf(2), leaf(3)];
    const proof = buildInclusionProof(1, leaves);
    const tampered = {
      ...proof,
      auditPath: [...proof.auditPath.slice(0, -1), 'ff'.repeat(32)],
    };
    expect(verifyInclusionProof(leaves[1] as Buffer, tampered)).toBe(false);
  });

  it('rejects an out-of-range leaf index', () => {
    const leaves = [leaf(0), leaf(1)];
    expect(() => buildInclusionProof(5, leaves)).toThrow(RangeError);
    expect(
      verifyInclusionProof(leaf(0), {
        leafIndex: 5,
        treeSize: 2,
        auditPath: [],
        merkleRoot: merkleRootHex(leaves),
      }),
    ).toBe(false);
  });

  it('rejects a proof whose path length is wrong for the tree size', () => {
    const leaves = [leaf(0), leaf(1), leaf(2), leaf(3)];
    const proof = buildInclusionProof(0, leaves);
    expect(
      verifyInclusionProof(leaves[0] as Buffer, { ...proof, auditPath: [] }),
    ).toBe(false);
  });
});
