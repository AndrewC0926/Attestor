import type { Checkpoint, EvidenceRecord } from '@attestor/types';
import { canonicalize } from './canonical.js';
import { merkleRootHex } from './merkle.js';
import { signMessage, verifySignature } from './signing.js';
import type { Signer } from './signer.js';

/**
 * Checkpoints are signed tree heads: a Merkle root over records 1..treeSize,
 * signed with the spine's Ed25519 key. The signed message is the canonical
 * serialization of (treeSize, merkleRoot, createdAt) so a verifier can
 * reconstruct exactly what was signed.
 */

/** The exact bytes that get signed / verified for a checkpoint. */
export function checkpointSigningBytes(body: {
  treeSize: number;
  merkleRoot: string;
  createdAt: string;
}): Buffer {
  return Buffer.from(
    canonicalize({
      treeSize: body.treeSize,
      merkleRoot: body.merkleRoot,
      createdAt: body.createdAt,
    }),
    'utf8',
  );
}

/** Merkle root (hex) over the record hashes of `records`, in order. */
export function merkleRootOfRecords(records: readonly EvidenceRecord[]): string {
  const leaves = records.map((r) => Buffer.from(r.recordHash, 'hex'));
  return merkleRootHex(leaves);
}

/** Build and sign a checkpoint over the given records. */
export function buildCheckpoint(
  records: readonly EvidenceRecord[],
  keys: { privateKeyHex: string; publicKeyHex: string },
  createdAt: string,
): Omit<Checkpoint, 'id'> {
  const treeSize = records.length;
  const merkleRoot = merkleRootOfRecords(records);
  const signature = signMessage(
    keys.privateKeyHex,
    checkpointSigningBytes({ treeSize, merkleRoot, createdAt }),
  );
  return {
    treeSize,
    merkleRoot,
    createdAt,
    signature,
    publicKey: keys.publicKeyHex,
  };
}

/** Verify a checkpoint's Ed25519 signature against its embedded public key. */
export function verifyCheckpointSignature(checkpoint: Checkpoint): boolean {
  return verifySignature(
    checkpoint.publicKey,
    checkpointSigningBytes(checkpoint),
    checkpoint.signature,
  );
}

/**
 * Build and sign a checkpoint via a `Signer` (the pluggable path used by the
 * spine). It signs the EXACT SAME `checkpointSigningBytes` as `buildCheckpoint`
 * and embeds the signer's public key, so the signature format is unchanged and
 * `verifyCheckpointSignature` validates it without modification. The signer's
 * `keyId` is recorded for rotation but is deliberately NOT part of the signed
 * bytes, so its presence never affects verification of any checkpoint.
 */
export async function signCheckpoint(
  records: readonly EvidenceRecord[],
  signer: Signer,
  createdAt: string,
): Promise<Omit<Checkpoint, 'id'>> {
  const treeSize = records.length;
  const merkleRoot = merkleRootOfRecords(records);
  const signature = await signer.sign(checkpointSigningBytes({ treeSize, merkleRoot, createdAt }));
  const publicKey = await signer.publicKeyHex();
  return {
    treeSize,
    merkleRoot,
    createdAt,
    signature,
    publicKey,
    ...(signer.keyId !== undefined ? { keyId: signer.keyId } : {}),
  };
}
