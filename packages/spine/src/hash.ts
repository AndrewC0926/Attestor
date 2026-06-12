import { createHash } from 'node:crypto';

/** Hex SHA-256 of a string or buffer. The one hashing primitive used everywhere. */
export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Raw 32-byte SHA-256 digest, for Merkle tree construction. */
export function sha256Bytes(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}
