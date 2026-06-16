import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateSpineKeyPair } from '../src/signing.js';
import { runParitySequence, PARITY_INPUTS } from './parity-helpers.js';

/**
 * Storage-agnostic parity, always-on (no external dependency): the SAME sequence
 * through two independent SQLite stores, with the same key and clock, must be
 * byte-identical in every cryptographic respect. This proves the crypto lives
 * above the store; the Postgres arm (postgres-parity.test.ts) extends the same
 * proof to a real Postgres when one is available.
 */
describe('storage parity — SQLite ↔ SQLite', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-parity-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('produces byte-identical hashes, Merkle roots, signatures, and proofs', async () => {
    const keys = generateSpineKeyPair();
    const a = await runParitySequence({ kind: 'sqlite', path: join(dir, 'a.sqlite') }, keys);
    const b = await runParitySequence({ kind: 'sqlite', path: join(dir, 'b.sqlite') }, keys);

    // Same number of records as inputs, and identical record hashes.
    expect(a.recordHashes).toHaveLength(PARITY_INPUTS.length);
    expect(a.recordHashes).toEqual(b.recordHashes);

    // Identical Merkle roots (and, with the same key+clock, identical signatures).
    expect(a.merkleRoots).toEqual(b.merkleRoots);
    expect(a.checkpoints).toEqual(b.checkpoints);

    // Identical full records and inclusion proofs.
    expect(a.records).toEqual(b.records);
    expect(a.inclusion).toEqual(b.inclusion);

    // Both verify, identically.
    expect(a.verification.ok).toBe(true);
    expect(b.verification.ok).toBe(true);
    expect(a.verification).toEqual(b.verification);
  });
});
