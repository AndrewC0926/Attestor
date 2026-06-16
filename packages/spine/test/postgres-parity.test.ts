import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Pool } from 'pg';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceInput } from '@attestor/types';
import { Spine } from '../src/spine.js';
import { generateSpineKeyPair } from '../src/signing.js';
import { runParitySequence } from './parity-helpers.js';

/**
 * The SQLite ↔ Postgres PARITY proof, plus Postgres-specific guarantees
 * (concurrent appends stay chain-ordered; UPDATE/DELETE are rejected).
 *
 * Requires a real Postgres. Set ATTESTOR_TEST_DATABASE_URL to a connection
 * string and the suite runs; unset, it is skipped (same pattern as the
 * live-freetsa test) so CI without Postgres stays green.
 *
 *   ATTESTOR_TEST_DATABASE_URL=postgres://user:pass@localhost:5432/attestor_test \
 *     npm test
 */
const PG = process.env.ATTESTOR_TEST_DATABASE_URL;

function input(n: number): EvidenceInput {
  return {
    agentId: 'agent-conc',
    recordedAt: `2026-02-01T00:00:${String(n).padStart(2, '0')}.000Z`,
    actionType: 'tool_call',
    actionName: `op_${n}`,
    inputSha256: 'f'.repeat(64),
    outputSha256: null,
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T2',
    decision: 'allow',
    policyId: 'rule.write',
    controls: ['A.9.4'],
    reason: `concurrent append ${n}`,
    bufferedOffline: false,
  };
}

describe.skipIf(!PG)('storage parity — SQLite ↔ Postgres (real DB)', () => {
  const connectionString = PG as string;
  const admin = new Pool({ connectionString });
  let dir: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-pg-'));
    // Clean slate: drop the evidence tables (DDL is allowed; the append-only
    // trigger only blocks row UPDATE/DELETE). init() recreates them.
    await admin.query('DROP TABLE IF EXISTS evidence_record, evidence_checkpoint CASCADE');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  afterAll(async () => {
    await admin.end();
  });

  it('produces byte-identical hashes, Merkle roots, and proofs as SQLite', async () => {
    const keys = generateSpineKeyPair();
    const sqlite = await runParitySequence({ kind: 'sqlite', path: join(dir, 'a.sqlite') }, keys);
    const postgres = await runParitySequence({ kind: 'postgres', connectionString }, keys);

    expect(postgres.recordHashes).toEqual(sqlite.recordHashes);
    expect(postgres.merkleRoots).toEqual(sqlite.merkleRoots);
    expect(postgres.records).toEqual(sqlite.records);
    expect(postgres.inclusion).toEqual(sqlite.inclusion);
    expect(sqlite.verification.ok).toBe(true);
    expect(postgres.verification.ok).toBe(true);
    expect(postgres.verification).toEqual(sqlite.verification);
  });

  it('keeps the hash chain strictly ordered under concurrent appends', async () => {
    const keys = generateSpineKeyPair();
    const spine = await Spine.open({ kind: 'postgres', connectionString }, keys);
    try {
      const n = 25;
      // Fire all appends concurrently; the advisory lock must serialize them.
      await Promise.all(Array.from({ length: n }, (_, i) => spine.append(input(i + 1))));

      const records = await spine.getAllRecords();
      // Strictly sequential seqs, no gaps or duplicates.
      expect(records.map((r) => r.seq)).toEqual(Array.from({ length: n }, (_, i) => i + 1));
      // The chain is intact end to end.
      expect((await spine.verify()).ok).toBe(true);
    } finally {
      await spine.close();
    }
  });

  it('rejects UPDATE and DELETE on evidence (append-only trigger)', async () => {
    const keys = generateSpineKeyPair();
    const spine = await Spine.open({ kind: 'postgres', connectionString }, keys);
    try {
      await spine.append(input(1));
    } finally {
      await spine.close();
    }
    await expect(
      admin.query("UPDATE evidence_record SET reason = 'tampered' WHERE seq = 1"),
    ).rejects.toThrow(/append-only/);
    await expect(admin.query('DELETE FROM evidence_record WHERE seq = 1')).rejects.toThrow(
      /append-only/,
    );
  });
});
