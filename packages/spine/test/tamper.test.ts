import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Spine } from '../src/spine.js';
import { SqliteEvidenceStore } from '../src/store/sqlite.js';
import { generateSpineKeyPair } from '../src/signing.js';
import { fixedClock, makeInput } from './helpers.js';

/**
 * These tests model the real threat: an attacker with direct database access who
 * bypasses the application entirely. The DB-level triggers stop the application
 * from ever mutating evidence; cryptographic verification stops the privileged
 * attacker who can drop those triggers.
 */
describe('tamper detection', () => {
  let dir: string;
  let dbPath: string;
  const keys = generateSpineKeyPair();

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-tamper-'));
    dbPath = join(dir, 'evidence.sqlite');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function seedLog(): Promise<void> {
    const spine = await Spine.fromStore(new SqliteEvidenceStore(dbPath), keys, {
      now: fixedClock(),
    });
    for (let i = 0; i < 5; i++) {
      await spine.append(makeInput({ decision: 'allow' }));
    }
    await spine.checkpoint();
    await spine.close();
  }

  it('database triggers block UPDATE and DELETE through the normal path', async () => {
    await seedLog();
    const raw = new Database(dbPath);
    expect(() =>
      raw.prepare("UPDATE evidence_record SET decision = 'deny' WHERE seq = 1").run(),
    ).toThrow(/append-only/);
    expect(() => raw.prepare('DELETE FROM evidence_record WHERE seq = 1').run()).toThrow(
      /append-only/,
    );
    raw.close();
  });

  it('detects an out-of-band field mutation after triggers are dropped', async () => {
    await seedLog();

    // Attacker with raw DB access removes the guard and rewrites a record.
    const raw = new Database(dbPath);
    raw.exec('DROP TRIGGER evidence_record_no_update');
    raw.prepare("UPDATE evidence_record SET decision = 'deny' WHERE seq = 2").run();
    raw.close();

    const spine = await Spine.fromStore(new SqliteEvidenceStore(dbPath), keys, {
      now: fixedClock(),
    });
    const result = await spine.verify();
    expect(result.ok).toBe(false);
    expect(result.failures.some((f) => f.kind === 'record_hash_mismatch')).toBe(true);
    expect(result.failures.some((f) => f.at === 2)).toBe(true);
    expect(await spine.verifyInclusion(2)).toBe(true); // proof self-consistent...
    await spine.close();
  });

  it('detects an out-of-band record deletion after triggers are dropped', async () => {
    await seedLog();

    const raw = new Database(dbPath);
    raw.exec('DROP TRIGGER evidence_record_no_delete');
    raw.prepare('DELETE FROM evidence_record WHERE seq = 3').run();
    raw.close();

    const spine = await Spine.fromStore(new SqliteEvidenceStore(dbPath), keys, {
      now: fixedClock(),
    });
    const result = await spine.verify();
    expect(result.ok).toBe(false);
    expect(
      result.failures.some(
        (f) => f.kind === 'sequence_gap' || f.kind === 'chain_link_mismatch',
      ),
    ).toBe(true);
    await spine.close();
  });

  it('detects checkpoint forgery when the signed root no longer matches', async () => {
    await seedLog();

    const raw = new Database(dbPath);
    raw.exec('DROP TRIGGER evidence_record_no_update');
    // Rewrite a record and re-hash it so the chain looks internally consistent;
    // the historical signed checkpoint still pins the original Merkle root.
    raw.prepare("UPDATE evidence_record SET reason = 'rewritten' WHERE seq = 1").run();
    raw.close();

    const spine = await Spine.fromStore(new SqliteEvidenceStore(dbPath), keys, {
      now: fixedClock(),
    });
    const result = await spine.verify();
    expect(result.ok).toBe(false);
    await spine.close();
  });
});
