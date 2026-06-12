import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Spine } from '../src/spine.js';
import { SqliteEvidenceStore } from '../src/store/sqlite.js';
import { generateSpineKeyPair } from '../src/signing.js';
import { fixedClock, makeInput } from './helpers.js';

describe('Spine (sqlite integration)', () => {
  let dir: string;
  let dbPath: string;
  const keys = generateSpineKeyPair();

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-spine-'));
    dbPath = join(dir, 'evidence.sqlite');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function openSpine(interval = 0): Promise<Spine> {
    return Spine.fromStore(new SqliteEvidenceStore(dbPath), keys, {
      checkpointInterval: interval,
      now: fixedClock(),
    });
  }

  it('appends a hash-chained log and verifies clean', async () => {
    const spine = await openSpine();
    for (let i = 0; i < 5; i++) {
      await spine.append(makeInput());
    }
    await spine.checkpoint();

    expect(await spine.count()).toBe(5);
    const result = await spine.verify();
    expect(result.ok).toBe(true);
    expect(result.recordsChecked).toBe(5);
    expect(result.checkpointsChecked).toBe(1);
    await spine.close();
  });

  it('links each record to its predecessor', async () => {
    const spine = await openSpine();
    const a = await spine.append(makeInput());
    const b = await spine.append(makeInput());
    expect(b.prevHash).toBe(a.recordHash);
    expect(b.seq).toBe(a.seq + 1);
    await spine.close();
  });

  it('auto-checkpoints on the configured interval', async () => {
    const spine = await openSpine(2);
    await spine.append(makeInput());
    expect(await spine.getCheckpoints()).toHaveLength(0);
    await spine.append(makeInput());
    expect(await spine.getCheckpoints()).toHaveLength(1);
    await spine.close();
  });

  it('produces and verifies an O(log n) inclusion proof', async () => {
    const spine = await openSpine();
    for (let i = 0; i < 7; i++) {
      await spine.append(makeInput());
    }
    const proof = await spine.proveInclusion(4);
    expect(proof.treeSize).toBe(7);
    expect(proof.leafIndex).toBe(3);
    expect(await spine.verifyInclusion(4)).toBe(true);
    await spine.close();
  });

  it('returns ranges and individual records', async () => {
    const spine = await openSpine();
    for (let i = 0; i < 4; i++) {
      await spine.append(makeInput());
    }
    const range = await spine.getRange(2, 3);
    expect(range.map((r) => r.seq)).toEqual([2, 3]);
    expect((await spine.getRecord(1))?.seq).toBe(1);
    expect(await spine.getRecord(99)).toBeNull();
    await spine.close();
  });

  it('verifyInclusion is false for a missing record', async () => {
    const spine = await openSpine();
    await spine.append(makeInput());
    expect(await spine.verifyInclusion(50)).toBe(false);
    await spine.close();
  });

  it('opens from a store config and exposes getAllRecords', async () => {
    const spine = await Spine.open({ kind: 'sqlite', path: dbPath }, keys, {
      now: fixedClock(),
    });
    await spine.append(makeInput());
    await spine.append(makeInput());
    expect((await spine.getAllRecords()).map((r) => r.seq)).toEqual([1, 2]);
    expect(await spine.getCheckpoints()).toHaveLength(0);
    await spine.close();
  });

  it('persists capture=full payloads only when opted in', async () => {
    const spine = await openSpine();
    const digest = await spine.append(makeInput());
    const full = await spine.append(
      makeInput({ capture: 'full', inputCapture: 'raw', outputCapture: 'out' }),
    );
    expect((await spine.getRecord(digest.seq))?.inputCapture).toBeNull();
    expect((await spine.getRecord(full.seq))?.inputCapture).toBe('raw');
    await spine.close();
  });
});
