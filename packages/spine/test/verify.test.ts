import { describe, expect, it } from 'vitest';
import { GENESIS_HASH, type EvidenceRecord } from '@attestor/types';
import { chainRecord, computeRecordHash } from '../src/chain.js';
import { buildCheckpoint } from '../src/checkpoint.js';
import { generateSpineKeyPair } from '../src/signing.js';
import { verifyLog } from '../src/verify.js';
import { fixedClock, makeInput } from './helpers.js';

function buildChain(n: number): EvidenceRecord[] {
  const records: EvidenceRecord[] = [];
  let prevSeq = 0;
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < n; i++) {
    const record = chainRecord(makeInput(), prevSeq, prevHash);
    records.push(record);
    prevSeq = record.seq;
    prevHash = record.recordHash;
  }
  return records;
}

/** Recompute recordHash so a deliberately altered record still self-hashes. */
function reseal(record: EvidenceRecord): EvidenceRecord {
  const { recordHash: _h, ...hashable } = record;
  return { ...hashable, recordHash: computeRecordHash(hashable) };
}

describe('verifyLog', () => {
  const keys = generateSpineKeyPair();

  it('accepts a clean chain with a valid signed checkpoint', () => {
    const records = buildChain(5);
    const checkpoint = { id: 1, ...buildCheckpoint(records, keys, fixedClock()()) };
    const result = verifyLog(records, [checkpoint]);
    expect(result.ok).toBe(true);
    expect(result.recordsChecked).toBe(5);
    expect(result.checkpointsChecked).toBe(1);
    expect(result.failures).toHaveLength(0);
  });

  it('accepts an empty log', () => {
    expect(verifyLog([], []).ok).toBe(true);
  });

  it('detects a field mutation (record hash mismatch)', () => {
    const records = buildChain(3);
    const tampered = [...records];
    tampered[1] = { ...(records[1] as EvidenceRecord), decision: 'deny' };
    const result = verifyLog(tampered, []);
    expect(result.ok).toBe(false);
    expect(result.failures.some((f) => f.kind === 'record_hash_mismatch')).toBe(true);
  });

  it('detects a mutation even if the attacker re-seals the record hash', () => {
    const records = buildChain(3);
    const tampered = [...records];
    // Re-sealing fixes the self-hash but breaks the next record's prevHash link.
    tampered[1] = reseal({ ...(records[1] as EvidenceRecord), riskTier: 'T3' });
    const result = verifyLog(tampered, []);
    expect(result.ok).toBe(false);
    expect(result.failures.some((f) => f.kind === 'chain_link_mismatch')).toBe(true);
  });

  it('detects a deleted record (sequence gap)', () => {
    const records = buildChain(4);
    const withHole = [records[0], records[2], records[3]] as EvidenceRecord[];
    const result = verifyLog(withHole, []);
    expect(result.ok).toBe(false);
    expect(
      result.failures.some(
        (f) => f.kind === 'sequence_gap' || f.kind === 'chain_link_mismatch',
      ),
    ).toBe(true);
  });

  it('detects a forged checkpoint root', () => {
    const records = buildChain(4);
    const good = buildCheckpoint(records, keys, fixedClock()());
    const forged = { id: 1, ...good, merkleRoot: 'a'.repeat(64) };
    // Re-signing the forged root would still fail the root recomputation check.
    const result = verifyLog(records, [forged]);
    expect(result.ok).toBe(false);
    expect(
      result.failures.some((f) => f.kind === 'checkpoint_root_mismatch'),
    ).toBe(true);
  });

  it('detects an invalid checkpoint signature', () => {
    const records = buildChain(2);
    const good = buildCheckpoint(records, keys, fixedClock()());
    const result = verifyLog(records, [
      { id: 1, ...good, signature: 'ff'.repeat(64) },
    ]);
    expect(result.ok).toBe(false);
    expect(
      result.failures.some((f) => f.kind === 'checkpoint_signature_invalid'),
    ).toBe(true);
  });

  it('detects a checkpoint that claims more records than exist', () => {
    const records = buildChain(2);
    const good = buildCheckpoint(records, keys, fixedClock()());
    const result = verifyLog(records, [{ id: 1, ...good, treeSize: 9 }]);
    expect(result.ok).toBe(false);
    expect(
      result.failures.some((f) => f.kind === 'checkpoint_root_mismatch'),
    ).toBe(true);
  });
});
