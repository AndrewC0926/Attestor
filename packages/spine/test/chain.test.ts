import { describe, expect, it } from 'vitest';
import { GENESIS_HASH } from '@attestor/types';
import { chainRecord, computeRecordHash } from '../src/chain.js';
import { makeInput } from './helpers.js';

describe('record chaining', () => {
  it('assigns sequential seq and links prevHash', () => {
    const first = chainRecord(makeInput(), 0, GENESIS_HASH);
    expect(first.seq).toBe(1);
    expect(first.prevHash).toBe(GENESIS_HASH);

    const second = chainRecord(makeInput(), first.seq, first.recordHash);
    expect(second.seq).toBe(2);
    expect(second.prevHash).toBe(first.recordHash);
  });

  it('record hash is deterministic for identical content', () => {
    const input = makeInput();
    const a = chainRecord(input, 0, GENESIS_HASH);
    const b = chainRecord(input, 0, GENESIS_HASH);
    expect(a.recordHash).toBe(b.recordHash);
  });

  it('changing any field changes the record hash', () => {
    const base = chainRecord(makeInput(), 0, GENESIS_HASH);
    const { recordHash: _h, ...hashable } = base;
    expect(computeRecordHash({ ...hashable, decision: 'deny' })).not.toBe(
      base.recordHash,
    );
    expect(computeRecordHash({ ...hashable, riskTier: 'T3' })).not.toBe(
      base.recordHash,
    );
    expect(computeRecordHash({ ...hashable, reason: 'changed' })).not.toBe(
      base.recordHash,
    );
  });

  it('changing prevHash changes the record hash (binds the chain)', () => {
    const base = chainRecord(makeInput(), 0, GENESIS_HASH);
    const { recordHash: _h, ...hashable } = base;
    expect(computeRecordHash({ ...hashable, prevHash: 'f'.repeat(64) })).not.toBe(
      base.recordHash,
    );
  });

  it('changing a full-capture payload changes the record hash', () => {
    const base = chainRecord(
      makeInput({ capture: 'full', inputCapture: 'raw-input' }),
      0,
      GENESIS_HASH,
    );
    const { recordHash: _h, ...hashable } = base;
    expect(computeRecordHash({ ...hashable, inputCapture: 'tampered' })).not.toBe(
      base.recordHash,
    );
  });
});
