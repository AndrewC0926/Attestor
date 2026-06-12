import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceInput, EvidenceRecord } from '@attestor/types';
import { EvidenceBuffer } from '../src/buffer.js';
import type { EvidenceSink } from '../src/sink.js';

function input(name: string): EvidenceInput {
  return {
    agentId: 'a',
    recordedAt: '2026-01-01T00:00:00.000Z',
    actionType: 'tool_call',
    actionName: name,
    inputSha256: 'a'.repeat(64),
    outputSha256: null,
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T1',
    decision: 'allow',
    policyId: 'rule.test',
    controls: [],
    reason: 'r',
    bufferedOffline: true,
  };
}

describe('EvidenceBuffer', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-buffer-'));
    path = join(dir, 'buf.jsonl');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('is empty before any writes', () => {
    expect(new EvidenceBuffer(path).size()).toBe(0);
    expect(new EvidenceBuffer(path).list()).toEqual([]);
  });

  it('appends and lists records in order', () => {
    const buffer = new EvidenceBuffer(path);
    buffer.add(input('one'));
    buffer.add(input('two'));
    expect(buffer.list().map((r) => r.actionName)).toEqual(['one', 'two']);
  });

  it('flushes all records and clears', async () => {
    const buffer = new EvidenceBuffer(path);
    buffer.add(input('one'));
    buffer.add(input('two'));
    const sink: EvidenceSink = {
      healthy: () => Promise.resolve(true),
      append: (i) => Promise.resolve({ ...i, seq: 1, prevHash: '', recordHash: '' } as EvidenceRecord),
    };
    expect(await buffer.flush(sink)).toBe(2);
    expect(buffer.size()).toBe(0);
  });

  it('preserves the unflushed remainder when the sink fails partway', async () => {
    const buffer = new EvidenceBuffer(path);
    buffer.add(input('one'));
    buffer.add(input('two'));
    buffer.add(input('three'));
    let n = 0;
    const flakySink: EvidenceSink = {
      healthy: () => Promise.resolve(true),
      append: (i) => {
        n += 1;
        if (n === 2) {
          return Promise.reject(new Error('died'));
        }
        return Promise.resolve({ ...i, seq: n, prevHash: '', recordHash: '' } as EvidenceRecord);
      },
    };
    await expect(buffer.flush(flakySink)).rejects.toThrow('died');
    // First flushed; the failed one and the rest remain.
    expect(buffer.list().map((r) => r.actionName)).toEqual(['two', 'three']);
  });
});
