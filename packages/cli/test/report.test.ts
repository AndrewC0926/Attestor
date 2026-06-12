import { describe, expect, it } from 'vitest';
import { GENESIS_HASH, type EvidenceRecord, type VerificationResult } from '@attestor/types';
import { chainRecord } from '@attestor/spine';
import type { ControlCatalog } from '../src/controls.js';
import { buildReport } from '../src/report/build.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderJson } from '../src/report/json.js';

const catalog: ControlCatalog = {
  framework: 'ISO/IEC 42001:2023',
  annex: 'Annex A',
  controls: { 'A.6.2.4': { title: 'Operation and monitoring', clause: 'A.6.2.4', summary: '' } },
};

const OK: VerificationResult = {
  ok: true,
  recordsChecked: 3,
  checkpointsChecked: 0,
  failures: [],
};

function rec(seq: number, overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return chainRecord(
    {
      agentId: 'agent',
      recordedAt: `2026-03-0${seq}T00:00:00.000Z`,
      actionType: 'tool_call',
      actionName: 'fs.read',
      inputSha256: 'a'.repeat(64),
      outputSha256: 'b'.repeat(64),
      capture: 'digest',
      inputCapture: null,
      outputCapture: null,
      riskTier: 'T1',
      decision: 'allow',
      policyId: 'rule.read.t1',
      controls: ['A.6.2.4'],
      reason: 'read',
      bufferedOffline: false,
      ...overrides,
    },
    seq - 1,
    GENESIS_HASH,
  );
}

describe('buildReport', () => {
  const records = [
    rec(1),
    rec(2, { riskTier: 'T3', decision: 'deny', policyId: 'rule.financial.t3.deny' }),
    rec(3, { bufferedOffline: true }),
  ];

  it('tallies totals by tier and decision', () => {
    const report = buildReport({
      records,
      checkpoints: [],
      verification: OK,
      catalog,
      from: null,
      to: null,
      generatedAt: '2026-03-10T00:00:00.000Z',
    });
    expect(report.totals.records).toBe(3);
    expect(report.totals.byTier.T1).toBe(2);
    expect(report.totals.byTier.T3).toBe(1);
    expect(report.totals.byDecision.deny).toBe(1);
    expect(report.totals.bufferedOffline).toBe(1);
    expect(report.controlCoverage[0]).toMatchObject({ id: 'A.6.2.4', count: 3 });
  });

  it('filters records by the inclusive timestamp range', () => {
    const report = buildReport({
      records,
      checkpoints: [],
      verification: OK,
      catalog,
      from: '2026-03-02T00:00:00.000Z',
      to: '2026-03-02T23:59:59.000Z',
      generatedAt: '2026-03-10T00:00:00.000Z',
    });
    expect(report.totals.records).toBe(1);
    expect(report.records[0]?.seq).toBe(2);
  });

  it('renders markdown and json with the incident trail', () => {
    const report = buildReport({
      records,
      checkpoints: [],
      verification: OK,
      catalog,
      from: null,
      to: null,
      generatedAt: '2026-03-10T00:00:00.000Z',
    });
    const md = renderMarkdown(report);
    expect(md).toContain('Attestor Compliance Attestation');
    expect(md).toContain('VERIFIED');
    expect(md).toContain('rule.financial.t3.deny');
    expect(md).toContain('⛔ deny');

    const json = JSON.parse(renderJson(report)) as { totals: { records: number } };
    expect(json.totals.records).toBe(3);
  });

  it('marks integrity failures in the rendered report', () => {
    const failed: VerificationResult = {
      ok: false,
      recordsChecked: 3,
      checkpointsChecked: 0,
      failures: [{ kind: 'record_hash_mismatch', at: 2, detail: 'content altered' }],
    };
    const report = buildReport({
      records,
      checkpoints: [],
      verification: failed,
      catalog,
      from: null,
      to: null,
      generatedAt: '2026-03-10T00:00:00.000Z',
    });
    const md = renderMarkdown(report);
    expect(md).toContain('FAILED — tampering detected');
    expect(md).toContain('record_hash_mismatch');
  });
});
