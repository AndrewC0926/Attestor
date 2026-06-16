import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceRecord } from '@attestor/types';
import { createShowcaseHarness } from '../src/harness.js';
import { AmlPolicyEngine, CTR_THRESHOLD, amlScenario } from '../src/scenarios/aml.js';
import { getScenario, SCENARIO_IDS } from '../src/scenarios/index.js';
import { projectReplay } from '../src/replay.js';

const engine = new AmlPolicyEngine();

async function decide(
  actionName: string,
  args: Record<string, unknown> = {},
): Promise<{ tier: string; decision: string; capture: string; reason: string }> {
  const r = await engine.evaluate({
    agentId: 'aml-investigation-agent',
    actionType: 'tool_call',
    actionName,
    argumentsJson: JSON.stringify(args),
  });
  return { tier: r.riskTier, decision: r.decision, capture: r.capture, reason: r.reason };
}

describe('AmlPolicyEngine — BSA/AML dispositions (name-pattern)', () => {
  it('allows reading the alert at T0', async () => {
    expect(await decide('review_alert')).toMatchObject({ tier: 'T0', decision: 'allow' });
  });

  it('allows EDD reads at T1', async () => {
    expect(await decide('pull_customer_profile')).toMatchObject({ tier: 'T1', decision: 'allow' });
    expect(await decide('screen_sanctions_pep')).toMatchObject({ tier: 'T1', decision: 'allow' });
  });

  it('allows dismiss_alert at T2 and retains the rationale (full capture)', async () => {
    expect(await decide('dismiss_alert', { rationale: 'false positive' })).toMatchObject({
      tier: 'T2',
      decision: 'allow',
      capture: 'full',
    });
  });

  it('escalates file_sar at T3 — BSA officer authorization required', async () => {
    const r = await decide('file_sar');
    expect(r).toMatchObject({ tier: 'T3', decision: 'escalate', capture: 'full' });
    expect(r.reason).toContain('BSA officer');
  });

  it('denies notify_customer_of_sar at T3 — illegal tipping off', async () => {
    const r = await decide('notify_customer_of_sar');
    expect(r).toMatchObject({ tier: 'T3', decision: 'deny', capture: 'full' });
    expect(r.reason.toLowerCase()).toContain('tipping off');
  });
});

describe('AmlPolicyEngine — mandatory CTR threshold (argument-aware)', () => {
  it('requires NO CTR at or below $10,000', async () => {
    const under = await decide('report_ctr', { amount: 5000 });
    expect(under).toMatchObject({ tier: 'T3', decision: 'allow' });
    expect(under.reason).toContain('no Currency Transaction Report');
    // Boundary: exactly $10,000 is NOT over the threshold → no CTR.
    expect(await decide('report_ctr', { amount: CTR_THRESHOLD })).toMatchObject({
      decision: 'allow',
    });
  });

  it('makes a CTR MANDATORY when cash exceeds $10,000', async () => {
    const over = await decide('report_ctr', { amount: 25000 });
    expect(over).toMatchObject({ tier: 'T3', decision: 'escalate', capture: 'full' });
    expect(over.reason).toContain('MANDATORY');
    expect(over.reason).toContain('FinCEN Form 112');
    // One dollar over the line still triggers it.
    expect(await decide('report_ctr', { amount: CTR_THRESHOLD + 1 })).toMatchObject({
      decision: 'escalate',
    });
  });
});

describe('aml scenario end-to-end through the real gateway + spine', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-aml-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('is registered (default stays support-desk)', () => {
    expect(SCENARIO_IDS).toEqual(['support-desk', 'finance', 'aml']);
    expect(getScenario('aml')?.id).toBe('aml');
  });

  async function run(): Promise<EvidenceRecord[]> {
    const harness = await createShowcaseHarness(amlScenario, dir);
    try {
      for (const step of amlScenario.steps) {
        try {
          await harness.agent.callTool({ name: step.tool, arguments: step.arguments });
        } catch {
          // blocked calls surface as tool errors; the evidence is still recorded.
        }
      }
      await harness.spine.checkpoint();
      return await harness.spine.getAllRecords();
    } finally {
      await harness.close();
    }
  }

  it('produces the expected BSA/AML decision sequence', async () => {
    const records = await run();
    expect(records.map((r) => `${r.actionName}:${r.decision}`)).toEqual([
      'review_alert:allow',
      'pull_customer_profile:allow',
      'screen_sanctions_pep:allow',
      'dismiss_alert:allow',
      'report_ctr:allow', // $5k — under CTR threshold
      'report_ctr:escalate', // $25k — CTR mandatory
      'file_sar:escalate', // BSA officer authorization
      'notify_customer_of_sar:deny', // tipping off
    ]);
  });

  it('never forwards the escalated/denied actions downstream', async () => {
    const records = await run();
    const at = (i: number): EvidenceRecord => records[i] as EvidenceRecord;
    expect(at(4).outputSha256).not.toBeNull(); // CTR under threshold executed
    expect(at(5).outputSha256).toBeNull(); // CTR over threshold — escalated, not filed
    expect(at(6).outputSha256).toBeNull(); // SAR — escalated, not filed
    expect(at(7).outputSha256).toBeNull(); // tipping off — denied
  });

  it('passes full integrity verification and retains the SAR rationale in replay', async () => {
    const records = await run();
    const replay = projectReplay(records);
    const sar = replay.find((e) => e.actionName === 'file_sar');
    expect(sar?.decision).toBe('escalate');
    expect(sar?.capturedInput).toContain('FinCEN Form 111');
  });
});
