import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceRecord } from '@attestor/types';
import { createShowcaseHarness } from '../src/harness.js';
import { financeScenario } from '../src/scenarios/finance.js';
import { getScenario, SCENARIO_IDS, DEFAULT_SCENARIO_ID } from '../src/scenarios/index.js';
import { projectReplay } from '../src/replay.js';

describe('scenario registry', () => {
  it('registers both scenarios and defaults to support-desk', () => {
    expect(SCENARIO_IDS).toEqual(['support-desk', 'finance']);
    expect(DEFAULT_SCENARIO_ID).toBe('support-desk');
    expect(getScenario('finance')?.id).toBe('finance');
    expect(getScenario('nope')).toBeUndefined();
  });
});

describe('finance scenario end-to-end through the real gateway + spine', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-finance-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function run(): Promise<EvidenceRecord[]> {
    const harness = await createShowcaseHarness(financeScenario, dir);
    try {
      for (const step of financeScenario.steps) {
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

  it('produces the expected ordered allow / escalate / deny decisions', async () => {
    const records = await run();
    expect(records.map((r) => `${r.actionName}:${r.decision}`)).toEqual([
      'check_balance:allow',
      'categorize_transaction:allow',
      'move_funds:allow', // $5,000 — within limit
      'move_funds:escalate', // $25,000 — over limit
      'wire_external:deny',
      'pull_full_ledger:deny',
    ]);
  });

  it('never forwards blocked calls downstream', async () => {
    const records = await run();
    const at = (i: number): EvidenceRecord => records[i] as EvidenceRecord;
    expect(at(2).outputSha256).not.toBeNull(); // allowed move executed
    expect(at(3).outputSha256).toBeNull(); // escalated move blocked
    expect(at(4).outputSha256).toBeNull(); // external wire denied
    expect(at(5).outputSha256).toBeNull(); // ledger export denied
  });

  it('passes full integrity verification', async () => {
    const harness = await createShowcaseHarness(financeScenario, dir);
    try {
      for (const step of financeScenario.steps) {
        try {
          await harness.agent.callTool({ name: step.tool, arguments: step.arguments });
        } catch {
          /* blocked */
        }
      }
      await harness.spine.checkpoint();
      const result = await harness.spine.verify();
      expect(result.ok).toBe(true);
      expect(result.recordsChecked).toBe(financeScenario.steps.length);
    } finally {
      await harness.close();
    }
  });

  it('replays the $25,000 escalation with its captured detail', async () => {
    const replay = projectReplay(await run());
    const escalation = replay.find((e) => e.decision === 'escalate');
    expect(escalation?.actionName).toBe('move_funds');
    expect(escalation?.capturedInput).toContain('25000');
  });
});
