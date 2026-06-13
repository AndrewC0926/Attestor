import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceRecord } from '@attestor/types';
import { createShowcaseHarness } from '../src/harness.js';
import { SHOWCASE_STEPS } from '../src/scenario.js';
import { projectReplay } from '../src/replay.js';

interface CallResult {
  isError?: boolean;
}

describe('showcase end-to-end through the real gateway + spine', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-showcase-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function run(): Promise<EvidenceRecord[]> {
    const harness = await createShowcaseHarness(dir);
    try {
      for (const step of SHOWCASE_STEPS) {
        try {
          (await harness.agent.callTool({
            name: step.tool,
            arguments: step.arguments,
          })) as CallResult;
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

  it('records one signed, hash-chained evidence record per attempted action', async () => {
    const records = await run();
    expect(records).toHaveLength(SHOWCASE_STEPS.length);
    expect(records.map((r) => r.seq)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('produces the expected ordered allow / escalate / deny decisions', async () => {
    const records = await run();
    expect(records.map((r) => `${r.actionName}:${r.decision}`)).toEqual([
      'read_ticket:allow',
      'update_customer_record:allow',
      'post_reply:allow',
      'issue_refund:allow', // $200 — within limit
      'issue_refund:escalate', // $750 — over limit
      'export_customer_data:deny',
    ]);
  });

  it('never forwards blocked calls downstream (no output captured for them)', async () => {
    const records = await run();
    const byAction = (i: number): EvidenceRecord => records[i] as EvidenceRecord;
    // Allowed actions have a downstream output digest...
    expect(byAction(0).outputSha256).not.toBeNull();
    expect(byAction(3).outputSha256).not.toBeNull();
    // ...escalated and denied actions were never executed, so none exists.
    expect(byAction(4).outputSha256).toBeNull();
    expect(byAction(5).outputSha256).toBeNull();
  });

  it('passes full integrity verification (chain + signed checkpoints)', async () => {
    const harness = await createShowcaseHarness(dir);
    try {
      for (const step of SHOWCASE_STEPS) {
        try {
          await harness.agent.callTool({ name: step.tool, arguments: step.arguments });
        } catch {
          /* blocked */
        }
      }
      await harness.spine.checkpoint();
      const result = await harness.spine.verify();
      expect(result.ok).toBe(true);
      expect(result.recordsChecked).toBe(SHOWCASE_STEPS.length);
      expect(result.checkpointsChecked).toBeGreaterThan(0);
    } finally {
      await harness.close();
    }
  });

  it('replays the full account from the evidence alone', async () => {
    const records = await run();
    const replay = projectReplay(records);
    expect(replay).toHaveLength(SHOWCASE_STEPS.length);
    // The $750 escalation retains its details (capture:full) for the replay.
    const escalation = replay.find((e) => e.decision === 'escalate');
    expect(escalation?.actionName).toBe('issue_refund');
    expect(escalation?.capturedInput).toContain('750');
  });
});
