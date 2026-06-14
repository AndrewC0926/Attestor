import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceInput, EvidenceRecord } from '@attestor/types';
import { Spine, resolveKeyPair, verifyLog } from '@attestor/spine';
import { PolicyV0Engine, SpineEvidenceSink, type EvidenceSink } from '@attestor/gateway';
import { ProxyCore, type ProxyCall, type Forward } from '../src/proxy-core.js';

/** Minimal policy mapping the test tools across tiers. */
const POLICY_DOC = {
  version: 0,
  description: 'proxy test policy',
  defaultRule: {
    id: 'rule.default',
    riskTier: 'T2',
    decision: 'escalate',
    capture: 'digest',
    controls: [],
    reason: 'unclassified',
  },
  rules: [
    {
      id: 'rule.read',
      actionType: 'tool_call',
      namePattern: '^read_record$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4'],
      reason: 'read-only',
    },
    {
      id: 'rule.write',
      actionType: 'tool_call',
      namePattern: '^write_disposition$',
      riskTier: 'T2',
      decision: 'allow',
      capture: 'full',
      controls: ['A.9.4'],
      reason: 'state-changing write',
    },
    {
      id: 'rule.export',
      actionType: 'tool_call',
      namePattern: '^export_case_file$',
      riskTier: 'T3',
      decision: 'escalate',
      capture: 'full',
      controls: ['A.9.2'],
      reason: 'export requires approval',
    },
    {
      id: 'rule.purge',
      actionType: 'tool_call',
      namePattern: '^purge_records$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'digest',
      controls: ['A.9.2'],
      reason: 'destructive — denied',
    },
  ],
};

const engine = PolicyV0Engine.fromDocument(POLICY_DOC);

function call(toolName: string, args: Record<string, unknown> = {}): ProxyCall {
  return { agentId: 'live-agent', toolName, arguments: args };
}

/** A sink whose append always throws — simulates an unreachable evidence store. */
class FailingSink implements EvidenceSink {
  append(_input: EvidenceInput): Promise<EvidenceRecord> {
    return Promise.reject(new Error('evidence store down'));
  }
  healthy(): Promise<boolean> {
    return Promise.resolve(false);
  }
}

describe('ProxyCore — hot path (decide → record → maybe forward)', () => {
  let dir: string;
  let spine: Spine;
  let core: ProxyCore;
  let forwarded: string[];
  let forward: Forward;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-proxy-'));
    const keys = resolveKeyPair(join(dir, 'key.json'), {} as NodeJS.ProcessEnv);
    spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, keys);
    core = new ProxyCore(engine, new SpineEvidenceSink(spine), null, { forwardTimeoutMs: 200 });
    forwarded = [];
    forward = (c): Promise<unknown> => {
      forwarded.push(c.toolName);
      return Promise.resolve({ content: [{ type: 'text', text: `did ${c.toolName}` }] });
    };
  });

  afterEach(async () => {
    await spine.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('allows a T1 read: forwards once and records a single result', async () => {
    const out = await core.handle(call('read_record', { path: 'a.txt' }), forward);
    expect(out.allowed).toBe(true);
    expect(forwarded).toEqual(['read_record']);
    expect(out.records).toHaveLength(1);
    expect(out.records[0]?.outputSha256).not.toBeNull();
  });

  it('allows a T2 write: records authorized BEFORE forwarding, then the result', async () => {
    const out = await core.handle(
      call('write_disposition', { caseId: 'C1', disposition: 'cleared' }),
      forward,
    );
    expect(out.allowed).toBe(true);
    expect(forwarded).toEqual(['write_disposition']);
    expect(out.records).toHaveLength(2);
    const [authorized, executed] = out.records;
    // The authorization is the earlier record, has no output, and is on the
    // ledger before the action's result.
    expect(authorized?.seq).toBeLessThan(executed?.seq ?? 0);
    expect(authorized?.outputSha256).toBeNull();
    expect(authorized?.reason).toContain('authorized');
    expect(executed?.outputSha256).not.toBeNull();
    expect(executed?.reason).toContain('executed');
  });

  it('denies a T3 destructive call: never forwards, records the block', async () => {
    const out = await core.handle(call('purge_records', { table: 'cases' }), forward);
    expect(out.allowed).toBe(false);
    expect(out.decision).toBe('deny');
    expect(forwarded).toEqual([]);
    expect(out.records).toHaveLength(1);
    expect(out.records[0]?.outputSha256).toBeNull();
  });

  it('escalates a T3 export: never forwards, records the escalation', async () => {
    const out = await core.handle(call('export_case_file', { caseId: 'C1' }), forward);
    expect(out.allowed).toBe(false);
    expect(out.decision).toBe('escalate');
    expect(forwarded).toEqual([]);
    expect(out.records).toHaveLength(1);
  });

  it('handles a downstream timeout without hanging: authorized + failed-result recorded', async () => {
    const hang: Forward = () => new Promise(() => {}); // never resolves
    const out = await core.handle(call('write_disposition', { caseId: 'C2' }), hang);
    expect(out.allowed).toBe(false);
    expect(out.error?.code).toBe('downstream_unavailable');
    // The authorization is still on the ledger; the failed execution is recorded.
    expect(out.records).toHaveLength(2);
    expect(out.records[1]?.reason).toContain('execution failed');
  });

  it('fail-closed: if the authorized write fails on a T3, the action is DENIED and never forwarded', async () => {
    const failing = new ProxyCore(engine, new FailingSink(), null);
    const spy = vi.fn<Parameters<Forward>, ReturnType<Forward>>(() => Promise.resolve({}));
    const out = await failing.handle(call('write_disposition', { caseId: 'C3' }), spy);
    expect(out.allowed).toBe(false);
    expect(out.error?.code).toBe('evidence_unavailable');
    expect(spy).not.toHaveBeenCalled(); // no action without evidence
    expect(out.records).toHaveLength(0);
  });

  it('live-path evidence passes the SAME verifyLog + inclusion checks as the showcase', async () => {
    await core.handle(call('read_record', { path: 'a.txt' }), forward);
    await core.handle(call('write_disposition', { caseId: 'C1', disposition: 'cleared' }), forward);
    await core.handle(call('export_case_file', { caseId: 'C1' }), forward); // escalate
    await core.handle(call('purge_records', { table: 'cases' }), forward); // deny
    const checkpoint = await spine.checkpoint();

    const [records, checkpoints] = await Promise.all([
      spine.getAllRecords(),
      spine.getCheckpoints(),
    ]);
    // read(1) + write authorized+executed(2) + escalate(1) + deny(1) = 5 records.
    expect(records).toHaveLength(5);
    expect(verifyLog(records, checkpoints).ok).toBe(true);
    expect(await spine.verifyInclusion(checkpoint.treeSize)).toBe(true);
    expect((await spine.verify()).ok).toBe(true);
  });
});
