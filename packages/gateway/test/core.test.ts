import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { GatewayCore, type ToolCall } from '../src/core.js';
import { EvidenceBuffer } from '../src/buffer.js';
import { PolicyV0Engine } from '../src/policy/engine.js';
import type { PolicyEngine } from '../src/policy/types.js';
import { FakeSink, trackingForward } from './helpers.js';

const engine = PolicyV0Engine.fromFile('policies/v0.yaml');
const NOW = (): string => '2026-01-01T00:00:00.000Z';

function call(toolName: string, args: unknown = {}): ToolCall {
  return { agentId: 'agent-1', toolName, arguments: args };
}

describe('GatewayCore', () => {
  let dir: string;
  let buffer: EvidenceBuffer;
  let sink: FakeSink;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-core-'));
    buffer = new EvidenceBuffer(join(dir, 'buffer.jsonl'));
    sink = new FakeSink();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function core(e: PolicyEngine = engine): GatewayCore {
    return new GatewayCore(e, sink, buffer, { now: NOW });
  }

  it('allows a T1 read: forwards downstream and records evidence', async () => {
    const fwd = trackingForward();
    const decision = await core().handleToolCall(call('fs.read'), fwd.fn);
    expect(decision.allowed).toBe(true);
    expect(fwd.calls).toEqual(['fs.read']);
    expect(sink.appended).toHaveLength(1);
    expect(sink.appended[0]).toMatchObject({ decision: 'allow', riskTier: 'T1' });
    expect(sink.appended[0]?.outputSha256).toBeTypeOf('string');
  });

  it('denies a T3 financial transfer: never forwards, records the denial', async () => {
    const fwd = trackingForward();
    const decision = await core().handleToolCall(call('payments.transfer'), fwd.fn);
    expect(decision.allowed).toBe(false);
    expect(decision.error?.code).toBe('policy_denied');
    expect(fwd.calls).toEqual([]);
    expect(sink.appended[0]).toMatchObject({ decision: 'deny', riskTier: 'T3' });
  });

  it('captures raw payload only when the matched policy opts into full capture', async () => {
    await core().handleToolCall(call('payments.transfer', { amount: 9000 }), trackingForward().fn);
    await core().handleToolCall(call('fs.read', { path: '/etc/hosts' }), trackingForward().fn);
    expect(sink.appended[0]?.capture).toBe('full');
    expect(sink.appended[0]?.inputCapture).toContain('9000');
    expect(sink.appended[1]?.capture).toBe('digest');
    expect(sink.appended[1]?.inputCapture).toBeNull();
  });

  it('escalates external communication without forwarding', async () => {
    const fwd = trackingForward();
    const decision = await core().handleToolCall(call('email.send'), fwd.fn);
    expect(decision.allowed).toBe(false);
    expect(decision.error?.code).toBe('escalation_required');
    expect(fwd.calls).toEqual([]);
  });

  it('fails closed: a T2 action is blocked when the store is unreachable', async () => {
    sink.up = false;
    const fwd = trackingForward();
    const decision = await core().handleToolCall(call('config.update'), fwd.fn);
    expect(decision.allowed).toBe(false);
    expect(decision.error?.code).toBe('evidence_unavailable');
    expect(fwd.calls).toEqual([]); // action NOT performed
    expect(buffer.size()).toBe(1); // but the blocked attempt is buffered
    expect(buffer.list()[0]?.bufferedOffline).toBe(true);
  });

  it('fails open: a T1 action proceeds and is buffered when the store is unreachable', async () => {
    sink.up = false;
    const fwd = trackingForward();
    const decision = await core().handleToolCall(call('db.query'), fwd.fn);
    expect(decision.allowed).toBe(true);
    expect(fwd.calls).toEqual(['db.query']); // action performed
    expect(decision.bufferedOffline).toBe(true);
    expect(buffer.size()).toBe(1);
  });

  it('flushes the buffer once the store recovers', async () => {
    sink.up = false;
    await core().handleToolCall(call('db.query'), trackingForward().fn);
    expect(buffer.size()).toBe(1);

    sink.up = true;
    await core().handleToolCall(call('fs.read'), trackingForward().fn);
    expect(buffer.size()).toBe(0);
    // Both the flushed record and the new one are now in the store.
    expect(sink.appended.length).toBe(2);
  });

  it('buffers mid-flight when the store dies between probe and write', async () => {
    sink.up = true;
    sink.appendFails = true;
    const decision = await core().handleToolCall(call('fs.read'), trackingForward().fn);
    expect(decision.allowed).toBe(true);
    expect(decision.record).toBeNull();
    expect(buffer.size()).toBe(1);
  });

  it('fails closed when the policy engine itself is unavailable', async () => {
    const brokenEngine: PolicyEngine = {
      name: 'broken',
      evaluate: () => Promise.reject(new Error('opa down')),
    };
    const fwd = trackingForward();
    const decision = await core(brokenEngine).handleToolCall(call('fs.read'), fwd.fn);
    expect(decision.allowed).toBe(false);
    expect(decision.error?.code).toBe('policy_unavailable');
    expect(fwd.calls).toEqual([]);
    expect(sink.appended[0]).toMatchObject({ decision: 'deny', policyId: 'engine.unavailable' });
  });
});
