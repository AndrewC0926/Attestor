import { describe, expect, it } from 'vitest';
import { PolicyV0Engine } from '../src/policy/engine.js';

const engine = PolicyV0Engine.fromFile('policies/v0.yaml');

async function classify(name: string): Promise<{ tier: string; decision: string; id: string }> {
  const r = await engine.evaluate({
    agentId: 'a',
    actionType: 'tool_call',
    actionName: name,
    argumentsJson: '{}',
  });
  return { tier: r.riskTier, decision: r.decision, id: r.policyId };
}

describe('policy v0 classification', () => {
  it('classifies read-only metadata as T0 allow', async () => {
    expect(await classify('tools/list')).toMatchObject({ tier: 'T0', decision: 'allow' });
    expect(await classify('service.status')).toMatchObject({ tier: 'T0' });
  });

  it('classifies reads as T1 allow', async () => {
    expect(await classify('fs.read')).toMatchObject({ tier: 'T1', decision: 'allow' });
    expect(await classify('db.query')).toMatchObject({ tier: 'T1', decision: 'allow' });
  });

  it('classifies writes as T2 allow', async () => {
    expect(await classify('config.update')).toMatchObject({ tier: 'T2', decision: 'allow' });
    expect(await classify('file.write')).toMatchObject({ tier: 'T2', decision: 'allow' });
  });

  it('denies financial transfers at T3', async () => {
    expect(await classify('payments.transfer')).toMatchObject({
      tier: 'T3',
      decision: 'deny',
    });
  });

  it('denies destructive actions at T3', async () => {
    expect(await classify('db.delete')).toMatchObject({ tier: 'T3', decision: 'deny' });
  });

  it('escalates external communication at T3', async () => {
    expect(await classify('email.send')).toMatchObject({
      tier: 'T3',
      decision: 'escalate',
    });
  });

  it('falls back to the conservative default for unknown tools', async () => {
    expect(await classify('mystery.frobnicate')).toMatchObject({
      tier: 'T2',
      decision: 'escalate',
      id: 'rule.default.unknown',
    });
  });

  it('attaches ISO 42001 controls to decisions', async () => {
    const r = await engine.evaluate({
      agentId: 'a',
      actionType: 'tool_call',
      actionName: 'fs.read',
      argumentsJson: '{}',
    });
    expect(r.controls).toContain('A.6.2.4');
  });

  it('rejects a malformed policy document', () => {
    expect(() => PolicyV0Engine.fromDocument({ version: 0 })).toThrow();
  });
});
