import { describe, expect, it } from 'vitest';
import { SupportDeskPolicyEngine, REFUND_AUTO_APPROVE_LIMIT } from '../src/policy.js';

const engine = new SupportDeskPolicyEngine();

async function decide(
  actionName: string,
  args: Record<string, unknown> = {},
): Promise<{ tier: string; decision: string; capture: string; reason: string }> {
  const r = await engine.evaluate({
    agentId: 'support-desk-agent',
    actionType: 'tool_call',
    actionName,
    argumentsJson: JSON.stringify(args),
  });
  return { tier: r.riskTier, decision: r.decision, capture: r.capture, reason: r.reason };
}

describe('SupportDeskPolicyEngine — name-pattern tiers', () => {
  it('classifies read_ticket as T0 allow', async () => {
    expect(await decide('read_ticket')).toMatchObject({ tier: 'T0', decision: 'allow' });
  });

  it('classifies post_reply as T1 allow', async () => {
    expect(await decide('post_reply')).toMatchObject({ tier: 'T1', decision: 'allow' });
  });

  it('classifies update_customer_record as T2 allow', async () => {
    expect(await decide('update_customer_record')).toMatchObject({
      tier: 'T2',
      decision: 'allow',
    });
  });

  it('denies delete_account at T3', async () => {
    expect(await decide('delete_account')).toMatchObject({ tier: 'T3', decision: 'deny' });
  });

  it('denies export_customer_data at T3 (full capture for forensics)', async () => {
    expect(await decide('export_customer_data', { scope: 'all' })).toMatchObject({
      tier: 'T3',
      decision: 'deny',
      capture: 'full',
    });
  });

  it('falls back to the conservative default for unknown tools', async () => {
    expect(await decide('mystery_tool')).toMatchObject({ tier: 'T2', decision: 'escalate' });
  });
});

describe('SupportDeskPolicyEngine — argument-aware refund threshold', () => {
  it('auto-approves a refund within the limit', async () => {
    expect(await decide('issue_refund', { amount: 200 })).toMatchObject({
      tier: 'T3',
      decision: 'allow',
    });
  });

  it('allows exactly the limit (boundary is inclusive)', async () => {
    expect(await decide('issue_refund', { amount: REFUND_AUTO_APPROVE_LIMIT })).toMatchObject({
      decision: 'allow',
    });
  });

  it('escalates one dollar over the limit', async () => {
    expect(await decide('issue_refund', { amount: REFUND_AUTO_APPROVE_LIMIT + 1 })).toMatchObject({
      decision: 'escalate',
    });
  });

  it('escalates the $750 scenario refund', async () => {
    const r = await decide('issue_refund', { amount: 750 });
    expect(r.decision).toBe('escalate');
    expect(r.reason).toContain('750');
  });

  it('escalates when the amount is missing or invalid (fails safe)', async () => {
    expect(await decide('issue_refund', { reason: 'no amount given' })).toMatchObject({
      decision: 'escalate',
    });
    expect(await decide('issue_refund', { amount: 'lots' })).toMatchObject({
      decision: 'escalate',
    });
  });

  it('keeps refunds at T3 with full capture regardless of amount', async () => {
    expect(await decide('issue_refund', { amount: 10 })).toMatchObject({
      tier: 'T3',
      capture: 'full',
    });
  });
});
