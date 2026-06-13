import { describe, expect, it } from 'vitest';
import { FinancePolicyEngine, MOVE_FUNDS_AUTO_APPROVE_LIMIT } from '../src/scenarios/finance.js';

const engine = new FinancePolicyEngine();

async function decide(
  actionName: string,
  args: Record<string, unknown> = {},
): Promise<{ tier: string; decision: string; capture: string; reason: string }> {
  const r = await engine.evaluate({
    agentId: 'treasury-ops-agent',
    actionType: 'tool_call',
    actionName,
    argumentsJson: JSON.stringify(args),
  });
  return { tier: r.riskTier, decision: r.decision, capture: r.capture, reason: r.reason };
}

describe('FinancePolicyEngine — name-pattern tiers', () => {
  it('classifies check_balance as T0 allow', async () => {
    expect(await decide('check_balance')).toMatchObject({ tier: 'T0', decision: 'allow' });
  });

  it('classifies categorize_transaction as T1 allow', async () => {
    expect(await decide('categorize_transaction')).toMatchObject({ tier: 'T1', decision: 'allow' });
  });

  it('denies wire_external at T3 (full capture)', async () => {
    expect(await decide('wire_external', { amount: 25000 })).toMatchObject({
      tier: 'T3',
      decision: 'deny',
      capture: 'full',
    });
  });

  it('denies pull_full_ledger at T3', async () => {
    expect(await decide('pull_full_ledger', { scope: 'all' })).toMatchObject({
      tier: 'T3',
      decision: 'deny',
    });
  });

  it('falls back to the conservative default for unknown tools', async () => {
    expect(await decide('reconcile_books')).toMatchObject({ tier: 'T2', decision: 'escalate' });
  });
});

describe('FinancePolicyEngine — argument-aware move_funds threshold', () => {
  it('auto-approves a move within the limit', async () => {
    expect(await decide('move_funds', { amount: 5000 })).toMatchObject({
      tier: 'T3',
      decision: 'allow',
    });
  });

  it('allows exactly the limit (inclusive boundary)', async () => {
    expect(await decide('move_funds', { amount: MOVE_FUNDS_AUTO_APPROVE_LIMIT })).toMatchObject({
      decision: 'allow',
    });
  });

  it('escalates one dollar over the limit', async () => {
    expect(await decide('move_funds', { amount: MOVE_FUNDS_AUTO_APPROVE_LIMIT + 1 })).toMatchObject({
      decision: 'escalate',
    });
  });

  it('escalates the $25,000 scenario move and names the amount', async () => {
    const r = await decide('move_funds', { amount: 25000 });
    expect(r.decision).toBe('escalate');
    expect(r.reason).toContain('25000');
  });

  it('escalates when the amount is missing or invalid (fails safe)', async () => {
    expect(await decide('move_funds', { memo: 'no amount' })).toMatchObject({ decision: 'escalate' });
    expect(await decide('move_funds', { amount: 'lots' })).toMatchObject({ decision: 'escalate' });
  });

  it('keeps move_funds at T3 with full capture regardless of amount', async () => {
    expect(await decide('move_funds', { amount: 1 })).toMatchObject({ tier: 'T3', capture: 'full' });
  });
});
