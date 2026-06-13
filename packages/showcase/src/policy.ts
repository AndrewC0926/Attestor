import type { PolicyEngine, PolicyInput, PolicyResult } from '@attestor/gateway';
import { createAmountAwarePolicyEngine } from './amount-policy.js';

/**
 * Showcase policy: an ADDITIVE policy engine layered on the existing
 * `PolicyV0Engine`. It does not modify the gateway or the product policy set.
 *
 * The base rules below assign tiers/decisions by tool name exactly the way the
 * product's name-pattern engine does. On top of that, `SupportDeskPolicyEngine`
 * adds the one thing v0 cannot express — an *argument-aware* rule: a refund is
 * auto-approved up to the limit and escalated above it. This demonstrates the
 * `PolicyEngine` extension point (a real OPA/Cedar engine would slot in the
 * same way) without touching core logic. The threshold itself is the shared
 * `createAmountAwarePolicyEngine` helper, reused by the finance scenario.
 */

/** Refunds at or below this dollar amount are auto-approved; above it, escalate. */
export const REFUND_AUTO_APPROVE_LIMIT = 500;

/** Tool name whose decision depends on its arguments. */
const REFUND_TOOL = 'issue_refund';

/** Name-pattern base policy for the support-desk tools (data only). */
const SHOWCASE_POLICY_DOC = {
  version: 0,
  description: 'Attestor support-desk showcase policy (additive demo layer).',
  defaultRule: {
    id: 'showcase.default.unknown',
    riskTier: 'T2',
    decision: 'escalate',
    capture: 'digest',
    controls: ['A.6.2.4', 'A.9.2'],
    reason: 'Unclassified support-desk action; escalate for human review.',
  },
  rules: [
    {
      id: 'showcase.read_ticket.t0',
      actionType: 'tool_call',
      namePattern: '^read_ticket$',
      riskTier: 'T0',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4'],
      reason: 'Read-only ticket access (non-sensitive metadata).',
    },
    {
      id: 'showcase.post_reply.t1',
      actionType: 'tool_call',
      namePattern: '^post_reply$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4', 'A.6.2.8'],
      reason: 'Replying on an operator-owned ticket.',
    },
    {
      id: 'showcase.update_customer_record.t2',
      actionType: 'tool_call',
      namePattern: '^update_customer_record$',
      riskTier: 'T2',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.8', 'A.9.4'],
      reason: 'State-changing write within the operator-owned CRM.',
    },
    {
      id: 'showcase.issue_refund.t3',
      actionType: 'tool_call',
      namePattern: '^issue_refund$',
      riskTier: 'T3',
      // Base decision is the conservative one; the engine below refines it by
      // amount. capture:full retains the refund details for the replay/forensics.
      decision: 'escalate',
      capture: 'full',
      controls: ['A.9.2', 'A.5.5'],
      reason: 'Financial action; subject to the refund auto-approval limit.',
    },
    {
      id: 'showcase.delete_account.t3.deny',
      actionType: 'tool_call',
      namePattern: '^delete_account$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'digest',
      controls: ['A.9.2', 'A.6.2.8'],
      reason: 'Destructive account deletion blocked by showcase policy.',
    },
    {
      id: 'showcase.export_customer_data.t3.deny',
      actionType: 'tool_call',
      namePattern: '^export_customer_data$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'full',
      controls: ['A.9.2', 'A.10.4'],
      reason: 'Bulk PII export blocked by showcase policy.',
    },
  ],
};

/**
 * Argument-aware policy engine for the support desk. Delegates tier/decision to
 * the name-pattern base, then refines the refund decision by amount via the
 * shared threshold helper.
 */
export class SupportDeskPolicyEngine implements PolicyEngine {
  readonly name = 'support-desk-policy-v0';

  private readonly engine = createAmountAwarePolicyEngine(this.name, SHOWCASE_POLICY_DOC, {
    tool: REFUND_TOOL,
    limit: REFUND_AUTO_APPROVE_LIMIT,
    noun: 'Refund',
  });

  evaluate(input: PolicyInput): Promise<PolicyResult> {
    return this.engine.evaluate(input);
  }
}
