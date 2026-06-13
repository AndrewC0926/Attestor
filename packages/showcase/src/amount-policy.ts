import { PolicyV0Engine } from '@attestor/gateway';
import type { PolicyEngine, PolicyInput, PolicyResult } from '@attestor/gateway';

/**
 * Shared argument-aware policy helper.
 *
 * The product's `PolicyV0Engine` classifies by tool name only. Several showcase
 * tools need a decision that depends on an *amount* argument (a refund limit, a
 * funds-movement limit). Rather than duplicate that logic per scenario, both the
 * support-desk and finance engines build on this helper: name-pattern base
 * decision, then an inclusive amount threshold on one named tool. This is the
 * `PolicyEngine` extension point a real OPA/Cedar engine would use; the gateway
 * and product policy set are untouched.
 */

/** Extract a finite numeric `amount` from canonical args JSON, or null. */
export function readAmount(argumentsJson: string): number | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(argumentsJson);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }
  const amount = (parsed as Record<string, unknown>)['amount'];
  return typeof amount === 'number' && Number.isFinite(amount) ? amount : null;
}

/** Configuration for the amount threshold applied to one tool. */
export interface AmountThreshold {
  /** Tool name whose decision depends on its `amount` argument. */
  readonly tool: string;
  /** Inclusive auto-approval ceiling: `amount <= limit` allows, above escalates. */
  readonly limit: number;
  /** Human noun for the reason text, e.g. "Refund" or "Transfer". */
  readonly noun: string;
}

/**
 * Build a `PolicyEngine` from a name-pattern policy document plus one
 * amount-threshold rule. `amount <= limit` → allow; `> limit` → escalate;
 * missing/invalid amount → escalate (fail safe). All other tools fall through
 * to the base decision unchanged.
 */
export function createAmountAwarePolicyEngine(
  name: string,
  policyDoc: unknown,
  threshold: AmountThreshold,
): PolicyEngine {
  const base = PolicyV0Engine.fromDocument(policyDoc);
  return {
    name,
    async evaluate(input: PolicyInput): Promise<PolicyResult> {
      const decided = await base.evaluate(input);
      if (input.actionName !== threshold.tool) {
        return decided;
      }
      const amount = readAmount(input.argumentsJson);
      if (amount === null) {
        return {
          ...decided,
          decision: 'escalate',
          reason: `${threshold.noun} amount missing or invalid; escalating for human review.`,
        };
      }
      if (amount > threshold.limit) {
        return {
          ...decided,
          decision: 'escalate',
          reason: `${threshold.noun} of $${amount} exceeds the $${threshold.limit} auto-approval limit; escalating for human approval.`,
        };
      }
      return {
        ...decided,
        decision: 'allow',
        reason: `${threshold.noun} of $${amount} is within the $${threshold.limit} auto-approval limit.`,
      };
    },
  };
}
