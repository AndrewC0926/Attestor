import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { ActionType } from '@attestor/types';
import type { PolicyEngine, PolicyInput, PolicyResult } from './types.js';

/**
 * Policy set v0: a thin, declarative rule engine.
 *
 * Rules are evaluated in file order; the first rule whose actionType and
 * namePattern match wins. There are no hard-coded decisions in the gateway —
 * everything is data, validated here with zod at the trust boundary. A real
 * engine (OPA / Cedar) implements the same PolicyEngine interface in Phase 2.
 */

const ruleSchema = z.object({
  id: z.string().min(1),
  actionType: z.enum(['tool_call', 'model_call', 'agent_message']).optional(),
  namePattern: z.string().min(1),
  riskTier: z.enum(['T0', 'T1', 'T2', 'T3']),
  decision: z.enum(['allow', 'deny', 'escalate']),
  capture: z.enum(['digest', 'full']).default('digest'),
  controls: z.array(z.string()).default([]),
  reason: z.string().min(1),
});

const defaultRuleSchema = ruleSchema.omit({ namePattern: true, actionType: true });

const policySchema = z.object({
  version: z.number(),
  description: z.string().optional(),
  defaultRule: defaultRuleSchema,
  rules: z.array(ruleSchema),
});

type Rule = z.infer<typeof ruleSchema>;
type DefaultRule = z.infer<typeof defaultRuleSchema>;

interface CompiledRule extends Rule {
  readonly regex: RegExp;
}

function toResult(rule: Rule | DefaultRule): PolicyResult {
  return {
    decision: rule.decision,
    riskTier: rule.riskTier,
    policyId: rule.id,
    controls: rule.controls,
    reason: rule.reason,
    capture: rule.capture,
  };
}

export class PolicyV0Engine implements PolicyEngine {
  readonly name = 'attestor-policy-v0';

  private constructor(
    private readonly rules: readonly CompiledRule[],
    private readonly defaultRule: DefaultRule,
  ) {}

  /** Build an engine from a parsed and validated policy document. */
  static fromDocument(doc: unknown): PolicyV0Engine {
    const policy = policySchema.parse(doc);
    const compiled = policy.rules.map((rule) => ({
      ...rule,
      regex: new RegExp(rule.namePattern),
    }));
    return new PolicyV0Engine(compiled, policy.defaultRule);
  }

  /** Load and compile a policy from a YAML file path. */
  static fromFile(path: string): PolicyV0Engine {
    const doc = parseYaml(readFileSync(path, 'utf8'));
    return PolicyV0Engine.fromDocument(doc);
  }

  evaluate(input: PolicyInput): Promise<PolicyResult> {
    for (const rule of this.rules) {
      if (this.matches(rule, input.actionType, input.actionName)) {
        return Promise.resolve(toResult(rule));
      }
    }
    return Promise.resolve(toResult(this.defaultRule));
  }

  private matches(rule: CompiledRule, actionType: ActionType, name: string): boolean {
    if (rule.actionType && rule.actionType !== actionType) {
      return false;
    }
    return rule.regex.test(name);
  }
}
