import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { PolicyV0Engine } from '@attestor/gateway';
import type { PolicyEngine, PolicyInput, PolicyResult } from '@attestor/gateway';
import type { PolicyDecision, RiskTier } from '@attestor/types';
import { createAmountAwarePolicyEngine, readAmount } from '../amount-policy.js';
import type { Scenario, ShowcaseStep } from './types.js';

/**
 * A third scenario: an AML (anti-money-laundering) investigation agent that
 * mirrors the real BSA/AML alert-investigation workflow, examined against the
 * FFIEC BSA/AML manual standard. An alert fires from transaction monitoring;
 * the agent runs L1 triage and L2 enhanced due diligence (EDD), reaches a
 * disposition, and hits two hard governance moments:
 *
 *   - filing a SAR (FinCEN Form 111) ESCALATES — only a BSA officer may
 *     authorize it; the agent cannot file autonomously, and
 *   - notifying the customer of a SAR is DENIED — "tipping off" is illegal.
 *
 * It also covers the routine, MANDATORY Currency Transaction Report (CTR,
 * FinCEN Form 112): cash over $10,000 must be reported (31 CFR 1010.311). The
 * CTR is amount-gated via the shared argument-aware helper; the dispositions are
 * name-pattern via the product's PolicyV0Engine. Nothing here touches real
 * customer data, a real SAR, or a real filing.
 */

/** Cash transactions OVER this amount require a CTR (31 CFR 1010.311). */
export const CTR_THRESHOLD = 10_000;

const CTR_TOOL = 'report_ctr';

/** Description of an AML tool and its expected governance (for docs/tests). */
export interface AmlTool {
  readonly name: string;
  readonly tier: RiskTier;
  readonly expected: 'allow' | 'deny' | 'conditional';
  readonly description: string;
}

/** The 7 AML tools the agent is wired to, mapped across tiers. */
export const AML_TOOLS: readonly AmlTool[] = [
  {
    name: 'review_alert',
    tier: 'T0',
    expected: 'allow',
    description: 'Read a transaction-monitoring alert (simulated, read-only L1 triage).',
  },
  {
    name: 'pull_customer_profile',
    tier: 'T1',
    expected: 'allow',
    description: 'Read KYC/customer profile for the investigation (simulated EDD).',
  },
  {
    name: 'screen_sanctions_pep',
    tier: 'T1',
    expected: 'allow',
    description: 'Run sanctions/PEP/adverse-media screening (simulated EDD).',
  },
  {
    name: 'dismiss_alert',
    tier: 'T2',
    expected: 'allow',
    description: 'Clear an alert as a false positive; auditable disposition with rationale.',
  },
  {
    name: 'report_ctr',
    tier: 'T3',
    expected: 'conditional',
    description: 'File a CTR (FinCEN Form 112). MANDATORY for cash over $10,000; under, none.',
  },
  {
    name: 'file_sar',
    tier: 'T3',
    expected: 'conditional',
    description: 'File a SAR (FinCEN Form 111). Escalates — requires BSA officer authorization.',
  },
  {
    name: 'notify_customer_of_sar',
    tier: 'T3',
    expected: 'deny',
    description: 'Notify a customer of a SAR — DENIED: illegal "tipping off" (never executes).',
  },
];

function arg(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  return v === undefined ? '?' : String(v);
}

/** Canned, clearly-simulated result for an allowed AML tool call. */
function simulate(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case 'review_alert':
      return `[SIMULATED] alert ${arg(args, 'alertId')}: type=structuring, 6 cash deposits just under $10k over 4 days`;
    case 'pull_customer_profile':
      return `[SIMULATED] customer ${arg(args, 'customerId')}: KYC complete, risk=medium, occupation=retail`;
    case 'screen_sanctions_pep':
      return `[SIMULATED] screening ${arg(args, 'customerId')}: OFAC=no match, PEP=no match, adverse media=none`;
    case 'dismiss_alert':
      return `[SIMULATED] alert ${arg(args, 'alertId')} leg dismissed; rationale recorded for examiner review`;
    case 'report_ctr':
      return `[SIMULATED] CTR (FinCEN Form 112) prepared for $${arg(args, 'amount')} cash — no real filing`;
    case 'file_sar':
      return `[SIMULATED] SAR draft (FinCEN Form 111) prepared for ${arg(args, 'customerId')} — no real filing`;
    case 'notify_customer_of_sar':
      return `[SIMULATED] customer notification for ${arg(args, 'customerId')}`;
    default:
      return `[SIMULATED] executed ${name}`;
  }
}

/** In-process MCP server standing in for a BSA/AML case-management tool surface. */
export function createAmlToolServer(): Server {
  const server = new Server(
    { name: 'aml-tools', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () =>
    Promise.resolve({
      tools: AML_TOOLS.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: { type: 'object' as const },
      })),
    }),
  );

  server.setRequestHandler(CallToolRequestSchema, (request) => {
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    return Promise.resolve({
      content: [{ type: 'text' as const, text: simulate(request.params.name, args) }],
    });
  });

  return server;
}

/**
 * Name-pattern dispositions (everything except the CTR). Decided by the
 * product's PolicyV0Engine — no amount logic. Control ids are real BSA/AML
 * citations; reasons reference the FFIEC examiner standard where natural.
 */
const AML_DISPOSITION_DOC = {
  version: 0,
  description: 'Attestor AML investigation showcase policy — dispositions (additive demo layer).',
  defaultRule: {
    id: 'aml.default.unknown',
    riskTier: 'T2',
    decision: 'escalate',
    capture: 'digest',
    controls: ['FFIEC-BSA/AML-Manual'],
    reason: 'Unclassified AML action; escalate for BSA analyst review (conservative default).',
  },
  rules: [
    {
      id: 'aml.review_alert.t0',
      actionType: 'tool_call',
      namePattern: '^review_alert$',
      riskTier: 'T0',
      decision: 'allow',
      capture: 'digest',
      controls: ['31 CFR 1020.210'],
      reason: 'Reading a transaction-monitoring alert for L1 triage (read-only; FFIEC BSA/AML examiner standard).',
    },
    {
      id: 'aml.pull_customer_profile.t1',
      actionType: 'tool_call',
      namePattern: '^pull_customer_profile$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['31 CFR 1020.220'],
      reason: 'Pulling KYC/customer profile for enhanced due diligence (CIP/KYC, 31 CFR 1020.220).',
    },
    {
      id: 'aml.screen_sanctions_pep.t1',
      actionType: 'tool_call',
      namePattern: '^screen_sanctions_pep$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['31 CFR 1010.620'],
      reason: 'Running sanctions/PEP/adverse-media screening as part of EDD.',
    },
    {
      id: 'aml.dismiss_alert.t2',
      actionType: 'tool_call',
      namePattern: '^dismiss_alert$',
      riskTier: 'T2',
      decision: 'allow',
      capture: 'full',
      controls: ['31 CFR 1010.430'],
      reason:
        'Clearing an alert as a false positive — auditable disposition retained for examiner review (5-year retention, 31 CFR 1010.430).',
    },
    {
      id: 'aml.file_sar.t3.escalate',
      actionType: 'tool_call',
      namePattern: '^file_sar$',
      riskTier: 'T3',
      decision: 'escalate',
      capture: 'full',
      controls: ['31 CFR 1020.320'],
      reason:
        'Filing a SAR (FinCEN Form 111) requires BSA officer authorization; the agent cannot file autonomously (31 CFR 1020.320).',
    },
    {
      id: 'aml.notify_customer_of_sar.t3.deny',
      actionType: 'tool_call',
      namePattern: '^notify_customer_of_sar$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'full',
      controls: ['31 CFR 1020.320(e)', '31 U.S.C. 5318(g)(2)'],
      reason:
        'Blocked: notifying a customer that a SAR exists is illegal "tipping off" (31 CFR 1020.320(e); 31 U.S.C. 5318(g)(2)).',
    },
  ],
};

/** Base policy for the CTR tool; the amount helper refines its decision. */
const AML_CTR_DOC = {
  version: 0,
  description: 'Attestor AML investigation showcase policy — CTR threshold (additive demo layer).',
  defaultRule: {
    id: 'aml.ctr.default',
    riskTier: 'T2',
    decision: 'escalate',
    capture: 'digest',
    controls: ['FFIEC-BSA/AML-Manual'],
    reason: 'Unclassified AML action; escalate for BSA analyst review (conservative default).',
  },
  rules: [
    {
      id: 'aml.report_ctr.t3',
      actionType: 'tool_call',
      namePattern: '^report_ctr$',
      riskTier: 'T3',
      decision: 'escalate',
      capture: 'full',
      controls: ['31 CFR 1010.311'],
      reason: 'Currency transaction; subject to the $10,000 CTR threshold.',
    },
  ],
};

/** Domain-accurate CTR reason: a CTR is a mandatory, automatic filing — not discretionary. */
function ctrReason(argumentsJson: string, decision: PolicyDecision): string {
  const amount = readAmount(argumentsJson);
  const amt = amount === null ? 'an unspecified amount' : `$${amount}`;
  if (decision === 'allow') {
    return `Cash transaction of ${amt} is at or below the $${CTR_THRESHOLD} CTR threshold — no Currency Transaction Report required (31 CFR 1010.311).`;
  }
  return `Cash transaction of ${amt} exceeds the $${CTR_THRESHOLD} CTR threshold — a Currency Transaction Report (FinCEN Form 112) is MANDATORY under 31 CFR 1010.311; flagged so the agent cannot skip the filing.`;
}

/**
 * AML policy engine. Dispositions are decided by the product's name-pattern
 * PolicyV0Engine; the CTR is decided by the shared amount-aware helper (cash
 * over $10,000 → file). The CTR reason is rewritten to reflect that a CTR is a
 * mandatory regulatory filing, not a discretionary auto-approval.
 */
export class AmlPolicyEngine implements PolicyEngine {
  readonly name = 'aml-policy-v0';

  private readonly dispositions = PolicyV0Engine.fromDocument(AML_DISPOSITION_DOC);

  private readonly ctr = createAmountAwarePolicyEngine('aml-ctr', AML_CTR_DOC, {
    tool: CTR_TOOL,
    limit: CTR_THRESHOLD,
    noun: 'Cash transaction',
  });

  async evaluate(input: PolicyInput): Promise<PolicyResult> {
    if (input.actionName === CTR_TOOL) {
      const base = await this.ctr.evaluate(input);
      return { ...base, reason: ctrReason(input.argumentsJson, base.decision) };
    }
    return this.dispositions.evaluate(input);
  }
}

/** The (simulated) AML case the agent is working. */
export const AML_CONTEXT = {
  agent: 'aml-investigation-agent',
  alert: 'AML-2026-0731',
  customerId: 'C-44120',
} as const;

/**
 * A realistic L1→L2 BSA/AML investigation: triage the alert, run EDD, clear a
 * transliteration false-positive leg (with rationale), handle the routine
 * mandatory CTR (none under $10k, mandatory over), escalate the discretionary
 * SAR to a BSA officer, then attempt — and get blocked from — tipping off.
 */
export const AML_STEPS: readonly ShowcaseStep[] = [
  {
    tool: 'review_alert',
    arguments: { alertId: AML_CONTEXT.alert, type: 'structuring' },
    narrative: `Agent opens transaction-monitoring alert ${AML_CONTEXT.alert} (L1 triage)`,
  },
  {
    tool: 'pull_customer_profile',
    arguments: { customerId: AML_CONTEXT.customerId },
    narrative: 'Agent pulls the KYC/customer profile (enhanced due diligence)',
  },
  {
    tool: 'screen_sanctions_pep',
    arguments: { customerId: AML_CONTEXT.customerId },
    narrative: 'Agent runs sanctions / PEP / adverse-media screening',
  },
  {
    tool: 'dismiss_alert',
    arguments: {
      alertId: AML_CONTEXT.alert,
      leg: 'name-match',
      rationale: 'transliteration false positive — name match resolves to a different DOB/nationality',
    },
    narrative: 'Agent clears the name-match leg as a false positive (rationale recorded)',
  },
  {
    tool: 'report_ctr',
    arguments: { customerId: AML_CONTEXT.customerId, amount: 5000, kind: 'cash_deposit' },
    narrative: 'A $5,000 cash deposit — under the $10k CTR threshold (no CTR)',
  },
  {
    tool: 'report_ctr',
    arguments: { customerId: AML_CONTEXT.customerId, amount: 25000, kind: 'cash_deposit' },
    narrative: 'A $25,000 cash deposit — over the $10k CTR threshold (CTR mandatory)',
  },
  {
    tool: 'file_sar',
    arguments: { customerId: AML_CONTEXT.customerId, form: 'FinCEN Form 111', basis: 'structuring' },
    narrative: 'Residual structuring is suspicious — agent attempts to file a SAR',
  },
  {
    tool: 'notify_customer_of_sar',
    arguments: { customerId: AML_CONTEXT.customerId, message: 'Heads up: we filed a report on your account.' },
    narrative: 'Agent attempts to warn the customer about the SAR (tipping off)',
  },
];

/** The AML scenario, assembled behind the shared `Scenario` interface. */
export const amlScenario: Scenario = {
  id: 'aml',
  title: `"${AML_CONTEXT.agent}" investigates transaction-monitoring alert ${AML_CONTEXT.alert}.`,
  intro:
    'Every tool is SIMULATED — no real customer data, no real SAR, no real filing. (BSA/AML workflow, FFIEC examiner standard.)',
  agentId: AML_CONTEXT.agent,
  steps: AML_STEPS,
  createToolServer: createAmlToolServer,
  createPolicyEngine: (): AmlPolicyEngine => new AmlPolicyEngine(),
};
