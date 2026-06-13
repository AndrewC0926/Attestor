import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { PolicyEngine, PolicyInput, PolicyResult } from '@attestor/gateway';
import type { RiskTier } from '@attestor/types';
import { createAmountAwarePolicyEngine } from '../amount-policy.js';
import type { Scenario, ShowcaseStep } from './types.js';

/**
 * A second, higher-stakes scenario: a finance / treasury-ops agent. It reuses
 * the exact patterns of the support-desk scenario — simulated tools, an
 * argument-aware policy engine via the shared threshold helper, and the same
 * isolated-store discipline. Nothing here touches real money or real accounts.
 */

/** Internal moves at or below this amount auto-approve; above it, escalate. */
export const MOVE_FUNDS_AUTO_APPROVE_LIMIT = 10_000;

const MOVE_FUNDS_TOOL = 'move_funds';

/** Description of a finance tool and its expected governance (for docs/tests). */
export interface FinanceTool {
  readonly name: string;
  readonly tier: RiskTier;
  readonly expected: 'allow' | 'deny' | 'conditional';
  readonly description: string;
}

/** The 5 finance tools the agent is wired to, mapped across tiers. */
export const FINANCE_TOOLS: readonly FinanceTool[] = [
  {
    name: 'check_balance',
    tier: 'T0',
    expected: 'allow',
    description: 'Check an account balance (simulated, read-only).',
  },
  {
    name: 'categorize_transaction',
    tier: 'T1',
    expected: 'allow',
    description: 'Categorize a posted transaction (simulated).',
  },
  {
    name: 'move_funds',
    tier: 'T3',
    expected: 'conditional',
    description: 'Move funds between internal accounts (simulated). Auto-approved up to $10,000; over escalates.',
  },
  {
    name: 'wire_external',
    tier: 'T3',
    expected: 'deny',
    description: 'Wire funds to an external account (denied by policy — never executes).',
  },
  {
    name: 'pull_full_ledger',
    tier: 'T3',
    expected: 'deny',
    description: 'Export the full general ledger (denied by policy — never executes).',
  },
];

function arg(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  return v === undefined ? '?' : String(v);
}

/** Canned, clearly-simulated result for an allowed finance tool call. */
function simulate(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case 'check_balance':
      return `[SIMULATED] account ${arg(args, 'account')} balance: $1,250,000.00 available`;
    case 'categorize_transaction':
      return `[SIMULATED] transaction ${arg(args, 'txnId')} categorized as '${arg(args, 'category')}'`;
    case 'move_funds':
      return `[SIMULATED] moved $${arg(args, 'amount')} from ${arg(args, 'from')} to ${arg(args, 'to')} — no real money moved`;
    case 'wire_external':
      return `[SIMULATED] external wire of $${arg(args, 'amount')} to ${arg(args, 'to')}`;
    case 'pull_full_ledger':
      return `[SIMULATED] full ledger export (${arg(args, 'scope')})`;
    default:
      return `[SIMULATED] executed ${name}`;
  }
}

/** In-process MCP server standing in for a treasury/payments tool surface. */
export function createFinanceToolServer(): Server {
  const server = new Server(
    { name: 'finance-tools', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () =>
    Promise.resolve({
      tools: FINANCE_TOOLS.map((t) => ({
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

/** Name-pattern base policy for the finance tools (data only). */
const FINANCE_POLICY_DOC = {
  version: 0,
  description: 'Attestor finance/treasury showcase policy (additive demo layer).',
  defaultRule: {
    id: 'finance.default.unknown',
    riskTier: 'T2',
    decision: 'escalate',
    capture: 'digest',
    controls: ['A.6.2.4', 'A.9.2'],
    reason: 'Unclassified finance action; escalate for human review.',
  },
  rules: [
    {
      id: 'finance.check_balance.t0',
      actionType: 'tool_call',
      namePattern: '^check_balance$',
      riskTier: 'T0',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4'],
      reason: 'Read-only balance lookup (non-sensitive metadata).',
    },
    {
      id: 'finance.categorize_transaction.t1',
      actionType: 'tool_call',
      namePattern: '^categorize_transaction$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4', 'A.6.2.8'],
      reason: 'Read/annotate of operator-owned transaction data.',
    },
    {
      id: 'finance.move_funds.t3',
      actionType: 'tool_call',
      namePattern: '^move_funds$',
      riskTier: 'T3',
      // Base decision is conservative; the engine refines it by amount.
      // capture:full retains the transfer details for the replay/forensics.
      decision: 'escalate',
      capture: 'full',
      controls: ['A.9.2', 'A.5.5'],
      reason: 'Internal funds movement; subject to the auto-approval limit.',
    },
    {
      id: 'finance.wire_external.t3.deny',
      actionType: 'tool_call',
      namePattern: '^wire_external$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'full',
      controls: ['A.9.2', 'A.5.5'],
      reason: 'External wire blocked by showcase policy (no allowlist in the demo).',
    },
    {
      id: 'finance.pull_full_ledger.t3.deny',
      actionType: 'tool_call',
      namePattern: '^pull_full_ledger$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'full',
      controls: ['A.9.2', 'A.6.2.8'],
      reason: 'Full-ledger export blocked by showcase policy.',
    },
  ],
};

/**
 * Argument-aware policy engine for the finance scenario. Mirrors the support
 * desk: name-pattern base, refined by an amount threshold on `move_funds`.
 */
export class FinancePolicyEngine implements PolicyEngine {
  readonly name = 'finance-policy-v0';

  private readonly engine = createAmountAwarePolicyEngine(this.name, FINANCE_POLICY_DOC, {
    tool: MOVE_FUNDS_TOOL,
    limit: MOVE_FUNDS_AUTO_APPROVE_LIMIT,
    noun: 'Transfer',
  });

  evaluate(input: PolicyInput): Promise<PolicyResult> {
    return this.engine.evaluate(input);
  }
}

/** The (simulated) treasury context the agent is working. */
export const FINANCE_CONTEXT = {
  agent: 'treasury-ops-agent',
  runbook: 'month-end vendor settlement',
} as const;

/**
 * The finance scenario: balance check, categorize, an in-limit move (allowed),
 * an over-limit move (escalates), then an external wire and a full-ledger export
 * (both denied). Several allowed actions, one escalation, two denials — every
 * tool exercised on screen.
 */
export const FINANCE_STEPS: readonly ShowcaseStep[] = [
  {
    tool: 'check_balance',
    arguments: { account: 'OPS-001' },
    narrative: 'Agent checks the operating account balance',
  },
  {
    tool: 'categorize_transaction',
    arguments: { txnId: 'TXN-55012', category: 'vendor_settlement' },
    narrative: 'Agent categorizes a posted transaction',
  },
  {
    tool: 'move_funds',
    arguments: { from: 'OPS-001', to: 'PAYROLL-002', amount: 5000, memo: 'payroll top-up' },
    narrative: 'Agent moves $5,000 internally (within the auto-approval limit)',
  },
  {
    tool: 'move_funds',
    arguments: { from: 'OPS-001', to: 'VENDOR-477', amount: 25000, memo: 'vendor settlement' },
    narrative: 'Agent attempts a $25,000 internal move (over the limit → escalates)',
  },
  {
    tool: 'wire_external',
    arguments: { to: 'IBAN GB29 NWBK 6016 1331 9268 19', amount: 25000, memo: 'vendor settlement' },
    narrative: 'Agent attempts a $25,000 external wire (denied by policy)',
  },
  {
    tool: 'pull_full_ledger',
    arguments: { scope: 'all-accounts', format: 'csv' },
    narrative: 'Agent attempts a full general-ledger export (denied by policy)',
  },
];

/** The finance scenario, assembled behind the shared `Scenario` interface. */
export const financeScenario: Scenario = {
  id: 'finance',
  title: `"${FINANCE_CONTEXT.agent}" runs the ${FINANCE_CONTEXT.runbook} runbook.`,
  intro: 'Every tool is SIMULATED — no real money moves, no real accounts.',
  agentId: FINANCE_CONTEXT.agent,
  steps: FINANCE_STEPS,
  createToolServer: createFinanceToolServer,
  createPolicyEngine: (): FinancePolicyEngine => new FinancePolicyEngine(),
};
