import type { Client } from '@modelcontextprotocol/sdk/client/index.js';

/**
 * A minimal, real MCP-native agent. It is a genuine MCP Client; the caller wires
 * it to the Attestor proxy's transport ONLY (never to the tools), so it can only
 * reach tools through Attestor. It issues a realistic sequence that exercises
 * allow / escalate / deny so we can watch real (non-scripted) interception.
 */
export interface AgentStep {
  readonly tool: string;
  readonly arguments: Record<string, unknown>;
  readonly intent: string;
}

/** The default plan: an investigator reads, derives, writes, then over-reaches. */
export const LIVE_AGENT_PLAN: readonly AgentStep[] = [
  {
    tool: 'read_record',
    arguments: { recordId: 'CASE-001' },
    intent: 'read the case record (expect ALLOW)',
  },
  {
    tool: 'compute_risk_score',
    arguments: { recordId: 'CASE-001', factors: [3, 5, 2] },
    intent: 'compute a risk score (expect ALLOW)',
  },
  {
    tool: 'write_disposition',
    arguments: { caseId: 'CASE-001', disposition: 'cleared', rationale: 'low aggregate risk' },
    intent: 'write a disposition (expect ALLOW — recorded before execution)',
  },
  {
    tool: 'export_case_file',
    arguments: { caseId: 'CASE-001' },
    intent: 'export the full case file (expect ESCALATE)',
  },
  {
    tool: 'purge_records',
    arguments: {},
    intent: 'purge all records (expect DENY)',
  },
];

export interface AgentResult {
  readonly tool: string;
  readonly intent: string;
  /** True if the proxy blocked the call (deny/escalate/error). */
  readonly blocked: boolean;
  /** Text the agent observed (downstream output or the block message). */
  readonly text: string;
  /** Attestor metadata the proxy attaches to blocked calls. */
  readonly decision: string | null;
  readonly riskTier: string | null;
}

interface CallToolResult {
  isError?: boolean;
  content?: { type: string; text?: string }[];
  _meta?: Record<string, unknown>;
}

/** Drive the agent through a plan, returning what it observed at each step. */
export async function runAgent(
  client: Client,
  plan: readonly AgentStep[] = LIVE_AGENT_PLAN,
): Promise<AgentResult[]> {
  const results: AgentResult[] = [];
  for (const step of plan) {
    try {
      const res = (await client.callTool({
        name: step.tool,
        arguments: step.arguments,
      })) as CallToolResult;
      const text = (res.content ?? []).map((c) => c.text ?? '').join(' ');
      results.push({
        tool: step.tool,
        intent: step.intent,
        blocked: res.isError === true,
        text,
        decision: (res._meta?.['attestor/decision'] as string | undefined) ?? null,
        riskTier: (res._meta?.['attestor/riskTier'] as string | undefined) ?? null,
      });
    } catch (err) {
      results.push({
        tool: step.tool,
        intent: step.intent,
        blocked: true,
        text: err instanceof Error ? err.message : String(err),
        decision: null,
        riskTier: null,
      });
    }
  }
  return results;
}
