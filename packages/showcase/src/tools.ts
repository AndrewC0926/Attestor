import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { RiskTier } from '@attestor/types';

/**
 * The simulated "support desk" tool surface for the showcase.
 *
 * IMPORTANT: every tool here is a SIMULATION. Nothing touches a real CRM, real
 * payments, or real customer data — handlers return canned, clearly-labelled
 * strings. The point of the showcase is to exercise the *governance* path
 * (classify → decide → record signed evidence), not to perform real work.
 */
export interface SupportDeskTool {
  readonly name: string;
  /** Expected risk tier under the showcase policy (for docs/inspection). */
  readonly tier: RiskTier;
  /** Expected steady-state outcome: a conditional tool depends on its args. */
  readonly expected: 'allow' | 'deny' | 'conditional';
  readonly description: string;
}

/** The 6 tools the support-desk agent is wired to, mapped across tiers. */
export const SUPPORT_DESK_TOOLS: readonly SupportDeskTool[] = [
  {
    name: 'read_ticket',
    tier: 'T0',
    expected: 'allow',
    description: 'Read a support ticket (simulated, read-only).',
  },
  {
    name: 'post_reply',
    tier: 'T1',
    expected: 'allow',
    description: 'Post a reply on a ticket (simulated).',
  },
  {
    name: 'update_customer_record',
    tier: 'T2',
    expected: 'allow',
    description: 'Update a field on a customer record (simulated CRM write).',
  },
  {
    name: 'issue_refund',
    tier: 'T3',
    expected: 'conditional',
    description: 'Issue a refund (simulated). Auto-approved up to $500; over $500 escalates.',
  },
  {
    name: 'delete_account',
    tier: 'T3',
    expected: 'deny',
    description: 'Delete a customer account (denied by policy — never executes).',
  },
  {
    name: 'export_customer_data',
    tier: 'T3',
    expected: 'deny',
    description: 'Bulk-export customer PII (denied by policy — never executes).',
  },
];

function arg(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  return v === undefined ? '?' : String(v);
}

/** Produce the canned, clearly-simulated result for an allowed tool call. */
function simulate(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case 'read_ticket':
      return `[SIMULATED] ticket ${arg(args, 'ticketId')}: status=open, subject="Double charge dispute", customer=C-8832`;
    case 'post_reply':
      return `[SIMULATED] reply posted to ticket ${arg(args, 'ticketId')}`;
    case 'update_customer_record':
      return `[SIMULATED] customer ${arg(args, 'customerId')} field '${arg(args, 'field')}' set to '${arg(args, 'value')}'`;
    case 'issue_refund':
      return `[SIMULATED] refund of $${arg(args, 'amount')} issued to ${arg(args, 'customerId')} — no real money moved`;
    case 'delete_account':
      return `[SIMULATED] account deletion for ${arg(args, 'customerId')}`;
    case 'export_customer_data':
      return `[SIMULATED] export of ${arg(args, 'scope')} data for ${arg(args, 'customerId')}`;
    default:
      return `[SIMULATED] executed ${name}`;
  }
}

/**
 * An in-process MCP server standing in for a customer's real support tooling.
 * Mirrors the gateway's own sample-tools server so the showcase wires up the
 * same way the product demo does.
 */
export function createSupportDeskServer(): Server {
  const server = new Server(
    { name: 'support-desk-tools', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () =>
    Promise.resolve({
      tools: SUPPORT_DESK_TOOLS.map((t) => ({
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
