/**
 * The scripted support-desk scenario. Pure data — no console, no side effects.
 * The CLI command drives these steps through the gateway and prints the live
 * governance decisions.
 */
import type { ShowcaseStep } from './scenarios/types.js';

export type { ShowcaseStep } from './scenarios/types.js';

/** The (simulated) ticket the agent is working. */
export const SHOWCASE_TICKET = {
  id: 'T-4471',
  customerId: 'C-8832',
  customerName: 'Dana',
  subject: 'Double charge dispute',
} as const;

/**
 * A realistic support interaction: verify the customer, reply, refund a small
 * goodwill amount (auto-approved), attempt a larger refund (escalates), then
 * attempt a bulk data export (denied). Several allowed actions, one escalation,
 * one denial — all flowing through the existing Attestor gateway.
 */
export const SHOWCASE_STEPS: readonly ShowcaseStep[] = [
  {
    tool: 'read_ticket',
    arguments: { ticketId: SHOWCASE_TICKET.id },
    narrative: `Agent opens the disputed-charge ticket ${SHOWCASE_TICKET.id}`,
  },
  {
    tool: 'update_customer_record',
    arguments: {
      customerId: SHOWCASE_TICKET.customerId,
      field: 'identity_verified',
      value: true,
    },
    narrative: 'Agent marks the customer as identity-verified',
  },
  {
    tool: 'post_reply',
    arguments: {
      ticketId: SHOWCASE_TICKET.id,
      body: 'Thanks Dana — confirming the duplicate charge and processing a refund now.',
    },
    narrative: 'Agent replies to the customer',
  },
  {
    tool: 'issue_refund',
    arguments: {
      customerId: SHOWCASE_TICKET.customerId,
      amount: 200,
      reason: 'partial goodwill refund',
    },
    narrative: 'Agent issues a $200 refund (within the auto-approval limit)',
  },
  {
    tool: 'issue_refund',
    arguments: {
      customerId: SHOWCASE_TICKET.customerId,
      amount: 750,
      reason: 'full refund of disputed charge',
    },
    narrative: 'Agent attempts a $750 refund (over the limit → escalates)',
  },
  {
    tool: 'export_customer_data',
    arguments: { customerId: SHOWCASE_TICKET.customerId, scope: 'all' },
    narrative: 'Agent attempts a full PII export (denied by policy)',
  },
];
