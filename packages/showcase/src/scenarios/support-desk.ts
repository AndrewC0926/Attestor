import type { Scenario } from './types.js';
import { createSupportDeskServer } from '../tools.js';
import { SupportDeskPolicyEngine } from '../policy.js';
import { SHOWCASE_STEPS, SHOWCASE_TICKET } from '../scenario.js';

/**
 * The original support-desk scenario, assembled as a `Scenario`. Behaviour is
 * unchanged from the first showcase release — this just packages the existing
 * tools, policy engine, and steps behind the scenario interface so the runner
 * can host multiple scenarios.
 */
export const supportDeskScenario: Scenario = {
  id: 'support-desk',
  title: `"support-desk-agent" works ticket ${SHOWCASE_TICKET.id} for ${SHOWCASE_TICKET.customerName} (“${SHOWCASE_TICKET.subject}”).`,
  intro: 'Every tool is SIMULATED — no real customer data, no real money moves.',
  agentId: 'support-desk-agent',
  steps: SHOWCASE_STEPS,
  createToolServer: createSupportDeskServer,
  createPolicyEngine: (): SupportDeskPolicyEngine => new SupportDeskPolicyEngine(),
};
