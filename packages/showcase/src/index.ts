/**
 * @attestor/showcase — an additive demo layer on top of the Attestor product.
 *
 * A purpose-built MCP "support desk" agent wired through the EXISTING gateway
 * and spine, designed to visibly demonstrate allow / escalate / deny in real
 * time and end with a tamper-evident replay. It modifies neither the spine nor
 * the gateway core: it only consumes their public interfaces and supplies its
 * own tools and (argument-aware) policy engine.
 */
export {
  createSupportDeskServer,
  SUPPORT_DESK_TOOLS,
  type SupportDeskTool,
} from './tools.js';
export {
  SupportDeskPolicyEngine,
  REFUND_AUTO_APPROVE_LIMIT,
} from './policy.js';
export {
  SHOWCASE_STEPS,
  SHOWCASE_TICKET,
  type ShowcaseStep,
} from './scenario.js';
export {
  createShowcaseHarness,
  SHOWCASE_DIR,
  SHOWCASE_AGENT_ID,
  type ShowcaseHarness,
} from './harness.js';
export { projectReplay, type ReplayEntry } from './replay.js';
