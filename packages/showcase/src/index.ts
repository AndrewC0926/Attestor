/**
 * @attestor/showcase — an additive demo layer on top of the Attestor product.
 *
 * Purpose-built MCP agents wired through the EXISTING gateway and spine, to
 * visibly demonstrate allow / escalate / deny in real time, replay the account
 * from the signed evidence, and prove tamper-evidence on screen. It modifies
 * neither the spine nor the gateway core: it only consumes their public
 * interfaces and supplies its own tools and (argument-aware) policy engines.
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
  createAmountAwarePolicyEngine,
  readAmount,
  type AmountThreshold,
} from './amount-policy.js';
export {
  createFinanceToolServer,
  FinancePolicyEngine,
  FINANCE_TOOLS,
  FINANCE_STEPS,
  FINANCE_CONTEXT,
  MOVE_FUNDS_AUTO_APPROVE_LIMIT,
  type FinanceTool,
} from './scenarios/finance.js';
export {
  getScenario,
  SCENARIO_IDS,
  DEFAULT_SCENARIO_ID,
  supportDeskScenario,
  financeScenario,
  type Scenario,
} from './scenarios/index.js';
export {
  createShowcaseHarness,
  SHOWCASE_DIR,
  SHOWCASE_AGENT_ID,
  type ShowcaseHarness,
} from './harness.js';
export { projectReplay, type ReplayEntry } from './replay.js';
export {
  flipEvidenceByte,
  restoreEvidenceByte,
  type TamperResult,
} from './tamper.js';
