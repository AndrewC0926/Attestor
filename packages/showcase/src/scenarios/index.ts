import type { Scenario } from './types.js';
import { supportDeskScenario } from './support-desk.js';
import { financeScenario } from './finance.js';
import { amlScenario } from './aml.js';

/** The scenario selected when no `--scenario` flag is given. */
export const DEFAULT_SCENARIO_ID = supportDeskScenario.id;

const REGISTRY: Readonly<Record<string, Scenario>> = {
  [supportDeskScenario.id]: supportDeskScenario,
  [financeScenario.id]: financeScenario,
  [amlScenario.id]: amlScenario,
};

/** Ids of all registered scenarios, in registration order. */
export const SCENARIO_IDS: readonly string[] = Object.keys(REGISTRY);

/** Look up a scenario by id, or undefined if there is no such scenario. */
export function getScenario(id: string): Scenario | undefined {
  return REGISTRY[id];
}

export { supportDeskScenario, financeScenario, amlScenario };
export type { Scenario, ShowcaseStep } from './types.js';
