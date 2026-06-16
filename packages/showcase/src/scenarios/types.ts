import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { PolicyEngine } from '@attestor/gateway';

/**
 * A single action the agent attempts during a scenario. Pure data — the CLI
 * drives these through the gateway and prints the live governance decisions.
 */
export interface ShowcaseStep {
  readonly tool: string;
  readonly arguments: Record<string, unknown>;
  /** One-line, human-readable description of what the agent is doing. */
  readonly narrative: string;
}

/**
 * A self-contained showcase scenario. Each scenario owns its tool surface and
 * its (argument-aware) policy engine, supplied as factories so every run gets
 * fresh, stateless instances — no shared mutable state between scenarios.
 */
export interface Scenario {
  /** Stable id used on the CLI (`--scenario <id>`). */
  readonly id: string;
  /** Headline describing the run (printed after "Attestor showcase — "). */
  readonly title: string;
  /** One-line context / simulation disclaimer printed under the title. */
  readonly intro: string;
  /** Identity attributed to the agent in every evidence record. */
  readonly agentId: string;
  /** The scripted actions, in order. */
  readonly steps: readonly ShowcaseStep[];
  /** Build the downstream (simulated) MCP tool server. */
  createToolServer(): Server;
  /** Build the policy engine that governs this scenario. */
  createPolicyEngine(): PolicyEngine;
}
