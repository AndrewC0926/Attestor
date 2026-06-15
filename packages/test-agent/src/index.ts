/**
 * @attestor/test-agent — a minimal real MCP-native agent for the live demo.
 * It connects only to the Attestor proxy and issues a realistic call sequence.
 */
export { runAgent, LIVE_AGENT_PLAN, type AgentStep, type AgentResult } from './agent.js';
