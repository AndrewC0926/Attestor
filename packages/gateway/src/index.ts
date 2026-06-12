/**
 * @attestor/gateway — MCP-first instrumentation and audit gateway.
 *
 * Speaks MCP on both sides: an MCP server to the agent, an MCP client to the
 * downstream tool servers. Every tool call passes through the audit core, which
 * classifies risk, enforces the policy decision, and records signed evidence.
 */
export {
  GatewayCore,
  type ToolCall,
  type ForwardFn,
  type GatewayDecision,
  type GatewayError,
  type GatewayErrorCode,
  type GatewayCoreOptions,
} from './core.js';
export { EvidenceBuffer } from './buffer.js';
export { SpineEvidenceSink, type EvidenceSink } from './sink.js';
export { canonicalJson } from './canonical-json.js';
export { PolicyV0Engine } from './policy/engine.js';
export type { PolicyEngine, PolicyInput, PolicyResult } from './policy/types.js';
export {
  connectDownstream,
  type DownstreamConfig,
} from './downstream.js';
export {
  buildAuditedServer,
  serveStdio,
  serveHttp,
  type AuditedServerOptions,
  type HttpServeOptions,
} from './server.js';
export {
  startGateway,
  type GatewayConfig,
  type GatewayHandle,
} from './runtime.js';
export { createSampleToolServer, SAMPLE_TOOLS } from './sample-tools.js';
