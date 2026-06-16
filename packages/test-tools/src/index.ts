/**
 * @attestor/test-tools — a real, sandboxed downstream MCP tool server for the
 * live-traffic demo. Real file/compute side effects confined to a scratch dir.
 */
export { createTestToolsServer, seedRecord } from './server.js';
export { LIVE_TOOLS_POLICY } from './policy.js';

/** The tool names this server exposes, with their intended risk tiers (docs). */
export const TEST_TOOL_NAMES = [
  'read_record',
  'compute_risk_score',
  'write_disposition',
  'export_case_file',
  'purge_records',
] as const;
