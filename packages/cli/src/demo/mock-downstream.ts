import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

/** The tools the demo's downstream MCP server exposes. */
export const DEMO_TOOLS = [
  'fs.read',
  'db.query',
  'service.status',
  'config.update',
  'file.write',
  'report.create',
  'email.send',
  'payments.transfer',
  'db.delete',
  'cache.read',
] as const;

/**
 * A minimal in-process MCP server standing in for the customer's real tool
 * servers. It returns canned results; the point of the demo is the gateway's
 * audit behaviour around it, not the tools themselves.
 */
export function createMockDownstream(): Server {
  const server = new Server(
    { name: 'demo-tools', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () =>
    Promise.resolve({
      tools: DEMO_TOOLS.map((name) => ({
        name,
        description: `Demo tool ${name}`,
        inputSchema: { type: 'object' as const },
      })),
    }),
  );

  server.setRequestHandler(CallToolRequestSchema, (request) =>
    Promise.resolve({
      content: [{ type: 'text' as const, text: `downstream executed ${request.params.name}` }],
    }),
  );

  return server;
}
