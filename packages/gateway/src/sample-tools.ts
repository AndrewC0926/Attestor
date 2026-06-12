import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

/** Sample tool names spanning every risk tier, for the demo and Compose image. */
export const SAMPLE_TOOLS = [
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
 * A minimal in-process MCP server standing in for a customer's real tool
 * servers. It returns canned results so the gateway's audit behaviour can be
 * exercised without external dependencies.
 */
export function createSampleToolServer(): Server {
  const server = new Server(
    { name: 'attestor-sample-tools', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () =>
    Promise.resolve({
      tools: SAMPLE_TOOLS.map((name) => ({
        name,
        description: `Sample tool ${name}`,
        inputSchema: { type: 'object' as const },
      })),
    }),
  );

  server.setRequestHandler(CallToolRequestSchema, (request) =>
    Promise.resolve({
      content: [
        { type: 'text' as const, text: `executed ${request.params.name}` },
      ],
    }),
  );

  return server;
}
