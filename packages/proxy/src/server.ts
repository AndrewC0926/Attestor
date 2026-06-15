import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { ProxyCore, type Forward, type ProxyCall } from './proxy-core.js';

/**
 * The Attestor MCP proxy server. It is a REAL MCP server the agent connects to;
 * the agent is handed only this transport and never a handle to the downstream
 * tools, so it cannot reach them except through here — a true man-in-the-middle,
 * not a cooperative wrapper. `tools/list` is forwarded unchanged; every
 * `tools/call` goes through the hot path in `ProxyCore` (classify → record →
 * maybe forward). Denied/escalated calls become structured tool errors and are
 * never forwarded.
 */
export interface ProxyServerOptions {
  /** Identity attributed to the calling agent in evidence records. */
  readonly agentId: string;
  readonly serverInfo?: { name: string; version: string };
}

export function buildProxyServer(
  core: ProxyCore,
  downstream: Client,
  options: ProxyServerOptions,
): Server {
  const server = new Server(
    options.serverInfo ?? { name: 'attestor-proxy', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => downstream.listTools());

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const call: ProxyCall = {
      agentId: options.agentId,
      toolName: request.params.name,
      arguments: request.params.arguments ?? {},
    };
    const forward: Forward = async (c) =>
      downstream.callTool({
        name: c.toolName,
        arguments: (c.arguments ?? {}) as Record<string, unknown>,
      });

    const outcome = await core.handle(call, forward);

    if (!outcome.allowed && outcome.error) {
      return {
        content: [{ type: 'text', text: outcome.error.message }],
        isError: true,
        _meta: {
          'attestor/decision': outcome.decision,
          'attestor/riskTier': outcome.riskTier,
          'attestor/errorCode': outcome.error.code,
        },
      };
    }
    return outcome.response as Record<string, unknown>;
  });

  return server;
}
