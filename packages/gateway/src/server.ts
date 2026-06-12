import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { GatewayCore, ToolCall } from './core.js';

/**
 * MCP server wiring. The gateway is itself an MCP server: it forwards tools/list
 * to the downstream server unchanged and intercepts every tools/call through the
 * audit core. Denied or escalated calls are returned to the agent as structured
 * tool errors and are never forwarded downstream.
 */
export interface AuditedServerOptions {
  /** Identity attributed to the calling agent in evidence records. */
  readonly agentId: string;
  readonly serverInfo?: { name: string; version: string };
}

export function buildAuditedServer(
  core: GatewayCore,
  downstream: Client,
  options: AuditedServerOptions,
): Server {
  const server = new Server(
    options.serverInfo ?? { name: 'attestor-gateway', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => downstream.listTools());

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const call: ToolCall = {
      agentId: options.agentId,
      toolName: request.params.name,
      arguments: request.params.arguments ?? {},
    };
    const decision = await core.handleToolCall(call, async (c) =>
      downstream.callTool({
        name: c.toolName,
        arguments: (c.arguments ?? {}) as Record<string, unknown>,
      }),
    );

    if (!decision.allowed && decision.error) {
      return {
        content: [{ type: 'text', text: decision.error.message }],
        isError: true,
        _meta: {
          'attestor/decision': decision.policy.decision,
          'attestor/policyId': decision.policy.policyId,
          'attestor/riskTier': decision.policy.riskTier,
          'attestor/errorCode': decision.error.code,
        },
      };
    }
    return decision.response as Record<string, unknown>;
  });

  return server;
}

/** Serve an MCP server over stdio (the transport Claude Desktop/Code uses). */
export async function serveStdio(server: Server): Promise<void> {
  await server.connect(new StdioServerTransport());
}

export interface HttpServeOptions {
  readonly port: number;
  readonly host?: string;
}

/**
 * Serve an MCP server over Streamable HTTP (stateless mode) for networked agents
 * inside a VPC. Returns a stop function that closes the HTTP listener.
 */
export async function serveHttp(
  server: Server,
  options: HttpServeOptions,
): Promise<() => Promise<void>> {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);

  const http = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body: unknown = raw.length > 0 ? JSON.parse(raw) : undefined;
      void transport.handleRequest(req, res, body);
    });
  });

  await new Promise<void>((resolve) => http.listen(options.port, options.host, resolve));

  return () =>
    new Promise<void>((resolve, reject) => {
      http.close((err) => (err ? reject(err) : resolve()));
    });
}
