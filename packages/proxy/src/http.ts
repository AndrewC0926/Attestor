import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ProxyCore } from './proxy-core.js';
import { buildProxyServer } from './server.js';

/**
 * Serve the Attestor proxy over real Streamable HTTP, the transport a networked
 * agent (e.g. Vetria) uses. This is the standard MCP stateful pattern: the first
 * request (`initialize`) creates a session + transport bound to a fresh proxy
 * server (sharing the same core + downstream client); subsequent requests are
 * routed by the `mcp-session-id` header. The agent is handed only this URL — it
 * never receives a handle to the downstream tools.
 */
export interface ProxyHttpOptions {
  readonly agentId: string;
  readonly port: number;
  readonly host?: string;
}

export interface ProxyHttpHandle {
  readonly url: string;
  stop(): Promise<void>;
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw.length > 0 ? (JSON.parse(raw) as unknown) : undefined;
}

export async function serveProxyHttp(
  core: ProxyCore,
  downstream: Client,
  options: ProxyHttpOptions,
): Promise<ProxyHttpHandle> {
  const host = options.host ?? '127.0.0.1';
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async (): Promise<void> => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport = sessionId ? transports.get(sessionId) : undefined;

        if (!transport) {
          // New session: bind a fresh proxy server to a new transport.
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sid): void => {
              transports.set(sid, transport as StreamableHTTPServerTransport);
            },
          });
          transport.onclose = (): void => {
            if (transport?.sessionId) {
              transports.delete(transport.sessionId);
            }
          };
          const server = buildProxyServer(core, downstream, { agentId: options.agentId });
          await server.connect(transport);
        }

        const body = req.method === 'POST' ? await readBody(req) : undefined;
        await transport.handleRequest(req, res, body);
      } catch (err) {
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
        }
      }
    })();
  });

  await new Promise<void>((resolve) => httpServer.listen(options.port, host, resolve));

  return {
    url: `http://${host}:${options.port}/`,
    async stop(): Promise<void> {
      for (const t of transports.values()) {
        await t.close();
      }
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
