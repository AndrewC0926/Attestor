import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

/**
 * Downstream (tool-side) connection. The gateway is a client to the real MCP
 * servers it fronts, speaking MCP on both sides — the Envoy sidecar pattern.
 */
export type DownstreamConfig =
  | { readonly kind: 'stdio'; readonly command: string; readonly args?: string[]; readonly env?: Record<string, string> }
  | { readonly kind: 'http'; readonly url: string }
  /** A pre-built transport (used for in-memory wiring in tests and the demo). */
  | { readonly kind: 'transport'; readonly transport: Transport };

function buildTransport(config: DownstreamConfig): Transport {
  switch (config.kind) {
    case 'stdio':
      return new StdioClientTransport({
        command: config.command,
        ...(config.args ? { args: config.args } : {}),
        ...(config.env ? { env: config.env } : {}),
      });
    case 'http':
      return new StreamableHTTPClientTransport(new URL(config.url));
    case 'transport':
      return config.transport;
  }
}

/** Connect a downstream MCP client over the configured transport. */
export async function connectDownstream(config: DownstreamConfig): Promise<Client> {
  const client = new Client({ name: 'attestor-gateway-downstream', version: '0.1.0' });
  await client.connect(buildTransport(config));
  return client;
}
