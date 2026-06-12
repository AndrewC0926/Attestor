#!/usr/bin/env node
import { storeConfigFromEnv } from '@attestor/spine';
import { startGateway, type GatewayConfig } from '../runtime.js';
import type { DownstreamConfig } from '../downstream.js';

/** stderr logger — stdout is reserved for the stdio MCP channel. */
function log(message: string): void {
  process.stderr.write(`[attestor-gateway] ${message}\n`);
}

function resolveDownstream(env: NodeJS.ProcessEnv): DownstreamConfig {
  if (env.ATTESTOR_DOWNSTREAM_URL) {
    return { kind: 'http', url: env.ATTESTOR_DOWNSTREAM_URL };
  }
  if (env.ATTESTOR_DOWNSTREAM_CMD) {
    const args = env.ATTESTOR_DOWNSTREAM_ARGS
      ? env.ATTESTOR_DOWNSTREAM_ARGS.split(' ').filter((a) => a.length > 0)
      : [];
    return { kind: 'stdio', command: env.ATTESTOR_DOWNSTREAM_CMD, args };
  }
  throw new Error(
    'No downstream configured. Set ATTESTOR_DOWNSTREAM_URL (http) or ' +
      'ATTESTOR_DOWNSTREAM_CMD (stdio) to the MCP server the gateway should front.',
  );
}

function resolveConfig(env: NodeJS.ProcessEnv): GatewayConfig {
  const stdio = env.ATTESTOR_STDIO === '1';
  const port = Number(env.ATTESTOR_HTTP_PORT ?? '8080');
  return {
    agentId: env.ATTESTOR_AGENT_ID ?? 'agent',
    policyPath: env.ATTESTOR_POLICY_FILE ?? 'policies/v0.yaml',
    store: storeConfigFromEnv(env),
    keyFilePath: env.ATTESTOR_KEY_FILE ?? '.attestor/signing-key.json',
    bufferPath: env.ATTESTOR_BUFFER_FILE ?? '.attestor/buffer.jsonl',
    downstream: resolveDownstream(env),
    transports: stdio
      ? { stdio: true }
      : { http: { port, host: env.ATTESTOR_HTTP_HOST ?? '0.0.0.0' } },
    checkpointInterval: Number(env.ATTESTOR_CHECKPOINT_INTERVAL ?? '100'),
  };
}

async function main(): Promise<void> {
  const config = resolveConfig(process.env);
  const handle = await startGateway(config);
  const mode = config.transports.stdio
    ? 'stdio'
    : `http://${config.transports.http?.host}:${config.transports.http?.port}`;
  log(`gateway up (${mode}); store=${config.store.kind}; agent=${config.agentId}`);

  const shutdown = (signal: string): void => {
    log(`received ${signal}, shutting down`);
    handle
      .stop()
      .then(() => process.exit(0))
      .catch(() => process.exit(1));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
