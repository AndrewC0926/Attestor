#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createSampleToolServer } from '../sample-tools.js';

/** Stdio entrypoint for the bundled sample tool server (downstream of the gateway). */
async function main(): Promise<void> {
  const server = createSampleToolServer();
  await server.connect(new StdioServerTransport());
}

main().catch((err: unknown) => {
  process.stderr.write(`sample-tools failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
