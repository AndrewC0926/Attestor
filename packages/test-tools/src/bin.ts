#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createTestToolsServer } from './server.js';

/**
 * Run the real downstream tools as a standalone stdio MCP server. The Attestor
 * proxy spawns this as a CHILD PROCESS and is its only client, so the agent —
 * which talks only to the proxy — can never reach these tools directly.
 *
 * The sandbox directory is taken from ATTESTOR_SANDBOX_DIR.
 */
const sandboxDir = process.env.ATTESTOR_SANDBOX_DIR ?? '.attestor/live/sandbox';

const server = createTestToolsServer(sandboxDir);
await server.connect(new StdioServerTransport());
