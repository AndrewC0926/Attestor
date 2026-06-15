import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';

/**
 * A real downstream MCP tool server with REAL, sandboxed side effects — not
 * mocked returns. Every effect is confined to a scratch sandbox directory. This
 * is what the Attestor proxy fronts: when the proxy forwards an allowed call,
 * something real actually happens (a file is read, a disposition is written);
 * when it blocks a call, the real effect never occurs.
 */

/** Sanitize an id so it can only ever resolve inside the sandbox. */
function safeId(value: unknown): string {
  const s = String(value ?? '').replace(/[^A-Za-z0-9_-]/g, '');
  if (!s) {
    throw new Error('invalid id');
  }
  return s;
}

/** Resolve a path and assert it stays within the sandbox root. */
function within(root: string, ...parts: string[]): string {
  const full = resolve(root, ...parts);
  if (full !== resolve(root) && !full.startsWith(resolve(root) + '/')) {
    throw new Error('path escapes the sandbox');
  }
  return full;
}

/** Build the real tool server over a scratch sandbox directory. */
export function createTestToolsServer(sandboxDir: string): Server {
  const recordsDir = within(sandboxDir, 'records');
  const dispositionsDir = within(sandboxDir, 'dispositions');
  const exportsDir = within(sandboxDir, 'exports');
  for (const d of [recordsDir, dispositionsDir, exportsDir]) {
    mkdirSync(d, { recursive: true });
  }

  const tools = [
    { name: 'read_record', description: 'Read a case record from the sandbox (real file read).' },
    { name: 'compute_risk_score', description: 'Compute a risk score from factors (real compute).' },
    {
      name: 'write_disposition',
      description: 'Write a case disposition to the sandbox (real file write).',
    },
    { name: 'export_case_file', description: 'Export a full case file (real write; T3).' },
    { name: 'purge_records', description: 'Delete all case records (real delete; T3).' },
  ];

  const handlers: Record<string, (args: Record<string, unknown>) => CallToolResult> = {
    read_record(args) {
      const id = safeId(args['recordId']);
      const path = within(recordsDir, `${id}.json`);
      const content = readFileSync(path, 'utf8');
      return text(`[REAL] read record ${id}: ${content}`);
    },
    compute_risk_score(args) {
      const factors = Array.isArray(args['factors']) ? (args['factors'] as unknown[]) : [];
      const score = factors.reduce<number>((acc, f) => acc + (typeof f === 'number' ? f : 0), 0);
      return text(`[REAL] risk score for ${safeId(args['recordId'])} = ${score}`);
    },
    write_disposition(args) {
      const caseId = safeId(args['caseId']);
      const path = within(dispositionsDir, `${caseId}.json`);
      const body = {
        caseId,
        disposition: String(args['disposition'] ?? ''),
        rationale: String(args['rationale'] ?? ''),
        at: new Date().toISOString(),
      };
      writeFileSync(path, JSON.stringify(body, null, 2), 'utf8');
      return text(`[REAL] wrote disposition ${caseId} -> ${path}`);
    },
    export_case_file(args) {
      const caseId = safeId(args['caseId']);
      const path = within(exportsDir, `${caseId}.json`);
      writeFileSync(path, JSON.stringify({ caseId, exportedAt: new Date().toISOString() }), 'utf8');
      return text(`[REAL] exported case ${caseId} -> ${path}`);
    },
    purge_records() {
      const files = readdirSync(recordsDir);
      for (const f of files) {
        rmSync(within(recordsDir, f), { force: true });
      }
      return text(`[REAL] purged ${files.length} record(s)`);
    },
  };

  const server = new Server(
    { name: 'attestor-test-tools', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () =>
    Promise.resolve({
      tools: tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: { type: 'object' as const },
      })),
    }),
  );

  server.setRequestHandler(CallToolRequestSchema, (request) => {
    const handler = handlers[request.params.name];
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    if (!handler) {
      return Promise.resolve({
        content: [{ type: 'text' as const, text: `unknown tool ${request.params.name}` }],
        isError: true,
      });
    }
    return Promise.resolve(handler(args));
  });

  return server;
}

/** Seed a record file so `read_record` has something real to read. */
export function seedRecord(sandboxDir: string, recordId: string, body: unknown): void {
  const dir = within(sandboxDir, 'records');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${safeId(recordId)}.json`), JSON.stringify(body), 'utf8');
}

function text(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }] };
}
