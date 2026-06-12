import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Spine, resolveKeyPair } from '@attestor/spine';
import {
  EvidenceBuffer,
  GatewayCore,
  PolicyV0Engine,
  SpineEvidenceSink,
  buildAuditedServer,
} from '@attestor/gateway';
import type { CliConfig } from '../config.js';
import { loadControlCatalog } from '../controls.js';
import { buildReport } from '../report/build.js';
import { renderMarkdown } from '../report/markdown.js';
import { renderJson } from '../report/json.js';
import { createMockDownstream } from '../demo/mock-downstream.js';

const DEMO_DIR = '.attestor/demo';
const AGENT_ID = 'demo-agent';

interface Step {
  readonly tool: string;
  readonly args: Record<string, unknown>;
  readonly note: string;
}

/** Ten actions across the tier spectrum, including a denied T3 transfer. */
const STEPS: readonly Step[] = [
  { tool: 'service.status', args: {}, note: 'T0 read-only metadata' },
  { tool: 'fs.read', args: { path: '/etc/app/config.yaml' }, note: 'T1 read' },
  { tool: 'db.query', args: { sql: 'select count(*) from invoices' }, note: 'T1 read' },
  { tool: 'config.update', args: { key: 'rate_limit', value: 100 }, note: 'T2 write' },
  { tool: 'file.write', args: { path: '/tmp/out.txt', bytes: 12 }, note: 'T2 write' },
  { tool: 'report.create', args: { title: 'Q2 summary' }, note: 'T2 write' },
  { tool: 'cache.read', args: { key: 'session:42' }, note: 'T1 read' },
  { tool: 'email.send', args: { to: 'cfo@example.com' }, note: 'T3 external — escalate' },
  { tool: 'payments.transfer', args: { to: 'acct-999', amount: 50000 }, note: 'T3 financial — DENY' },
  { tool: 'db.delete', args: { table: 'audit_log' }, note: 'T3 destructive — DENY' },
];

interface CallResultMeta {
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/** `attestor demo` — run the full end-to-end scenario against a fresh store. */
export async function runDemo(config: CliConfig): Promise<number> {
  rmSync(DEMO_DIR, { recursive: true, force: true });
  mkdirSync(DEMO_DIR, { recursive: true });

  const keys = resolveKeyPair(join(DEMO_DIR, 'signing-key.json'), {} as NodeJS.ProcessEnv);
  const spine = await Spine.open(
    { kind: 'sqlite', path: join(DEMO_DIR, 'evidence.sqlite') },
    keys,
    { checkpointInterval: 4 },
  );
  const engine = PolicyV0Engine.fromFile(config.policyPath);
  const core = new GatewayCore(
    engine,
    new SpineEvidenceSink(spine),
    new EvidenceBuffer(join(DEMO_DIR, 'buffer.jsonl')),
  );

  // Wire: agent <-> gateway (audited) <-> downstream mock, all in-process MCP.
  const [agentSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  const [downClientSide, mockSide] = InMemoryTransport.createLinkedPair();

  const mock = createMockDownstream();
  await mock.connect(mockSide);
  const downstreamClient = new Client({ name: 'demo-downstream', version: '0.1.0' });
  await downstreamClient.connect(downClientSide);

  const gateway = buildAuditedServer(core, downstreamClient, { agentId: AGENT_ID });
  await gateway.connect(gatewaySide);
  const agent = new Client({ name: 'demo-agent-client', version: '0.1.0' });
  await agent.connect(agentSide);

  console.log('Attestor demo — agent performing 10 actions through the audit gateway:\n');
  for (const [i, step] of STEPS.entries()) {
    const res = (await agent.callTool({
      name: step.tool,
      arguments: step.args,
    })) as CallResultMeta;
    const blocked = res.isError === true;
    const decision = (res._meta?.['attestor/decision'] as string | undefined) ?? 'allow';
    const tier = (res._meta?.['attestor/riskTier'] as string | undefined) ?? '';
    const mark = blocked ? '⛔ BLOCKED' : '✅ allowed';
    console.log(
      `  ${String(i + 1).padStart(2)}. ${step.tool.padEnd(20)} ${mark}  (${decision}${tier ? ` ${tier}` : ''}) — ${step.note}`,
    );
  }

  await spine.checkpoint();

  // Regenerate the incident trail and prove integrity.
  const [records, checkpoints, verification] = await Promise.all([
    spine.getAllRecords(),
    spine.getCheckpoints(),
    spine.verify(),
  ]);
  const report = buildReport({
    records,
    checkpoints,
    verification,
    catalog: loadControlCatalog(config.controlsPath),
    from: null,
    to: null,
    generatedAt: new Date().toISOString(),
  });
  const reportPrefix = join(DEMO_DIR, 'attestation');
  writeFileSync(`${reportPrefix}.md`, renderMarkdown(report), 'utf8');
  writeFileSync(`${reportPrefix}.json`, renderJson(report), 'utf8');

  console.log('\n— Results —');
  console.log(`  Evidence records:   ${records.length}`);
  console.log(`  Signed checkpoints: ${checkpoints.length}`);
  console.log(`  Chain integrity:    ${verification.ok ? '✅ VERIFIED' : '❌ FAILED'}`);
  console.log(`  Latest signed root: ${checkpoints.at(-1)?.merkleRoot ?? '—'}`);
  console.log(`  Attestation report: ${reportPrefix}.md (+ .json)\n`);

  console.log('Try it yourself:');
  console.log(
    `  ATTESTOR_SQLITE_PATH=${join(DEMO_DIR, 'evidence.sqlite')} \\\n    ATTESTOR_KEY_FILE=${join(DEMO_DIR, 'signing-key.json')} attestor verify`,
  );
  console.log(
    '  # Then tamper out-of-band (sqlite3 ...UPDATE evidence_record...) and re-run verify — it will fail.\n',
  );

  await agent.close();
  await gateway.close();
  await downstreamClient.close();
  await mock.close();
  await spine.close();

  return verification.ok ? 0 : 1;
}
