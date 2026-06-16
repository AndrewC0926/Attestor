import { createRequire } from 'node:module';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Spine, resolveKeyPair } from '@attestor/spine';
import type { EvidenceRecord, PolicyDecision } from '@attestor/types';
import {
  PolicyV0Engine,
  SpineEvidenceSink,
  EvidenceBuffer,
  connectDownstream,
} from '@attestor/gateway';
import { ProxyCore, serveProxyHttp } from '@attestor/proxy';
import { LIVE_TOOLS_POLICY, seedRecord } from '@attestor/test-tools';
import { runAgent, type AgentResult } from '@attestor/test-agent';
import {
  AnchorService,
  AnchorStore,
  TsaClient,
  FREETSA,
  httpTransport,
  exportBundle,
  writeBundle,
  verifyAnchoredBundle,
} from '@attestor/anchor';
import { printAnchoredVerification } from './verify-anchored.js';

export interface LiveDemoArgs {
  /** Anchor the latest checkpoint to a TSA and verify an exported bundle. */
  readonly anchor?: boolean;
}

const LIVE_DIR = '.attestor/live';
const SANDBOX_DIR = join(LIVE_DIR, 'sandbox');
const SQLITE_PATH = join(LIVE_DIR, 'evidence.sqlite');
const KEY_PATH = join(LIVE_DIR, 'signing-key.json');
const BUNDLE_PATH = join(LIVE_DIR, 'bundle.json');
const PORT = Number(process.env.ATTESTOR_LIVE_PORT ?? 8731);

const LABEL: Record<string, string> = {
  allow: '✅ ALLOWED ',
  escalate: '⚠️  ESCALATE',
  deny: '⛔ DENY    ',
};

function countDecision(records: readonly EvidenceRecord[], decision: PolicyDecision): number {
  return records.filter((r) => r.decision === decision).length;
}

/** Resolve the test-tools stdio bin (the proxy spawns it as a child process). */
function testToolsBin(): string {
  const require = createRequire(import.meta.url);
  return join(dirname(require.resolve('@attestor/test-tools')), 'bin.js');
}

/**
 * `attestor live-demo [--anchor]` — the first real-traffic path.
 *
 * Starts the real downstream tools (a spawned stdio subprocess), serves the
 * Attestor proxy over real Streamable HTTP, connects a real MCP agent to the
 * PROXY ONLY, and lets it issue real calls. The agent cannot reach the tools
 * except through Attestor; every call is governed and recorded as real evidence.
 */
export async function runLiveDemo(args: LiveDemoArgs): Promise<number> {
  rmSync(LIVE_DIR, { recursive: true, force: true });
  mkdirSync(SANDBOX_DIR, { recursive: true });
  // A real record for the agent to read, and the thing `purge_records` would
  // destroy if the proxy ever let it through.
  seedRecord(SANDBOX_DIR, 'CASE-001', { caseId: 'CASE-001', subject: 'wire review', amount: 24000 });

  const keys = resolveKeyPair(KEY_PATH, {} as NodeJS.ProcessEnv);
  const spine = await Spine.open({ kind: 'sqlite', path: SQLITE_PATH }, keys, {
    checkpointInterval: 4,
  });
  const engine = PolicyV0Engine.fromDocument(LIVE_TOOLS_POLICY);
  const core = new ProxyCore(
    engine,
    new SpineEvidenceSink(spine),
    new EvidenceBuffer(join(LIVE_DIR, 'buffer.jsonl')),
  );

  // The proxy is the ONLY client of the real tools (spawned subprocess).
  const downstream = await connectDownstream({
    kind: 'stdio',
    command: process.execPath,
    args: [testToolsBin()],
    env: { ATTESTOR_SANDBOX_DIR: resolve(SANDBOX_DIR), PATH: process.env.PATH ?? '' },
  });
  const proxyHttp = await serveProxyHttp(core, downstream, {
    agentId: 'live-agent',
    port: PORT,
    host: '127.0.0.1',
  });

  console.log('\nAttestor live-demo — REAL MCP interception (not scripted).');
  console.log('  downstream tools : stdio subprocess (real file/compute side effects in a sandbox)');
  console.log(`  Attestor proxy   : Streamable HTTP on http://127.0.0.1:${PORT}/`);
  console.log('  agent            : a real MCP client wired ONLY to the proxy — it cannot reach the tools directly.\n');

  // The agent connects to the PROXY (never to the tools).
  const agent = new Client({ name: 'attestor-live-agent', version: '0.1.0' });
  await agent.connect(new StreamableHTTPClientTransport(new URL(proxyHttp.url)));

  let results: AgentResult[] = [];
  try {
    results = await runAgent(agent);
  } finally {
    await agent.close();
    await proxyHttp.stop();
    await downstream.close();
  }

  console.log('— Agent transcript (what the agent actually observed through the proxy) —\n');
  for (const [i, r] of results.entries()) {
    const verdict = r.blocked ? (LABEL[r.decision ?? 'deny'] ?? '⛔ BLOCKED ') : LABEL.allow;
    console.log(`  ${i + 1}. ${r.tool.padEnd(20)} ${verdict}  ${r.intent}`);
    console.log(`       ↳ ${r.text}`);
  }

  await spine.checkpoint();
  const [records, checkpoints, verification] = await Promise.all([
    spine.getAllRecords(),
    spine.getCheckpoints(),
    spine.verify(),
  ]);

  const dispositionWritten = existsSync(join(SANDBOX_DIR, 'dispositions', 'CASE-001.json'));
  const recordsIntact = existsSync(join(SANDBOX_DIR, 'records', 'CASE-001.json'));

  console.log('\n— Evidence (real, recorded in the spine) —');
  console.log(`  Evidence records:   ${records.length}  (the allowed T2 write produced 2: authorized + executed)`);
  console.log(`  Signed checkpoints: ${checkpoints.length}`);
  console.log(
    `  Allowed / Escalated / Denied: ${countDecision(records, 'allow')} / ${countDecision(records, 'escalate')} / ${countDecision(records, 'deny')}`,
  );
  console.log(`  Chain integrity:    ${verification.ok ? '✅ VERIFIED' : '❌ FAILED'}`);
  console.log(`  Latest signed root: ${checkpoints.at(-1)?.merkleRoot ?? '—'}`);
  console.log('\n— Real side effects (proof the boundary is real) —');
  console.log(`  disposition file written (allowed T2): ${dispositionWritten ? '✅ yes' : '❌ no'}`);
  console.log(`  case records intact (purge was DENIED): ${recordsIntact ? '✅ yes' : '❌ no — records were destroyed!'}`);
  console.log('');

  let ok = verification.ok && dispositionWritten && recordsIntact;
  if (args.anchor) {
    ok = (await anchorAndVerify(records, checkpoints)) && ok;
  }

  await spine.close();
  return ok ? 0 : 1;
}

/** Anchor the latest checkpoint to a real TSA and verify an exported bundle. */
async function anchorAndVerify(
  records: readonly EvidenceRecord[],
  checkpoints: readonly import('@attestor/types').Checkpoint[],
): Promise<boolean> {
  const latest = checkpoints.at(-1);
  if (!latest) {
    return true;
  }
  console.log('— External anchoring (RFC 3161 Trusted Timestamp) —');
  console.log(`  Submitting checkpoint #${latest.id} root to ${FREETSA.name} …`);
  const store = new AnchorStore(LIVE_DIR);
  const service = new AnchorService(store, new TsaClient(FREETSA, httpTransport(10_000)));
  const receipt = await service.anchor(latest);
  if (receipt.status === 'anchored') {
    console.log(`  ✅ anchored — TSA asserts time ${receipt.genTime}`);
  } else {
    console.log(`  ⚠️  TSA unreachable (${receipt.error}); checkpoint queued as a flagged gap.`);
  }
  const bundle = exportBundle({ records, checkpoints, anchors: store.all() });
  writeBundle(BUNDLE_PATH, bundle);
  console.log(`  Exported portable bundle: ${BUNDLE_PATH}`);
  const inclusionSeq = Math.max(1, Math.ceil(records.length / 2));
  console.log(`\nIndependent verification of the exported bundle (proving inclusion of record #${inclusionSeq}):`);
  const verification = await verifyAnchoredBundle(bundle, { seq: inclusionSeq });
  printAnchoredVerification(verification);
  // Chain + inclusion must hold; the external anchor may be a gap without egress.
  return verification.chain.ok && (verification.inclusion?.ok ?? false);
}
