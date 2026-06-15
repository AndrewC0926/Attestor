import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Spine, resolveKeyPair, verifyLog } from '@attestor/spine';
import { PolicyV0Engine, SpineEvidenceSink } from '@attestor/gateway';
import { ProxyCore, buildProxyServer } from '@attestor/proxy';
import { createTestToolsServer, seedRecord, LIVE_TOOLS_POLICY } from '@attestor/test-tools';
import { runAgent } from '@attestor/test-agent';

/**
 * The whole real-traffic stack over real MCP (InMemoryTransport is the genuine
 * MCP protocol, just in-process): agent → Attestor proxy → real downstream
 * tools. The agent is handed ONLY the proxy transport, so it cannot reach the
 * tools directly. Deterministic — no subprocess/HTTP — but exercises the same
 * decide→record→forward path the live HTTP demo uses.
 */
describe('live MCP interception, end-to-end', () => {
  let dir: string;
  let sandbox: string;
  let spine: Spine;
  let agent: Client;
  let downstream: Client;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-live-'));
    sandbox = join(dir, 'sandbox');
    seedRecord(sandbox, 'CASE-001', { caseId: 'CASE-001', amount: 24000 });

    const keys = resolveKeyPair(join(dir, 'key.json'), {} as NodeJS.ProcessEnv);
    spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, keys);
    const core = new ProxyCore(
      PolicyV0Engine.fromDocument(LIVE_TOOLS_POLICY),
      new SpineEvidenceSink(spine),
    );

    // real tools  <- (MCP) -  proxy's downstream client
    const [toolSide, downSide] = InMemoryTransport.createLinkedPair();
    const tools = createTestToolsServer(sandbox);
    await tools.connect(toolSide);
    downstream = new Client({ name: 'down', version: '0.1.0' });
    await downstream.connect(downSide);

    // proxy server  <- (MCP) -  agent (the agent's ONLY connection)
    const proxy = buildProxyServer(core, downstream, { agentId: 'live-agent' });
    const [proxySide, agentSide] = InMemoryTransport.createLinkedPair();
    await proxy.connect(proxySide);
    agent = new Client({ name: 'live-agent', version: '0.1.0' });
    await agent.connect(agentSide);
  });

  afterEach(async () => {
    await agent.close();
    await downstream.close();
    await spine.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('intercepts real calls: allow/escalate/deny, real side effects, verifiable evidence', async () => {
    const results = await runAgent(agent);

    // The agent observed the real governance outcomes through the proxy.
    expect(results.map((r) => `${r.tool}:${r.blocked ? r.decision ?? 'blocked' : 'allowed'}`)).toEqual([
      'read_record:allowed',
      'compute_risk_score:allowed',
      'write_disposition:allowed',
      'export_case_file:escalate',
      'purge_records:deny',
    ]);
    // Allowed calls really happened; blocked calls did not.
    expect(results[0]?.text).toContain('[REAL] read record CASE-001');
    expect(existsSync(join(sandbox, 'dispositions', 'CASE-001.json'))).toBe(true); // T2 write happened
    expect(existsSync(join(sandbox, 'records', 'CASE-001.json'))).toBe(true); // purge was DENIED
    expect(existsSync(join(sandbox, 'exports', 'CASE-001.json'))).toBe(false); // export was ESCALATED

    // The evidence the live path produced passes the SAME checks as the showcase.
    const checkpoint = await spine.checkpoint();
    const [records, checkpoints] = await Promise.all([
      spine.getAllRecords(),
      spine.getCheckpoints(),
    ]);
    // read(1) + compute(1) + write authorized+executed(2) + escalate(1) + deny(1) = 6
    expect(records).toHaveLength(6);
    expect(verifyLog(records, checkpoints).ok).toBe(true);
    expect(await spine.verifyInclusion(checkpoint.treeSize)).toBe(true);
    expect((await spine.verify()).ok).toBe(true);
  });
});
