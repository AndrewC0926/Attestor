import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Spine, resolveKeyPair } from '@attestor/spine';
import {
  EvidenceBuffer,
  GatewayCore,
  SpineEvidenceSink,
  buildAuditedServer,
} from '@attestor/gateway';
import { createSupportDeskServer } from './tools.js';
import { SupportDeskPolicyEngine } from './policy.js';

/** Default directory for the showcase's isolated evidence store. */
export const SHOWCASE_DIR = '.attestor/showcase';

/** Identity attributed to the agent in every showcase evidence record. */
export const SHOWCASE_AGENT_ID = 'support-desk-agent';

/** A wired, ready-to-drive showcase: an MCP agent client and its spine. */
export interface ShowcaseHarness {
  readonly agent: Client;
  readonly spine: Spine;
  /** Tear down all transports, clients, and the spine. */
  close(): Promise<void>;
}

/**
 * Wire agent ⇄ Attestor gateway ⇄ support-desk tools, all in-process over MCP,
 * exactly as the product demo does — but with the support-desk tool server and
 * the argument-aware showcase policy engine. Writes to an isolated SQLite store
 * so it never collides with `attestor demo`.
 *
 * This function performs NO console output (the spine core forbids it); the CLI
 * command drives the returned agent and prints the live decisions.
 */
export async function createShowcaseHarness(
  dir: string = SHOWCASE_DIR,
): Promise<ShowcaseHarness> {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  const keys = resolveKeyPair(join(dir, 'signing-key.json'), {} as NodeJS.ProcessEnv);
  const spine = await Spine.open(
    { kind: 'sqlite', path: join(dir, 'evidence.sqlite') },
    keys,
    { checkpointInterval: 4 },
  );
  const core = new GatewayCore(
    new SupportDeskPolicyEngine(),
    new SpineEvidenceSink(spine),
    new EvidenceBuffer(join(dir, 'buffer.jsonl')),
  );

  const [agentSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  const [downClientSide, toolSide] = InMemoryTransport.createLinkedPair();

  const tools = createSupportDeskServer();
  await tools.connect(toolSide);
  const downstreamClient = new Client({ name: 'showcase-downstream', version: '0.1.0' });
  await downstreamClient.connect(downClientSide);

  const gateway = buildAuditedServer(core, downstreamClient, {
    agentId: SHOWCASE_AGENT_ID,
  });
  await gateway.connect(gatewaySide);
  const agent = new Client({ name: 'support-desk-agent-client', version: '0.1.0' });
  await agent.connect(agentSide);

  return {
    agent,
    spine,
    async close(): Promise<void> {
      await agent.close();
      await gateway.close();
      await downstreamClient.close();
      await tools.close();
      await spine.close();
    },
  };
}
