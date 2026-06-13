import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Spine, resolveKeyPair } from '@attestor/spine';
import type { EvidenceRecord, PolicyDecision } from '@attestor/types';
import {
  createShowcaseHarness,
  projectReplay,
  SHOWCASE_DIR,
  SHOWCASE_STEPS,
  SHOWCASE_TICKET,
} from '@attestor/showcase';
import type { CliConfig } from '../config.js';
import { loadControlCatalog } from '../controls.js';
import { buildReport } from '../report/build.js';
import { renderMarkdown } from '../report/markdown.js';
import { renderJson } from '../report/json.js';

export interface ShowcaseArgs {
  /** When set, reconstruct the run from the existing evidence instead of running. */
  readonly replay?: boolean;
}

interface CallResult {
  isError?: boolean;
}

const DECISION_LABEL: Record<PolicyDecision, string> = {
  allow: '✅ ALLOW   ',
  escalate: '⚠️  ESCALATE',
  deny: '⛔ DENY    ',
};

function countDecision(records: readonly EvidenceRecord[], decision: PolicyDecision): number {
  return records.filter((r) => r.decision === decision).length;
}

/** `attestor showcase [--replay]` — the support-desk governance showcase. */
export async function runShowcase(config: CliConfig, args: ShowcaseArgs): Promise<number> {
  if (args.replay) {
    return runReplay();
  }

  const harness = await createShowcaseHarness(SHOWCASE_DIR);
  const { agent, spine } = harness;

  console.log(
    `\nAttestor showcase — "support-desk-agent" works ticket ${SHOWCASE_TICKET.id} for ${SHOWCASE_TICKET.customerName} (“${SHOWCASE_TICKET.subject}”).`,
  );
  console.log('Every tool is SIMULATED — no real customer data, no real money moves.');
  console.log('Each action below flows through the Attestor gateway and is recorded as signed evidence:\n');

  for (const [i, step] of SHOWCASE_STEPS.entries()) {
    try {
      (await agent.callTool({ name: step.tool, arguments: step.arguments })) as CallResult;
    } catch {
      // Denied/escalated calls surface as tool errors; the evidence is still written.
    }
    const seq = await spine.count();
    const record = await spine.getRecord(seq);
    if (!record) {
      console.error(`  ${String(i + 1).padStart(2)}. ${step.tool}: no evidence record produced`);
      continue;
    }
    const label = DECISION_LABEL[record.decision];
    console.log(
      `  ${String(i + 1).padStart(2)}. ${step.tool.padEnd(22)} ${record.riskTier}  ${label}  → evidence #${record.seq} (${record.recordHash.slice(0, 12)}…)`,
    );
    console.log(`      ${step.narrative}`);
    console.log(`      ↳ ${record.reason}`);
  }

  await spine.checkpoint();

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
  const reportPrefix = join(SHOWCASE_DIR, 'attestation');
  writeFileSync(`${reportPrefix}.md`, renderMarkdown(report), 'utf8');
  writeFileSync(`${reportPrefix}.json`, renderJson(report), 'utf8');

  console.log('\n— Governance summary —');
  console.log(`  Evidence records:   ${records.length}`);
  console.log(`  Signed checkpoints: ${checkpoints.length}`);
  console.log(
    `  Allowed / Escalated / Denied: ${countDecision(records, 'allow')} / ${countDecision(records, 'escalate')} / ${countDecision(records, 'deny')}`,
  );
  console.log(`  Chain integrity:    ${verification.ok ? '✅ VERIFIED' : '❌ FAILED'}`);
  console.log(`  Latest signed root: ${checkpoints.at(-1)?.merkleRoot ?? '—'}`);
  console.log(`  Attestation report: ${reportPrefix}.md (+ .json)\n`);

  console.log('Reconstruct it from the evidence alone:');
  console.log('  attestor showcase --replay');
  console.log('Prove it is tamper-evident (flip one byte → verify fails → restore):');
  console.log('  see SHOWCASE.md\n');

  await harness.close();
  return verification.ok ? 0 : 1;
}

/** Reconstruct the ordered account purely from the showcase evidence store. */
async function runReplay(): Promise<number> {
  const sqlitePath = join(SHOWCASE_DIR, 'evidence.sqlite');
  if (!existsSync(sqlitePath)) {
    console.error(`No showcase evidence at ${sqlitePath}. Run 'attestor showcase' first.`);
    return 1;
  }

  const keys = resolveKeyPair(join(SHOWCASE_DIR, 'signing-key.json'), {} as NodeJS.ProcessEnv);
  const spine = await Spine.open({ kind: 'sqlite', path: sqlitePath }, keys);
  try {
    const [records, verification] = await Promise.all([
      spine.getAllRecords(),
      spine.verify(),
    ]);

    console.log(
      `\nAttestor showcase — replay reconstructed from the evidence alone (${records.length} records).`,
    );
    console.log(
      `Integrity: ${verification.ok ? '✅ VERIFIED (hash chain intact, checkpoints signed)' : '❌ FAILED — evidence has been altered'}\n`,
    );

    for (const e of projectReplay(records)) {
      console.log(`  #${e.seq}  ${e.recordedAt}  ${e.actionName}  [${e.riskTier} / ${e.decision}]`);
      console.log(`        reason : ${e.reason}`);
      console.log(
        `        input  : sha256:${e.inputSha256.slice(0, 16)}…${e.capturedInput ? `   capture: ${e.capturedInput}` : ''}`,
      );
      console.log(`        record : ${e.recordHash.slice(0, 16)}…`);
    }
    console.log('');
    return verification.ok ? 0 : 1;
  } finally {
    await spine.close();
  }
}
