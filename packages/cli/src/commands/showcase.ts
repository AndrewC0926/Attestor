import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Spine, resolveKeyPair } from '@attestor/spine';
import type { EvidenceRecord, PolicyDecision, VerificationResult } from '@attestor/types';
import {
  createShowcaseHarness,
  projectReplay,
  flipEvidenceByte,
  restoreEvidenceByte,
  getScenario,
  SCENARIO_IDS,
  DEFAULT_SCENARIO_ID,
  SHOWCASE_DIR,
  type Scenario,
} from '@attestor/showcase';
import type { Checkpoint } from '@attestor/types';
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
import type { CliConfig } from '../config.js';
import { loadControlCatalog } from '../controls.js';
import { buildReport } from '../report/build.js';
import { renderMarkdown } from '../report/markdown.js';
import { renderJson } from '../report/json.js';
import { printAnchoredVerification } from './verify-anchored.js';

export interface ShowcaseArgs {
  /** Scenario id (default: support-desk). */
  readonly scenario?: string;
  /** When set, reconstruct the run from the existing evidence instead of running. */
  readonly replay?: boolean;
  /** When set, run the scenario then the built-in on-screen tamper proof. */
  readonly proveTamper?: boolean;
  /** When set, anchor the latest checkpoint to a TSA and verify an exported bundle. */
  readonly anchor?: boolean;
}

const BUNDLE_PATH = join(SHOWCASE_DIR, 'bundle.json');

interface CallResult {
  isError?: boolean;
}

const DECISION_LABEL: Record<PolicyDecision, string> = {
  allow: '✅ ALLOW   ',
  escalate: '⚠️  ESCALATE',
  deny: '⛔ DENY    ',
};

const SQLITE_PATH = join(SHOWCASE_DIR, 'evidence.sqlite');
const KEY_PATH = join(SHOWCASE_DIR, 'signing-key.json');

function countDecision(records: readonly EvidenceRecord[], decision: PolicyDecision): number {
  return records.filter((r) => r.decision === decision).length;
}

/** `attestor showcase [--scenario <id>] [--replay] [--prove-tamper]`. */
export async function runShowcase(config: CliConfig, args: ShowcaseArgs): Promise<number> {
  if (args.replay) {
    return runReplay();
  }

  const scenarioId = args.scenario ?? DEFAULT_SCENARIO_ID;
  const scenario = getScenario(scenarioId);
  if (!scenario) {
    console.error(`Unknown scenario '${scenarioId}'. Available: ${SCENARIO_IDS.join(', ')}.`);
    return 1;
  }

  const runOk = await runScenario(config, scenario, { anchor: args.anchor === true });
  if (!args.proveTamper) {
    return runOk ? 0 : 1;
  }
  const proofOk = await proveTamper();
  return runOk && proofOk ? 0 : 1;
}

/** Drive a scenario live through the gateway, write the report, print summary. */
async function runScenario(
  config: CliConfig,
  scenario: Scenario,
  opts: { anchor: boolean },
): Promise<boolean> {
  const harness = await createShowcaseHarness(scenario, SHOWCASE_DIR);
  const { agent, spine } = harness;

  console.log(`\nAttestor showcase — ${scenario.title}`);
  console.log(scenario.intro);
  console.log('Each action below flows through the Attestor gateway and is recorded as signed evidence:\n');

  for (const [i, step] of scenario.steps.entries()) {
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
      `  ${String(i + 1).padStart(2)}. ${step.tool.padEnd(24)} ${record.riskTier}  ${label}  → evidence #${record.seq} (${record.recordHash.slice(0, 12)}…)`,
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
  console.log(`  Scenario:           ${scenario.id}`);
  console.log(`  Evidence records:   ${records.length}`);
  console.log(`  Signed checkpoints: ${checkpoints.length}`);
  console.log(
    `  Allowed / Escalated / Denied: ${countDecision(records, 'allow')} / ${countDecision(records, 'escalate')} / ${countDecision(records, 'deny')}`,
  );
  console.log(`  Chain integrity:    ${verification.ok ? '✅ VERIFIED' : '❌ FAILED'}`);
  console.log(`  Latest signed root: ${checkpoints.at(-1)?.merkleRoot ?? '—'}`);
  console.log(`  Attestation report: ${reportPrefix}.md (+ .json)\n`);

  if (opts.anchor) {
    await anchorAndVerify(records, checkpoints);
  }

  console.log('Reconstruct it from the evidence alone:');
  console.log('  attestor showcase --replay');
  console.log('Prove it is tamper-evident, live:');
  console.log(`  attestor showcase --scenario ${scenario.id} --prove-tamper\n`);

  await harness.close();
  return verification.ok;
}

/**
 * Anchor the latest checkpoint to a real RFC 3161 TSA, export a portable bundle,
 * and run the independent three-part verification on that BUNDLE (not the live
 * store). If the TSA is unreachable, the checkpoint is preserved as a flagged
 * gap (graceful degradation) and the bundle still verifies chain + inclusion.
 */
async function anchorAndVerify(
  records: readonly EvidenceRecord[],
  checkpoints: readonly Checkpoint[],
): Promise<void> {
  const latest = checkpoints.at(-1);
  if (!latest) {
    return;
  }

  console.log('— External anchoring (RFC 3161 Trusted Timestamp) —');
  console.log(`  Submitting checkpoint #${latest.id} root to ${FREETSA.name} …`);

  const store = new AnchorStore(SHOWCASE_DIR);
  const service = new AnchorService(store, new TsaClient(FREETSA, httpTransport(10_000)));
  const receipt = await service.anchor(latest);
  if (receipt.status === 'anchored') {
    console.log(`  ✅ anchored — TSA asserts time ${receipt.genTime}`);
  } else {
    console.log(`  ⚠️  TSA unreachable (${receipt.error}); checkpoint queued as a flagged gap.`);
    console.log('     (Re-run with network egress to anchor; the checkpoint is never lost.)');
  }

  const bundle = exportBundle({
    records,
    checkpoints,
    anchors: store.all(),
    tsaCertsPem: service.trustedCertsPem(),
  });
  writeBundle(BUNDLE_PATH, bundle);
  console.log(`  Exported portable bundle: ${BUNDLE_PATH}`);

  const inclusionSeq = Math.max(1, Math.ceil(records.length / 2));
  console.log(
    `\nIndependent verification of the exported bundle (no live DB, proving inclusion of record #${inclusionSeq}):`,
  );
  const verification = await verifyAnchoredBundle(bundle, { seq: inclusionSeq });
  printAnchoredVerification(verification);
}

/**
 * Open the showcase store and run the REAL spine.verify(), printing a labelled
 * result. Every verify display in the tamper proof goes through here, so no
 * verification logic is re-implemented.
 */
async function verifyShowcase(label: string): Promise<VerificationResult> {
  const keys = resolveKeyPair(KEY_PATH, {} as NodeJS.ProcessEnv);
  const spine = await Spine.open({ kind: 'sqlite', path: SQLITE_PATH }, keys);
  try {
    const result = await spine.verify();
    if (result.ok) {
      console.log(
        `  ${label}: ✅ VERIFIED — ${result.recordsChecked} records, ${result.checkpointsChecked} signed checkpoints, chain intact.`,
      );
    } else {
      console.log(`  ${label}: ❌ FAILED — ${result.failures.length} issue(s) detected:`);
      for (const f of result.failures) {
        console.log(`        • [${f.kind}] at ${f.at ?? '—'}: ${f.detail}`);
      }
    }
    return result;
  } finally {
    await spine.close();
  }
}

/**
 * The built-in tamper proof: verify (pass) → flip one byte out of band → verify
 * (fail, naming the record) → restore the byte → verify (pass). Operates only on
 * the isolated showcase store. Returns true iff the cycle behaved as expected.
 */
async function proveTamper(): Promise<boolean> {
  console.log('— Built-in tamper proof (live, no hand-typed commands) —\n');

  const v1 = await verifyShowcase('1) verify on fresh evidence      ');
  const middle = Math.max(1, Math.ceil(v1.recordsChecked / 2));

  const flipped = flipEvidenceByte(SQLITE_PATH, middle);
  console.log(
    `  2) tamper: flipped exactly 1 byte of evidence #${flipped.seq} (${flipped.action}) — ` +
      `input_sha256 ${flipped.before.slice(0, 8)}… → ${flipped.after.slice(0, 8)}…`,
  );

  const v2 = await verifyShowcase('3) verify after tamper           ');

  const restored = restoreEvidenceByte(SQLITE_PATH, middle);
  console.log(`  4) restore: reverted the byte of evidence #${restored.seq} (XOR is its own inverse)`);

  const v3 = await verifyShowcase('5) verify after restore          ');
  console.log('');

  const asExpected = v1.ok && !v2.ok && v3.ok;
  if (asExpected) {
    console.log('Tamper proof complete: detection works, and the restored log verifies again.\n');
  } else {
    console.error('Tamper proof did NOT behave as expected (see steps above).\n');
  }
  return asExpected;
}

/** Reconstruct the ordered account purely from the showcase evidence store. */
async function runReplay(): Promise<number> {
  if (!existsSync(SQLITE_PATH)) {
    console.error(`No showcase evidence at ${SQLITE_PATH}. Run 'attestor showcase' first.`);
    return 1;
  }

  const keys = resolveKeyPair(KEY_PATH, {} as NodeJS.ProcessEnv);
  const spine = await Spine.open({ kind: 'sqlite', path: SQLITE_PATH }, keys);
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
