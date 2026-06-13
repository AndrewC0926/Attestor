import { existsSync } from 'node:fs';
import { readBundle, verifyAnchoredBundle, type AnchoredVerification } from '@attestor/anchor';

export interface VerifyAnchoredArgs {
  readonly bundle: string;
  readonly seq?: number;
}

/** Print the three-part result of an independent bundle verification. */
export function printAnchoredVerification(v: AnchoredVerification): void {
  console.log('\n(1) Internal chain integrity (re-derived, no operator trust):');
  if (v.chain.ok) {
    console.log(
      `    ✅ VERIFIED — ${v.chain.recordsChecked} records, ${v.chain.checkpointsChecked} signed checkpoints, chain intact.`,
    );
  } else {
    console.log(`    ❌ FAILED — ${v.chain.failures.length} issue(s):`);
    for (const f of v.chain.failures) {
      console.log(`        • [${f.kind}] at ${f.at ?? '—'}: ${f.detail}`);
    }
  }

  console.log('\n(2) External RFC 3161 anchors (attested by an independent TSA):');
  if (v.anchors.length === 0) {
    console.log('    ⚠️  no anchors present in the bundle');
  }
  for (const a of v.anchors) {
    if (a.ok) {
      console.log(
        `    ✅ checkpoint #${a.checkpointId} (tree size ${a.treeSize}) anchored at ${a.genTime} by ${a.tsaSubject ?? a.tsaName}`,
      );
    } else {
      console.log(
        `    ❌ checkpoint #${a.checkpointId} (status: ${a.status}) — ${a.failures.join('; ')}`,
      );
    }
  }

  console.log('\n(3) Merkle inclusion in an anchored root:');
  if (!v.inclusion) {
    console.log('    (no record requested — pass --seq <n> to prove one)');
  } else if (v.inclusion.ok) {
    console.log(`    ✅ ${v.inclusion.detail}`);
  } else {
    console.log(`    ❌ ${v.inclusion.detail}`);
  }

  console.log(
    `\nIndependent verdict: ${v.ok ? '✅ the evidence is authentic and externally anchored' : '❌ verification FAILED'}\n`,
  );
}

/**
 * `attestor verify-anchored --bundle <path> [--seq <n>]` — verify an EXPORTED
 * bundle (records + signed roots + anchor receipts) with no live database and no
 * trust in the operator. Reuses the spine's verifier and the RFC 3161 validator.
 */
export async function runVerifyAnchored(args: VerifyAnchoredArgs): Promise<number> {
  if (!existsSync(args.bundle)) {
    console.error(`No bundle at ${args.bundle}.`);
    return 1;
  }
  const bundle = readBundle(args.bundle);
  console.log(
    `Verifying anchored bundle ${args.bundle} — ${bundle.records.length} records, ${bundle.checkpoints.length} checkpoints, ${bundle.anchors.length} anchor(s), exported ${bundle.exportedAt}.`,
  );
  const verification = await verifyAnchoredBundle(
    bundle,
    args.seq !== undefined ? { seq: args.seq } : {},
  );
  printAnchoredVerification(verification);
  return verification.ok ? 0 : 1;
}
