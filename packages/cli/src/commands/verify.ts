import { openSpine, type CliConfig } from '../config.js';

export interface VerifyArgs {
  /** When set, verify a single record's inclusion proof in O(log n). */
  readonly seq?: number;
}

/** `attestor verify` — prove the integrity of the evidence log. */
export async function runVerify(config: CliConfig, args: VerifyArgs): Promise<number> {
  const spine = await openSpine(config);
  try {
    if (args.seq !== undefined) {
      const ok = await spine.verifyInclusion(args.seq);
      if (ok) {
        console.log(`✅ Record #${args.seq} is included in the signed log (proof verified).`);
        return 0;
      }
      console.error(`❌ Record #${args.seq} failed inclusion verification.`);
      return 1;
    }

    const result = await spine.verify();
    if (result.ok) {
      console.log(
        `✅ Evidence log VERIFIED — ${result.recordsChecked} records, ${result.checkpointsChecked} signed checkpoints, chain intact.`,
      );
      return 0;
    }

    console.error(
      `❌ Evidence log FAILED verification — ${result.failures.length} issue(s) detected:`,
    );
    for (const failure of result.failures) {
      console.error(`   • [${failure.kind}] at ${failure.at ?? '—'}: ${failure.detail}`);
    }
    return 1;
  } finally {
    await spine.close();
  }
}
