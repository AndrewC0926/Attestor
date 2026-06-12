import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { openSpine, type CliConfig } from '../config.js';
import { loadControlCatalog } from '../controls.js';
import { buildReport } from '../report/build.js';
import { renderMarkdown } from '../report/markdown.js';
import { renderJson } from '../report/json.js';

export interface AttestArgs {
  readonly from?: string;
  readonly to?: string;
  /** Output path prefix; writes `<out>.md` and `<out>.json`. Prints to stdout if absent. */
  readonly out?: string;
}

/** `attestor attest` — compile a time-range of evidence into a compliance report. */
export async function runAttest(config: CliConfig, args: AttestArgs): Promise<number> {
  const spine = await openSpine(config);
  try {
    const [records, checkpoints, verification] = await Promise.all([
      spine.getAllRecords(),
      spine.getCheckpoints(),
      spine.verify(),
    ]);
    const catalog = loadControlCatalog(config.controlsPath);
    const report = buildReport({
      records,
      checkpoints,
      verification,
      catalog,
      from: args.from ?? null,
      to: args.to ?? null,
      generatedAt: new Date().toISOString(),
    });

    const markdown = renderMarkdown(report);
    const json = renderJson(report);

    if (args.out) {
      mkdirSync(dirname(args.out) || '.', { recursive: true });
      writeFileSync(`${args.out}.md`, markdown, 'utf8');
      writeFileSync(`${args.out}.json`, json, 'utf8');
      console.log(`Wrote ${args.out}.md and ${args.out}.json`);
      console.log(
        `Integrity: ${verification.ok ? 'VERIFIED' : 'FAILED'} • ${report.totals.records} records in range.`,
      );
    } else {
      console.log(markdown);
    }

    // A report over a tampered log is still produced, but exits non-zero for CI.
    return verification.ok ? 0 : 1;
  } finally {
    await spine.close();
  }
}
