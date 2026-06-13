#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolveConfig } from './config.js';
import { runVerify } from './commands/verify.js';
import { runAttest, type AttestArgs } from './commands/attest.js';
import { runDemo } from './commands/demo.js';
import { runShowcase } from './commands/showcase.js';

const HELP = `attestor — audit gateway evidence CLI

Usage:
  attestor verify [--seq <n>]            Prove the evidence log is intact
                                         (--seq verifies one record in O(log n))
  attestor attest [--from <iso>] [--to <iso>] [--out <prefix>]
                                         Compile a compliance report (Markdown + JSON)
  attestor demo                          Run the end-to-end demo scenario
  attestor showcase [--scenario <id>] [--replay] [--prove-tamper]
                                         Run a governance showcase. Scenarios:
                                         support-desk (default), finance.
                                         --replay reconstructs from the evidence;
                                         --prove-tamper runs the live tamper proof.
  attestor help                          Show this help

Environment:
  ATTESTOR_DATABASE_URL   Postgres connection string (else SQLite)
  ATTESTOR_SQLITE_PATH    SQLite path (default .attestor/evidence.sqlite)
  ATTESTOR_KEY_FILE       Signing key file (default .attestor/signing-key.json)
  ATTESTOR_POLICY_FILE    Policy file (default policies/v0.yaml)
  ATTESTOR_CONTROLS_FILE  Control map (default data/iso42001-controls.json)
`;

async function main(): Promise<number> {
  const [, , command, ...rest] = process.argv;
  const config = resolveConfig();

  switch (command) {
    case 'verify': {
      const { values } = parseArgs({
        args: rest,
        options: { seq: { type: 'string' } },
      });
      return runVerify(config, values.seq !== undefined ? { seq: Number(values.seq) } : {});
    }
    case 'attest': {
      const { values } = parseArgs({
        args: rest,
        options: {
          from: { type: 'string' },
          to: { type: 'string' },
          out: { type: 'string' },
        },
      });
      const args: AttestArgs = {
        ...(values.from ? { from: values.from } : {}),
        ...(values.to ? { to: values.to } : {}),
        ...(values.out ? { out: values.out } : {}),
      };
      return runAttest(config, args);
    }
    case 'demo':
      return runDemo(config);
    case 'showcase': {
      const { values } = parseArgs({
        args: rest,
        options: {
          scenario: { type: 'string' },
          replay: { type: 'boolean' },
          'prove-tamper': { type: 'boolean' },
        },
      });
      return runShowcase(config, {
        ...(values.scenario ? { scenario: values.scenario } : {}),
        ...(values.replay ? { replay: true } : {}),
        ...(values['prove-tamper'] ? { proveTamper: true } : {}),
      });
    }
    case 'help':
    case undefined:
      console.log(HELP);
      return 0;
    default:
      console.error(`Unknown command: ${command}\n`);
      console.log(HELP);
      return 1;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
