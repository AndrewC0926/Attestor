import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceInput } from '@attestor/types';
import { Spine, resolveKeyPair } from '@attestor/spine';
import type { CliConfig } from '../src/config.js';
import { runVerify } from '../src/commands/verify.js';
import { runAttest } from '../src/commands/attest.js';
import { runDemo } from '../src/commands/demo.js';

function input(name: string, decision: EvidenceInput['decision'] = 'allow'): EvidenceInput {
  return {
    agentId: 'agent',
    recordedAt: '2026-01-01T00:00:00.000Z',
    actionType: 'tool_call',
    actionName: name,
    inputSha256: 'a'.repeat(64),
    outputSha256: 'b'.repeat(64),
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T1',
    decision,
    policyId: 'rule.read.t1',
    controls: ['A.6.2.4'],
    reason: 'read',
    bufferedOffline: false,
  };
}

describe('CLI commands (integration)', () => {
  let dir: string;
  let config: CliConfig;
  let dbPath: string;

  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    dir = mkdtempSync(join(tmpdir(), 'attestor-cli-'));
    dbPath = join(dir, 'evidence.sqlite');
    config = {
      store: { kind: 'sqlite', path: dbPath },
      keyFilePath: join(dir, 'signing-key.json'),
      policyPath: 'policies/v0.yaml',
      controlsPath: 'data/iso42001-controls.json',
      bufferPath: join(dir, 'buffer.jsonl'),
    };
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function seed(): Promise<void> {
    const spine = await Spine.open(config.store, resolveKeyPair(config.keyFilePath));
    await spine.append(input('fs.read'));
    await spine.append(input('db.query'));
    await spine.append(input('payments.transfer', 'deny'));
    await spine.checkpoint();
    await spine.close();
  }

  it('verify returns 0 for an intact log', async () => {
    await seed();
    expect(await runVerify(config, {})).toBe(0);
  });

  it('verify --seq proves a single record', async () => {
    await seed();
    expect(await runVerify(config, { seq: 2 })).toBe(0);
  });

  it('attest writes a Markdown and JSON report and returns 0', async () => {
    await seed();
    const out = join(dir, 'report');
    expect(await runAttest(config, { out })).toBe(0);
    expect(existsSync(`${out}.md`)).toBe(true);
    expect(existsSync(`${out}.json`)).toBe(true);
  });

  it('verify returns 1 after an out-of-band tamper', async () => {
    await seed();
    const raw = new Database(dbPath);
    raw.exec('DROP TRIGGER evidence_record_no_update');
    raw.prepare("UPDATE evidence_record SET decision='allow' WHERE seq=3").run();
    raw.close();
    expect(await runVerify(config, {})).toBe(1);
  });

  it('demo runs the full scenario and verifies clean', async () => {
    expect(await runDemo(config)).toBe(0);
  });
});
