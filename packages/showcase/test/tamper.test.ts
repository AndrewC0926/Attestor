import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Spine, resolveKeyPair } from '@attestor/spine';
import { createShowcaseHarness } from '../src/harness.js';
import { supportDeskScenario } from '../src/scenarios/support-desk.js';
import { flipEvidenceByte, restoreEvidenceByte } from '../src/tamper.js';

/**
 * Proves the built-in tamper helpers do exactly what `--prove-tamper` shows:
 * a one-byte out-of-band edit is detected by the REAL spine.verify(), and the
 * restore (its own inverse) clears the failure. Verification is the spine's —
 * the helpers only mutate storage.
 */
describe('built-in tamper proof helpers', () => {
  let dir: string;
  let sqlitePath: string;
  let keyPath: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-tamper-'));
    sqlitePath = join(dir, 'evidence.sqlite');
    keyPath = join(dir, 'signing-key.json');
    const harness = await createShowcaseHarness(supportDeskScenario, dir);
    try {
      for (const step of supportDeskScenario.steps) {
        try {
          await harness.agent.callTool({ name: step.tool, arguments: step.arguments });
        } catch {
          /* blocked */
        }
      }
      await harness.spine.checkpoint();
    } finally {
      await harness.close();
    }
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function verify(): Promise<ReturnType<Spine['verify']>> {
    const spine = await Spine.open(
      { kind: 'sqlite', path: sqlitePath },
      resolveKeyPair(keyPath, {} as NodeJS.ProcessEnv),
    );
    try {
      return await spine.verify();
    } finally {
      await spine.close();
    }
  }

  it('verifies fresh, detects a one-byte flip, then verifies again after restore', async () => {
    expect((await verify()).ok).toBe(true);

    const flipped = flipEvidenceByte(sqlitePath, 3);
    expect(flipped.seq).toBe(3);
    expect(flipped.after).not.toBe(flipped.before);
    expect(flipped.after).toHaveLength(flipped.before.length); // exactly one nibble changed

    const tampered = await verify();
    expect(tampered.ok).toBe(false);
    expect(tampered.failures).toEqual([
      expect.objectContaining({ kind: 'record_hash_mismatch', at: 3 }),
    ]);

    const restored = restoreEvidenceByte(sqlitePath, 3);
    expect(restored.after).toBe(flipped.before); // round-trips to the original byte
    expect((await verify()).ok).toBe(true);
  });
});
