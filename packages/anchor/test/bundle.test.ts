import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceInput } from '@attestor/types';
import { Spine, resolveKeyPair } from '@attestor/spine';
import type { AnchorReceipt } from '../src/anchor-store.js';
import { exportBundle, readBundle, writeBundle, type AnchoredBundle } from '../src/bundle.js';
import { verifyAnchoredBundle } from '../src/verify-bundle.js';
import { createTestTsa, type TestTsa } from './test-tsa.js';

function input(n: number): EvidenceInput {
  return {
    agentId: 'agent-1',
    recordedAt: `2026-06-13T00:00:0${n}.000Z`,
    actionType: 'tool_call',
    actionName: `tool_${n}`,
    inputSha256: createHash('sha256').update(`in-${n}`).digest('hex'),
    outputSha256: createHash('sha256').update(`out-${n}`).digest('hex'),
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T1',
    decision: 'allow',
    policyId: 'rule.test',
    controls: ['A.6.2.4'],
    reason: 'test record',
    bufferedOffline: false,
  };
}

/** Build a real spine, append records, checkpoint, and anchor with the test TSA. */
async function buildAnchoredBundle(
  dir: string,
  tsa: TestTsa,
  count: number,
): Promise<AnchoredBundle> {
  const keys = resolveKeyPair(join(dir, 'key.json'), {} as NodeJS.ProcessEnv);
  const spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, keys);
  try {
    for (let i = 1; i <= count; i++) {
      await spine.append(input(i));
    }
    const checkpoint = await spine.checkpoint();
    const records = await spine.getAllRecords();
    const checkpoints = await spine.getCheckpoints();

    const token = await tsa.sign(
      Buffer.from(checkpoint.merkleRoot, 'hex'),
      new Date('2026-06-13T12:00:00.000Z'),
    );
    const receipt: AnchorReceipt = {
      checkpointId: checkpoint.id,
      treeSize: checkpoint.treeSize,
      merkleRoot: checkpoint.merkleRoot,
      checkpointCreatedAt: checkpoint.createdAt,
      tsaName: 'test-tsa',
      tsaUrl: 'memory://test-tsa',
      status: 'anchored',
      tokenBase64: token.toString('base64'),
      genTime: '2026-06-13T12:00:00.000Z',
      anchoredAt: '2026-06-13T12:00:01.000Z',
      error: null,
      attempts: 1,
    };
    return exportBundle({ records, checkpoints, anchors: [receipt], tsaCertsPem: [tsa.certPem] });
  } finally {
    await spine.close();
  }
}

describe('exported bundle — independent three-part verification', () => {
  let dir: string;
  let tsa: TestTsa;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-bundle-'));
    tsa = await createTestTsa();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('verifies chain, anchor, and inclusion on a bundle with no live DB', async () => {
    const bundle = await buildAnchoredBundle(dir, tsa, 5);
    // Round-trip through disk to prove it is self-contained.
    const path = join(dir, 'bundle.json');
    writeBundle(path, bundle);
    const loaded = readBundle(path);

    const result = await verifyAnchoredBundle(loaded, { seq: 3 });
    expect(result.chain.ok).toBe(true);
    expect(result.anchors).toHaveLength(1);
    expect(result.anchors[0]?.ok).toBe(true);
    expect(result.anchors[0]?.genTime).toBe('2026-06-13T12:00:00.000Z');
    expect(result.anchors[0]?.tsaSubject).toContain('Attestor Test TSA');
    expect(result.inclusion?.ok).toBe(true);
    expect(result.inclusion?.checkpointId).toBe(1);
    expect(result.ok).toBe(true);
  });

  it('fails chain verification when a record is altered in the bundle', async () => {
    const bundle = await buildAnchoredBundle(dir, tsa, 4);
    const tampered: AnchoredBundle = structuredClone(bundle);
    // Flip a character of record #2's stored hash.
    const r = tampered.records[1] as { recordHash: string };
    r.recordHash = (r.recordHash[0] === '0' ? '1' : '0') + r.recordHash.slice(1);

    const result = await verifyAnchoredBundle(tampered, { seq: 2 });
    expect(result.chain.ok).toBe(false);
    expect(result.ok).toBe(false);
  });

  it('fails the anchor check when the token does not match the checkpoint root', async () => {
    const bundle = await buildAnchoredBundle(dir, tsa, 3);
    const tampered: AnchoredBundle = structuredClone(bundle);
    // Replace the token with one over a DIFFERENT digest.
    const wrongToken = await tsa.sign(createHash('sha256').update('not-the-root').digest());
    (tampered.anchors[0] as { tokenBase64: string }).tokenBase64 = wrongToken.toString('base64');

    const result = await verifyAnchoredBundle(tampered);
    expect(result.chain.ok).toBe(true); // chain itself is untouched
    expect(result.anchors[0]?.ok).toBe(false);
    expect(result.anchors[0]?.failures.join(' ')).toContain('messageImprint');
    expect(result.ok).toBe(false);
  });

  it('reports inclusion failure when no anchored checkpoint covers the record', async () => {
    const bundle = await buildAnchoredBundle(dir, tsa, 3);
    const result = await verifyAnchoredBundle(bundle, { seq: 99 });
    expect(result.inclusion?.ok).toBe(false);
    expect(result.ok).toBe(false);
  });
});
