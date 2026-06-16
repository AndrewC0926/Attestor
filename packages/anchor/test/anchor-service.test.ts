import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Checkpoint } from '@attestor/types';
import { AnchorStore } from '../src/anchor-store.js';
import { AnchorService } from '../src/anchor-service.js';
import { TsaClient, type TsaTransport } from '../src/tsa-client.js';
import { createTestTsa, grantedResponse, type TestTsa } from './test-tsa.js';

function checkpoint(id: number, root: Buffer): Checkpoint {
  return {
    id,
    treeSize: id * 4,
    merkleRoot: root.toString('hex'),
    createdAt: '2026-06-13T12:00:00.000Z',
    signature: 'aa',
    publicKey: 'bb',
  };
}

describe('AnchorService', () => {
  let dir: string;
  let tsa: TestTsa;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-anchor-svc-'));
    tsa = await createTestTsa();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('anchors a checkpoint and persists a verifiable receipt', async () => {
    const root = createHash('sha256').update('root-1').digest();
    const cp = checkpoint(1, root);
    // Transport mints a token over the digest in the request.
    const transport: TsaTransport = async (_url, _req) => ({
      status: 200,
      body: grantedResponse(await tsa.sign(root, new Date('2026-06-13T12:00:00.000Z'))),
    });
    const store = new AnchorStore(dir);
    const service = new AnchorService(store, new TsaClient({ url: 'x', name: 'test' }, transport));

    const receipt = await service.anchor(cp);
    expect(receipt.status).toBe('anchored');
    expect(receipt.tokenBase64).not.toBeNull();
    expect(receipt.genTime).toBe('2026-06-13T12:00:00.000Z');

    // Durable: a fresh store sees the anchored receipt.
    expect(new AnchorStore(dir).get(1)?.status).toBe('anchored');
  });

  it('never loses a checkpoint when the TSA is unreachable — it queues a flagged gap', async () => {
    const cp = checkpoint(7, createHash('sha256').update('root-7').digest());
    const failing: TsaTransport = async () => {
      throw new Error('network down');
    };
    const store = new AnchorStore(dir);
    const service = new AnchorService(store, new TsaClient({ url: 'x', name: 'test' }, failing));

    const receipt = await service.anchor(cp);
    expect(receipt.status).toBe('failed');
    expect(receipt.error).toContain('network down');
    // The checkpoint is preserved as a pending gap for retry.
    expect(store.pending().map((r) => r.checkpointId)).toContain(7);
    expect(new AnchorStore(dir).get(7)?.status).toBe('failed');
  });

  it('retries pending receipts and anchors them once the TSA recovers', async () => {
    const root = createHash('sha256').update('root-9').digest();
    const cp = checkpoint(9, root);
    let up = false;
    const flaky: TsaTransport = async () => {
      if (!up) {
        throw new Error('still down');
      }
      return { status: 200, body: grantedResponse(await tsa.sign(root)) };
    };
    const store = new AnchorStore(dir);
    const service = new AnchorService(store, new TsaClient({ url: 'x', name: 'test' }, flaky));

    await service.anchor(cp);
    expect(store.get(9)?.status).toBe('failed');

    up = true;
    const retried = await service.processPending();
    expect(retried.find((r) => r.checkpointId === 9)?.status).toBe('anchored');
    expect(store.pending()).toHaveLength(0);
  });
});
