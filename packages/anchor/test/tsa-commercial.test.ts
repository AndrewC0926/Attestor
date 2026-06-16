import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Checkpoint } from '@attestor/types';
import { AnchorStore } from '../src/anchor-store.js';
import { AnchorService } from '../src/anchor-service.js';
import { TsaClient, httpTransport, type TsaConfig } from '../src/tsa-client.js';

/**
 * Live anchoring against a real, configured (commercial/qualified) TSA. Requires
 * outbound egress and a real endpoint, so it is OFF by default and skipped in CI
 * / this container (no egress, no credentials) — the same pattern as the
 * live-freetsa and HSM tests. Point it at a provider to run:
 *
 *   ATTESTOR_TSA_URL=https://your-tsa/endpoint \
 *   ATTESTOR_TSA_AUTHORIZATION='Bearer …'   # optional \
 *     npm test
 *
 * The real commercial-TSA proof happens here, against the actual provider; the
 * pluggable/redundancy/queue/lag orchestration is fully covered offline by
 * tsa-redundancy.test.ts.
 */
const URL = process.env.ATTESTOR_TSA_URL;

function checkpoint(merkleRoot: string): Checkpoint {
  return {
    id: 1,
    treeSize: 1,
    merkleRoot,
    createdAt: new Date().toISOString(),
    signature: '00',
    publicKey: '00',
  };
}

describe.skipIf(!URL)('commercial/qualified TSA (live)', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-tsa-live-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('anchors a checkpoint root and the returned token self-verifies', async () => {
    const auth = process.env.ATTESTOR_TSA_AUTHORIZATION;
    const config: TsaConfig = {
      url: URL as string,
      name: 'configured-tsa',
      ...(auth ? { headers: { authorization: auth } } : {}),
    };
    const service = new AnchorService(new AnchorStore(dir), new TsaClient(config, httpTransport(20_000)));
    const root = createHash('sha256').update(`attestor-live-${Date.now()}`).digest('hex');

    const receipt = await service.anchor(checkpoint(root));
    expect(receipt.status).toBe('anchored');
    expect(receipt.genTime).not.toBeNull();
    expect(receipt.tokenBase64).not.toBeNull();
  }, 25_000);
});
