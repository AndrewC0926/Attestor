import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Checkpoint } from '@attestor/types';
import { AnchorStore } from '../src/anchor-store.js';
import { AnchorService } from '../src/anchor-service.js';
import { TsaClient, type TsaTransport } from '../src/tsa-client.js';
import { grantedResponse } from './test-tsa.js';

/**
 * Exercises the production-reliability orchestration — primary+fallback
 * redundancy, the durable retry queue, anchor-lag metrics, auth headers, and
 * cert bundling — using in-process fake transports plus the REAL freetsa token
 * fixture (so a genuine token still verifies through the service path). No
 * network, and the RFC 3161 verification logic is unchanged.
 */
const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = Buffer.from(
  readFileSync(join(here, 'fixtures', 'freetsa-token.b64'), 'utf8').replace(/\s+/g, ''),
  'base64',
);
/** The checkpoint root the fixture token actually attests (its messageImprint). */
const ROOT = '54528fdda0c7ada45b8dcefcb2258723e8572df474bce96d96773ea42d9c2733';

function checkpoint(id: number, merkleRoot: string = ROOT): Checkpoint {
  return {
    id,
    treeSize: id,
    merkleRoot,
    createdAt: new Date(Date.now() - id * 60_000).toISOString(),
    signature: '00',
    publicKey: '00',
  };
}

/** Transport that always fails (TSA unreachable). */
const failing: TsaTransport = () => Promise.reject(new Error('network down'));
/** Transport that returns the real freetsa token wrapped in a granted response. */
const grantedFixture: TsaTransport = () =>
  Promise.resolve({ status: 200, body: grantedResponse(FIXTURE) });

describe('production TSA reliability', () => {
  let dir: string;
  let store: AnchorStore;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-tsa-'));
    store = new AnchorStore(dir);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('falls back to the next TSA when the primary is unreachable', async () => {
    const service = new AnchorService(store, [
      new TsaClient({ url: 'https://primary', name: 'primary' }, failing),
      new TsaClient({ url: 'https://fallback', name: 'fallback' }, grantedFixture),
    ]);
    const receipt = await service.anchor(checkpoint(1));
    expect(receipt.status).toBe('anchored');
    expect(receipt.tsaName).toBe('fallback'); // the primary was skipped
    expect(receipt.genTime).not.toBeNull();
  });

  it('keeps the checkpoint queued (never anchored, never lost) when ALL TSAs fail, and retries later', async () => {
    let recovered = false;
    const flaky: TsaTransport = () =>
      recovered
        ? Promise.resolve({ status: 200, body: grantedResponse(FIXTURE) })
        : Promise.reject(new Error('still down'));
    const service = new AnchorService(store, [
      new TsaClient({ url: 'https://a', name: 'tsa-a' }, failing),
      new TsaClient({ url: 'https://b', name: 'tsa-b' }, flaky),
    ]);

    const failedReceipt = await service.anchor(checkpoint(1));
    expect(failedReceipt.status).toBe('failed');
    expect(failedReceipt.tokenBase64).toBeNull(); // never silently anchored
    expect(failedReceipt.error).toContain('tsa-a');
    expect(failedReceipt.error).toContain('tsa-b');
    expect(store.pending().map((r) => r.checkpointId)).toContain(1); // still queued

    // TSA recovers; the durable queue drains.
    recovered = true;
    const retried = await service.processPending();
    expect(retried.find((r) => r.checkpointId === 1)?.status).toBe('anchored');
    expect(store.pending()).toHaveLength(0);
  });

  it('does NOT anchor when the token does not match the checkpoint root', async () => {
    const service = new AnchorService(
      store,
      new TsaClient({ url: 'https://x', name: 'x' }, grantedFixture),
    );
    // The fixture attests ROOT; anchoring a different root must be rejected.
    const receipt = await service.anchor(checkpoint(1, '11'.repeat(32)));
    expect(receipt.status).toBe('failed');
    expect(receipt.tokenBase64).toBeNull();
    expect(receipt.error).toContain('self-verification');
  });

  it('sends configured auth headers to the TSA', async () => {
    let seen: Record<string, string> | undefined;
    const capturing: TsaTransport = (_url, _body, headers) => {
      seen = headers;
      return Promise.resolve({ status: 200, body: grantedResponse(FIXTURE) });
    };
    const service = new AnchorService(
      store,
      new TsaClient(
        { url: 'https://commercial', name: 'commercial', headers: { 'x-api-key': 'secret' } },
        capturing,
      ),
    );
    const receipt = await service.anchor(checkpoint(1));
    expect(receipt.status).toBe('anchored');
    expect(seen?.['x-api-key']).toBe('secret');
  });

  it('reports anchor lag for monitoring', async () => {
    const service = new AnchorService(store, new TsaClient({ url: 'https://x', name: 'x' }, failing));
    await service.anchor(checkpoint(1)); // fails -> unanchored
    await service.anchor(checkpoint(2)); // fails -> unanchored
    const now = Date.now();
    const lag = service.lag(now);
    expect(lag.anchored).toBe(0);
    expect(lag.failed).toBe(2);
    // checkpoint(2) has the older createdAt (now - 2min), so it's the oldest gap.
    expect(lag.oldestPendingCheckpointId).toBe(2);
    expect(lag.oldestPendingAgeMs).toBeGreaterThanOrEqual(120_000 - 5_000);
  });

  it('exposes the union of configured TSA cert chains for offline bundling', () => {
    const service = new AnchorService(store, [
      new TsaClient({ url: 'https://a', name: 'a', certsPem: ['PEM-A'] }, failing),
      new TsaClient({ url: 'https://b', name: 'b', certsPem: ['PEM-B', 'PEM-A'] }, failing),
    ]);
    expect(service.trustedCertsPem()).toEqual(['PEM-A', 'PEM-B']);
  });
});
