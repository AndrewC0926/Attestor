import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { TsaClient, FREETSA } from '../src/tsa-client.js';
import { verifyTimeStampToken } from '../src/rfc3161.js';

/**
 * Live integration against the real freetsa.org TSA. This requires outbound
 * network egress, so it is OFF by default and skipped in CI / sandboxed
 * environments. Enable it where egress is allowed:
 *
 *   ATTESTOR_LIVE_TSA=1 npm test
 */
const LIVE = process.env.ATTESTOR_LIVE_TSA === '1';

describe('live freetsa.org anchoring (network)', () => {
  it.runIf(LIVE)('timestamps a digest and the token verifies', async () => {
    const digest = createHash('sha256').update(`attestor-live-${Date.now()}`).digest();
    const client = new TsaClient(FREETSA);

    const token = await client.stamp(digest);
    expect(token.length).toBeGreaterThan(0);

    // Embedded-cert signature + messageImprint + EKU check (no trust anchor here;
    // bundle the freetsa CA to also assert the chain).
    const result = await verifyTimeStampToken(token, digest);
    expect(result.ok).toBe(true);
    expect(result.messageImprintHex).toBe(digest.toString('hex'));
    expect(result.genTime).not.toBeNull();
  }, 20_000);

  it('is wired and skips cleanly when ATTESTOR_LIVE_TSA is unset', () => {
    // A always-present marker test so the file is never "empty" when LIVE is off.
    expect(typeof LIVE).toBe('boolean');
  });
});
