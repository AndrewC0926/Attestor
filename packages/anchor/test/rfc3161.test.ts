import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildTimeStampRequest,
  verifyTimeStampToken,
} from '../src/rfc3161.js';
import { createTestTsa } from './test-tsa.js';

function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

describe('RFC 3161 request/token round-trip (offline test TSA)', () => {
  it('encodes a TimeStampReq over a digest', () => {
    const digest = sha256(Buffer.from('checkpoint-root'));
    const der = buildTimeStampRequest(digest);
    expect(der.length).toBeGreaterThan(0);
    // DER SEQUENCE tag.
    expect(der[0]).toBe(0x30);
  });

  it('verifies a token the test TSA minted over the digest', async () => {
    const tsa = await createTestTsa();
    const digest = sha256(Buffer.from('checkpoint-root-A'));
    const genTime = new Date('2026-06-13T12:00:00.000Z');
    const token = await tsa.sign(digest, genTime);

    const result = await verifyTimeStampToken(token, digest, [tsa.certPem]);
    expect(result.failures).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.genTime).toBe('2026-06-13T12:00:00.000Z');
    expect(result.messageImprintHex).toBe(digest.toString('hex'));
    expect(result.tsaSubject).toContain('Attestor Test TSA');
  });

  it('rejects a token whose digest does not match (tampered root)', async () => {
    const tsa = await createTestTsa();
    const token = await tsa.sign(sha256(Buffer.from('real-root')));
    const result = await verifyTimeStampToken(token, sha256(Buffer.from('forged-root')), [
      tsa.certPem,
    ]);
    expect(result.ok).toBe(false);
    expect(result.failures.join(' ')).toContain('messageImprint');
  });

  it('rejects a token signed by an untrusted TSA when a trust anchor is required', async () => {
    const realTsa = await createTestTsa();
    const otherTsa = await createTestTsa();
    const digest = sha256(Buffer.from('root-B'));
    const token = await realTsa.sign(digest);
    // Verify against the WRONG trust anchor → chain build must fail.
    const result = await verifyTimeStampToken(token, digest, [otherTsa.certPem]);
    expect(result.ok).toBe(false);
  });
});
