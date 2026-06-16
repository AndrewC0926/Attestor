import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { verifyTimeStampToken } from '../src/rfc3161.js';
import { ensureCryptoEngine, toArrayBuffer } from '../src/crypto-engine.js';

/**
 * Regression fixture: a REAL timeStampToken captured from freetsa.org. It exists
 * because the original verifier assumed SHA-256 + RSA, while freetsa actually
 * signs with SHA-512 + ECDSA (P-384) — so a self-signed test TSA passed but the
 * real token failed. Keeping the real token in the suite means that class of bug
 * can never silently return: verification must derive both the digest and the
 * key type from the token itself.
 */

const here = dirname(fileURLToPath(import.meta.url));
const TOKEN = Buffer.from(
  readFileSync(join(here, 'fixtures', 'freetsa-token.b64'), 'utf8').replace(/\s+/g, ''),
  'base64',
);
/** The checkpoint root that was anchored (the token's messageImprint). */
const ROOT = Buffer.from(
  '54528fdda0c7ada45b8dcefcb2258723e8572df474bce96d96773ea42d9c2733',
  'hex',
);
const SHA512_OID = '2.16.840.1.101.3.4.2.3';
const ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

describe('real freetsa.org token (captured fixture)', () => {
  it('verifies ok against the anchored root', async () => {
    const result = await verifyTimeStampToken(TOKEN, ROOT, []);
    expect(result.failures).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.genTime).toBe('2026-06-13T19:54:49.000Z');
    expect(result.tsaSubject).toBe('www.freetsa.org');
    expect(result.messageImprintHex).toBe(ROOT.toString('hex'));
  });

  it('rejects the token when the claimed root is wrong', async () => {
    const result = await verifyTimeStampToken(TOKEN, Buffer.alloc(32), []);
    expect(result.ok).toBe(false);
    expect(result.failures.join(' ')).toContain('messageImprint');
  });

  it('is SHA-512 + ECDSA — the encoding that broke the SHA-256/RSA assumptions', () => {
    ensureCryptoEngine();
    const contentInfo = new pkijs.ContentInfo({
      schema: asn1js.fromBER(toArrayBuffer(TOKEN)).result,
    });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    const signerInfo = signedData.signerInfos[0];
    expect(signerInfo).toBeDefined();
    // The TSA declared SHA-512, not SHA-256.
    expect(signerInfo?.digestAlgorithm.algorithmId).toBe(SHA512_OID);

    // The signing certificate uses an ECDSA key, not RSA.
    const sid = signerInfo?.sid;
    const serial =
      sid instanceof pkijs.IssuerAndSerialNumber
        ? Buffer.from(sid.serialNumber.valueBlock.valueHexView).toString('hex')
        : '';
    const signerCert = signedData.certificates?.find(
      (c): c is pkijs.Certificate =>
        c instanceof pkijs.Certificate &&
        Buffer.from(c.serialNumber.valueBlock.valueHexView).toString('hex') === serial,
    );
    expect(signerCert?.subjectPublicKeyInfo.algorithm.algorithmId).toBe(ID_EC_PUBLIC_KEY);
  });
});
