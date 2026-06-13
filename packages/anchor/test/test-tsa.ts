import { createHash } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import * as x509 from '@peculiar/x509';
import { ensureCryptoEngine, nodeCrypto, toArrayBuffer } from '../src/crypto-engine.js';

/**
 * A self-signed, in-memory RFC 3161 Trusted Timestamp Authority for offline
 * tests. It mints genuine timeStampTokens (CMS SignedData over a TSTInfo, with
 * the standard signed attributes) so the verification path is exercised exactly
 * as it would be for a real TSA — without any network. NOT for production.
 *
 * It signs with RSASSA-PKCS1-v1.5 / SHA-256, matching freetsa.org's signing
 * algorithm, so the same verification code path covers both.
 */

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const ID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const ID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const ATTR_SIGNING_TIME = '1.2.840.113549.1.9.5';

export interface TestTsa {
  /** PEM of the self-signed TSA certificate (the trust anchor for tests). */
  readonly certPem: string;
  /** Mint a timeStampToken (DER) over `digest` at `genTime`. */
  sign(digest: Buffer, genTime?: Date): Promise<Buffer>;
}

/** Map a WebCrypto digest name to its Node crypto name. */
const NODE_HASH: Readonly<Record<string, string>> = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
};

/**
 * Create a self-signed test TSA. `hash` selects the digest algorithm the TSA
 * signs with — real TSAs differ (freetsa.org uses SHA-512), so tests cover more
 * than SHA-256.
 */
export async function createTestTsa(
  options: { hash?: 'SHA-256' | 'SHA-384' | 'SHA-512' } = {},
): Promise<TestTsa> {
  ensureCryptoEngine();
  const crypto = nodeCrypto();
  x509.cryptoProvider.set(crypto);

  const hash = options.hash ?? 'SHA-256';
  const nodeHash = NODE_HASH[hash] ?? 'sha256';
  const alg: RsaHashedKeyGenParams = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash,
  };
  const keys = (await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Attestor Test TSA',
    notBefore: new Date(Date.now() - 3600_000),
    notAfter: new Date(Date.now() + 24 * 3600_000),
    keys,
    signingAlgorithm: alg,
    extensions: [new x509.ExtendedKeyUsageExtension([ID_KP_TIMESTAMPING], true)],
  });
  const certPem = cert.toString('pem');
  const pkijsCert = new pkijs.Certificate({
    schema: asn1js.fromBER(toArrayBuffer(Buffer.from(cert.rawData))).result,
  });

  async function sign(digest: Buffer, genTime: Date = new Date()): Promise<Buffer> {
    const tstInfo = new pkijs.TSTInfo({
      version: 1,
      policy: '1.2.3.4.1',
      messageImprint: new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({
          algorithmId: SHA256_OID,
          algorithmParams: new asn1js.Null(),
        }),
        hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(digest) }),
      }),
      serialNumber: new asn1js.Integer({ value: Date.now() }),
      genTime,
    });
    const tstInfoDer = tstInfo.toSchema().toBER(false);
    const messageDigest = createHash(nodeHash).update(Buffer.from(tstInfoDer)).digest();

    const signedData = new pkijs.SignedData({
      version: 3,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: ID_CT_TSTINFO,
        eContent: new asn1js.OctetString({ valueHex: tstInfoDer }),
      }),
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({
            issuer: pkijsCert.issuer,
            serialNumber: pkijsCert.serialNumber,
          }),
          signedAttrs: new pkijs.SignedAndUnsignedAttributes({
            type: 0,
            attributes: [
              new pkijs.Attribute({
                type: ATTR_CONTENT_TYPE,
                values: [new asn1js.ObjectIdentifier({ value: ID_CT_TSTINFO })],
              }),
              new pkijs.Attribute({
                type: ATTR_MESSAGE_DIGEST,
                values: [new asn1js.OctetString({ valueHex: toArrayBuffer(messageDigest) })],
              }),
              new pkijs.Attribute({
                type: ATTR_SIGNING_TIME,
                values: [new asn1js.UTCTime({ valueDate: genTime })],
              }),
            ],
          }),
        }),
      ],
      certificates: [pkijsCert],
    });
    await signedData.sign(keys.privateKey, 0, hash);

    const contentInfo = new pkijs.ContentInfo({
      contentType: ID_SIGNED_DATA,
      content: signedData.toSchema(true),
    });
    return Buffer.from(contentInfo.toSchema().toBER(false));
  }

  return { certPem, sign };
}

/** Wrap a timeStampToken (DER) in a granted RFC 3161 TimeStampResp (DER). */
export function grantedResponse(tokenDer: Buffer): Buffer {
  const response = new pkijs.TimeStampResp({
    status: new pkijs.PKIStatusInfo({ status: 0 }),
    timeStampToken: new pkijs.ContentInfo({
      schema: asn1js.fromBER(toArrayBuffer(tokenDer)).result,
    }),
  });
  return Buffer.from(response.toSchema().toBER(false));
}
