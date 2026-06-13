import { createHash } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { ensureCryptoEngine, nodeCrypto, toArrayBuffer } from './crypto-engine.js';

/**
 * RFC 3161 Trusted Timestamping, via pkijs/asn1js (no hand-rolled ASN.1).
 *
 * - `buildTimeStampRequest` encodes a TimeStampReq over a digest.
 * - `parseTimeStampResponse` decodes the TSA's TimeStampResp.
 * - `verifyTimeStampToken` validates a token: its messageImprint equals the
 *   expected digest, its CMS signature verifies against the TSA certificate, and
 *   the signing certificate carries the id-kp-timeStamping EKU.
 */

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const ID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const EKU_EXTENSION_OID = '2.5.29.37';
const ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/** PKIStatus values we care about (RFC 3161 §2.4.2). */
export const PKI_STATUS_GRANTED = 0;
export const PKI_STATUS_GRANTED_WITH_MODS = 1;

/** Build a DER-encoded TimeStampReq over a SHA-256 `digest` (32 bytes). */
export function buildTimeStampRequest(
  digest: Buffer,
  options: { certReq?: boolean } = {},
): Buffer {
  const request = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({
        algorithmId: SHA256_OID,
        algorithmParams: new asn1js.Null(),
      }),
      hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(digest) }),
    }),
    certReq: options.certReq ?? true,
  });
  return Buffer.from(request.toSchema().toBER(false));
}

export interface TimeStampResponse {
  /** PKIStatus integer (0 granted, 1 grantedWithMods, others are failures). */
  readonly status: number;
  /** The DER timeStampToken (a CMS ContentInfo), present on success. */
  readonly token: Buffer | null;
}

/** Decode a TimeStampResp; returns the embedded timeStampToken when granted. */
export function parseTimeStampResponse(der: Buffer): TimeStampResponse {
  const asn1 = asn1js.fromBER(toArrayBuffer(der));
  const response = new pkijs.TimeStampResp({ schema: asn1.result });
  const status = response.status.status;
  const token =
    response.timeStampToken !== undefined
      ? Buffer.from(response.timeStampToken.toSchema().toBER(false))
      : null;
  return { status, token };
}

export interface TokenVerification {
  readonly ok: boolean;
  /** The TSA's asserted timestamp, when parseable. */
  readonly genTime: string | null;
  /** Hex of the timestamped digest (messageImprint.hashedMessage). */
  readonly messageImprintHex: string | null;
  /** Subject of the signing (TSA) certificate, for display. */
  readonly tsaSubject: string | null;
  readonly failures: readonly string[];
}

interface OctetValueBlock {
  readonly valueHexView: Uint8Array;
  readonly value?: readonly asn1js.OctetString[];
}

/**
 * Bytes of an OCTET STRING, handling both the primitive form (real TSAs emit
 * DER) and the constructed form (pkijs encodes CMS eContent as chunked BER, so
 * the content lives in child blocks and valueHexView is empty).
 */
function octetStringBytes(os: asn1js.OctetString): Buffer {
  const block = os.valueBlock as unknown as OctetValueBlock;
  if (block.valueHexView.byteLength > 0) {
    return Buffer.from(block.valueHexView);
  }
  const children = block.value ?? [];
  if (children.length > 0) {
    return Buffer.concat(
      children.map((c) => Buffer.from((c.valueBlock as unknown as OctetValueBlock).valueHexView)),
    );
  }
  return Buffer.from(block.valueHexView);
}

function certCommonName(cert: pkijs.Certificate): string {
  for (const rdn of cert.subject.typesAndValues) {
    if (rdn.type === '2.5.4.3') {
      return String(rdn.value.valueBlock.value);
    }
  }
  return '(no CN)';
}

function hasTimeStampingEku(cert: pkijs.Certificate): boolean {
  const ext = cert.extensions?.find((e) => e.extnID === EKU_EXTENSION_OID);
  if (!ext || !(ext.parsedValue instanceof pkijs.ExtKeyUsage)) {
    return false;
  }
  return ext.parsedValue.keyPurposes.includes(ID_KP_TIMESTAMPING);
}

function parseCert(pemOrDer: string): pkijs.Certificate {
  return new pkijs.Certificate({
    schema: asn1js.fromBER(toArrayBuffer(pemToDer(pemOrDer))).result,
  });
}

function certDer(cert: pkijs.Certificate): Buffer {
  return Buffer.from(cert.toSchema().toBER(false));
}

/** Value bytes of the signed messageDigest attribute, if present. */
function signedMessageDigest(signerInfo: pkijs.SignerInfo): Buffer | null {
  const attrs = signerInfo.signedAttrs?.attributes ?? [];
  const attr = attrs.find((a) => a.type === ATTR_MESSAGE_DIGEST);
  const value = attr?.values?.[0];
  return value instanceof asn1js.OctetString ? octetStringBytes(value) : null;
}

/**
 * Verify the SignerInfo signature with WebCrypto. pkijs/asn1js do all the ASN.1;
 * the signature math is the platform's vetted RSASSA-PKCS1-v1.5/SHA-256. When
 * signed attributes are present (as real TSAs and our test TSA emit), the signed
 * value is the DER of the SignedAttributes re-tagged as an explicit SET OF
 * (RFC 5652 §5.4); otherwise it is the eContent octets.
 */
async function verifySignerSignature(
  signedData: pkijs.SignedData,
  signerInfo: pkijs.SignerInfo,
  signerCert: pkijs.Certificate,
  eContentBytes: Buffer,
): Promise<{ ok: boolean; detail?: string }> {
  let signedBytes: Buffer;
  if (signerInfo.signedAttrs) {
    const md = signedMessageDigest(signerInfo);
    const eHash = createHash('sha256').update(eContentBytes).digest();
    if (!md || !md.equals(eHash)) {
      return { ok: false, detail: 'messageDigest attribute does not match the TSTInfo content' };
    }
    const attrsDer = Buffer.from(signerInfo.signedAttrs.toSchema().toBER(false));
    // Re-tag [0] IMPLICIT (0xA0) as SET OF (0x31): the bytes actually signed.
    attrsDer[0] = 0x31;
    signedBytes = attrsDer;
  } else {
    signedBytes = eContentBytes;
  }

  const spki = signerCert.subjectPublicKeyInfo.toSchema().toBER(false);
  const key = await nodeCrypto().subtle.importKey(
    'spki',
    spki,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const signature = Buffer.from(signerInfo.signature.valueBlock.valueHexView);
  const ok = await nodeCrypto().subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    toArrayBuffer(signature),
    toArrayBuffer(signedBytes),
  );
  return { ok };
}

/**
 * Verify a timeStampToken without trusting the operator:
 *  - messageImprint equals `expectedDigest` (the anchored checkpoint root),
 *  - the CMS signature verifies against the embedded TSA certificate,
 *  - the signing certificate carries the id-kp-timeStamping EKU,
 *  - and (when `trustedCertsPem` is given) the TSA certificate is itself trusted
 *    or chains to a trusted anchor.
 */
export async function verifyTimeStampToken(
  tokenDer: Buffer,
  expectedDigest: Buffer,
  trustedCertsPem: readonly string[] = [],
): Promise<TokenVerification> {
  ensureCryptoEngine();
  const failures: string[] = [];

  const contentInfo = new pkijs.ContentInfo({
    schema: asn1js.fromBER(toArrayBuffer(tokenDer)).result,
  });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) {
    return {
      ok: false,
      genTime: null,
      messageImprintHex: null,
      tsaSubject: null,
      failures: ['token has no encapsulated TSTInfo content'],
    };
  }
  const eContentBytes = octetStringBytes(eContent);
  const tstInfo = new pkijs.TSTInfo({
    schema: asn1js.fromBER(toArrayBuffer(eContentBytes)).result,
  });

  const hashedMessage = octetStringBytes(tstInfo.messageImprint.hashedMessage);
  const messageImprintHex = hashedMessage.toString('hex');
  if (!hashedMessage.equals(expectedDigest)) {
    failures.push('messageImprint does not match the checkpoint root');
  }

  const genTime = tstInfo.genTime instanceof Date ? tstInfo.genTime.toISOString() : null;
  if (!genTime) {
    failures.push('token has no parseable genTime');
  }

  const signerInfo = signedData.signerInfos?.[0];
  const signerCert = signedData.certificates?.find(
    (c): c is pkijs.Certificate => c instanceof pkijs.Certificate,
  );
  const tsaSubject = signerCert ? certCommonName(signerCert) : null;

  if (!signerInfo || !signerCert) {
    failures.push('token is missing a signer or its certificate');
    return { ok: false, genTime, messageImprintHex, tsaSubject, failures };
  }

  if (!hasTimeStampingEku(signerCert)) {
    failures.push('signing certificate lacks the id-kp-timeStamping extended key usage');
  }

  try {
    const sig = await verifySignerSignature(signedData, signerInfo, signerCert, eContentBytes);
    if (!sig.ok) {
      failures.push(sig.detail ?? 'CMS signature did not verify against the TSA certificate');
    }
  } catch (err) {
    failures.push(`signature verification error: ${(err as Error).message}`);
  }

  if (trustedCertsPem.length > 0) {
    const trusted = trustedCertsPem.map(parseCert);
    const signerDer = certDer(signerCert);
    const direct = trusted.some((t) => certDer(t).equals(signerDer));
    if (!direct) {
      let chained = false;
      for (const ca of trusted) {
        try {
          if (await signerCert.verify(ca)) {
            chained = true;
            break;
          }
        } catch {
          // try the next anchor
        }
      }
      if (!chained) {
        failures.push('TSA certificate does not chain to a trusted anchor');
      }
    }
  }

  return {
    ok: failures.length === 0,
    genTime,
    messageImprintHex,
    tsaSubject,
    failures,
  };
}

/** Decode a PEM certificate block into its DER bytes. */
export function pemToDer(pem: string): Buffer {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  return Buffer.from(base64, 'base64');
}
