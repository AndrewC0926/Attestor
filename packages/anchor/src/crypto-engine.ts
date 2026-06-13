import { webcrypto } from 'node:crypto';
import * as pkijs from 'pkijs';

/**
 * pkijs needs a WebCrypto engine. Node 20+ ships one at `node:crypto`'s
 * `webcrypto`; we register it once. All ASN.1 / RFC 3161 / CMS work goes through
 * pkijs + asn1js — this module never hand-rolls DER.
 */
let initialized = false;

export function ensureCryptoEngine(): void {
  if (initialized) {
    return;
  }
  const crypto = webcrypto as unknown as Crypto;
  pkijs.setEngine('node-webcrypto', new pkijs.CryptoEngine({ name: 'node-webcrypto', crypto }));
  initialized = true;
}

/** The WebCrypto implementation backing pkijs (also used by tests for keygen). */
export function nodeCrypto(): Crypto {
  return webcrypto as unknown as Crypto;
}

/** Buffer → a fresh ArrayBuffer copy (asn1js expects ArrayBuffer-backed views). */
export function toArrayBuffer(buf: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(buf.byteLength);
  new Uint8Array(ab).set(buf);
  return ab;
}
