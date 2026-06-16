import { signMessage } from './signing.js';
import type { SpineKeyPair } from './signing.js';

/**
 * Checkpoint signing seam.
 *
 * The spine no longer reaches into raw key material directly: it asks a `Signer`
 * to sign the checkpoint bytes and to report the public key (and optional key
 * id) to embed. This is the one place key custody is pluggable — the key can
 * live in a local file (dev/test) or inside an HSM/KMS (production) — WITHOUT
 * changing the signature format or the verifier. Every `Signer` here produces a
 * standard Ed25519 signature that `verifyCheckpointSignature` validates
 * unchanged; the signing/verifying algorithm is untouched.
 */

/** Ed25519 SubjectPublicKeyInfo DER prefix; the raw 32-byte point follows it. */
export const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface Signer {
  /**
   * Optional key-version id, embedded in the checkpoint for rotation. It is
   * metadata only and is NOT part of the signed bytes, so adding it never
   * affects verification of existing or new checkpoints. When undefined (the
   * default local signer), checkpoints are byte-identical to the legacy format.
   */
  readonly keyId?: string;
  /** Hex-DER (spki) Ed25519 public key to embed in the checkpoint. */
  publicKeyHex(): string | Promise<string>;
  /** Hex Ed25519 signature over `message`. */
  sign(message: Buffer): string | Promise<string>;
}

/**
 * Default signer: the in-process local key. This is the unchanged Ed25519 path —
 * it delegates straight to the existing `signMessage`, so behaviour and output
 * are identical to before the abstraction existed.
 */
export class LocalKeySigner implements Signer {
  readonly keyId?: string;

  constructor(
    private readonly keys: SpineKeyPair,
    keyId?: string,
  ) {
    if (keyId !== undefined) {
      this.keyId = keyId;
    }
  }

  publicKeyHex(): string {
    return this.keys.publicKeyHex;
  }

  sign(message: Buffer): string {
    return signMessage(this.keys.privateKeyHex, message);
  }
}

/**
 * The minimal capability the spine needs from a PKCS#11 token (HSM): sign raw
 * bytes with the token's Ed25519 private key — which NEVER leaves the token —
 * and expose that key's raw 32-byte public point. A production binding (e.g.
 * `graphene-pk11` over SoftHSM / YubiHSM / a network HSM) implements this; tests
 * supply a fake that signs in-process to exercise the adapter without an HSM.
 */
export interface Pkcs11SigningHandle {
  /** Raw 64-byte Ed25519 signature over `message` (PKCS#11 C_Sign, CKM_EDDSA). */
  sign(message: Buffer): Promise<Buffer>;
  /** Raw 32-byte Ed25519 public point (PKCS#11 CKA_EC_POINT value). */
  publicKeyPoint(): Promise<Buffer>;
}

/**
 * Signs checkpoints with an Ed25519 key held in a PKCS#11 HSM. The private key
 * stays in the HSM; this adapter only converts the token's raw bytes into the
 * formats the UNCHANGED verifier expects — the raw 32-byte public point is
 * wrapped into DER spki, and the raw 64-byte signature is hex-encoded. The
 * resulting checkpoint is indistinguishable in format from a locally-signed one,
 * so `verifyCheckpointSignature` needs no changes.
 */
export class Pkcs11Signer implements Signer {
  constructor(
    private readonly handle: Pkcs11SigningHandle,
    readonly keyId: string,
  ) {}

  async publicKeyHex(): Promise<string> {
    const point = await this.handle.publicKeyPoint();
    if (point.length !== 32) {
      throw new Error(`expected a 32-byte Ed25519 public point, got ${point.length}`);
    }
    return Buffer.concat([ED25519_SPKI_PREFIX, point]).toString('hex');
  }

  async sign(message: Buffer): Promise<string> {
    const signature = await this.handle.sign(message);
    return signature.toString('hex');
  }
}

/** Wrap a bare keypair in the default signer; pass a Signer through unchanged. */
export function toSigner(keysOrSigner: SpineKeyPair | Signer): Signer {
  return 'privateKeyHex' in keysOrSigner ? new LocalKeySigner(keysOrSigner) : keysOrSigner;
}
