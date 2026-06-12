import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

/**
 * Ed25519 signing for checkpoints (signed tree heads). Keys are represented as
 * hex-encoded DER so they can be stored in a file or env var without ambiguity.
 * The private key never leaves the operator's environment.
 */
export interface SpineKeyPair {
  readonly publicKeyHex: string;
  readonly privateKeyHex: string;
}

/** Generate a fresh Ed25519 keypair, exported as hex DER (spki / pkcs8). */
export function generateSpineKeyPair(): SpineKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyHex: publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    privateKeyHex: privateKey
      .export({ format: 'der', type: 'pkcs8' })
      .toString('hex'),
  };
}

/** Sign a message with a hex-DER Ed25519 private key; returns a hex signature. */
export function signMessage(privateKeyHex: string, message: Buffer): string {
  const key = createPrivateKey({
    key: Buffer.from(privateKeyHex, 'hex'),
    format: 'der',
    type: 'pkcs8',
  });
  // Ed25519 ignores the algorithm argument (must be null).
  return cryptoSign(null, message, key).toString('hex');
}

/** Verify a hex Ed25519 signature against a hex-DER public key. */
export function verifySignature(
  publicKeyHex: string,
  message: Buffer,
  signatureHex: string,
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(publicKeyHex, 'hex'),
      format: 'der',
      type: 'spki',
    });
    return cryptoVerify(null, message, key, Buffer.from(signatureHex, 'hex'));
  } catch {
    // Malformed key or signature is, for our purposes, a failed verification.
    return false;
  }
}

/** Derive the hex-DER public key from a hex-DER private key. */
export function publicKeyFromPrivate(privateKeyHex: string): string {
  const priv = createPrivateKey({
    key: Buffer.from(privateKeyHex, 'hex'),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('hex');
}
