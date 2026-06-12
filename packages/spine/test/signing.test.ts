import { describe, expect, it } from 'vitest';
import {
  generateSpineKeyPair,
  publicKeyFromPrivate,
  signMessage,
  verifySignature,
} from '../src/signing.js';

describe('Ed25519 signing', () => {
  it('round-trips a signature', () => {
    const keys = generateSpineKeyPair();
    const msg = Buffer.from('attestor evidence', 'utf8');
    const sig = signMessage(keys.privateKeyHex, msg);
    expect(verifySignature(keys.publicKeyHex, msg, sig)).toBe(true);
  });

  it('rejects a tampered message', () => {
    const keys = generateSpineKeyPair();
    const sig = signMessage(keys.privateKeyHex, Buffer.from('original'));
    expect(verifySignature(keys.publicKeyHex, Buffer.from('changed'), sig)).toBe(false);
  });

  it('rejects a signature from a different key', () => {
    const a = generateSpineKeyPair();
    const b = generateSpineKeyPair();
    const msg = Buffer.from('x');
    const sig = signMessage(a.privateKeyHex, msg);
    expect(verifySignature(b.publicKeyHex, msg, sig)).toBe(false);
  });

  it('returns false (not throw) on malformed key material', () => {
    expect(verifySignature('not-hex-key', Buffer.from('x'), 'deadbeef')).toBe(false);
  });

  it('derives the public key from the private key', () => {
    const keys = generateSpineKeyPair();
    expect(publicKeyFromPrivate(keys.privateKeyHex)).toBe(keys.publicKeyHex);
  });
});
