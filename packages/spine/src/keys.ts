import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { generateSpineKeyPair, publicKeyFromPrivate, type SpineKeyPair } from './signing.js';

/**
 * Spine signing-key management. The private key is generated once at install and
 * stored locally (never committed — see .gitignore `keys/`). An operator may
 * instead supply the key out-of-band via ATTESTOR_SIGNING_KEY for stricter key
 * custody (e.g. mounted secret).
 */

interface StoredKey {
  readonly publicKeyHex: string;
  readonly privateKeyHex: string;
}

/** Load a keypair from `path`, generating and persisting one if absent. */
export function loadOrCreateKeyPair(path: string): SpineKeyPair {
  try {
    const raw = readFileSync(path, 'utf8');
    const parsed = JSON.parse(raw) as StoredKey;
    if (!parsed.privateKeyHex || !parsed.publicKeyHex) {
      throw new Error('key file is missing required fields');
    }
    return { publicKeyHex: parsed.publicKeyHex, privateKeyHex: parsed.privateKeyHex };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
    const keys = generateSpineKeyPair();
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(keys, null, 2), { mode: 0o600 });
    return keys;
  }
}

/** Resolve a keypair from environment or the given key-file path. */
export function resolveKeyPair(
  keyFilePath: string,
  env: NodeJS.ProcessEnv = process.env,
): SpineKeyPair {
  const inline = env.ATTESTOR_SIGNING_KEY;
  if (inline && inline.length > 0) {
    return { privateKeyHex: inline, publicKeyHex: publicKeyFromPrivate(inline) };
  }
  return loadOrCreateKeyPair(keyFilePath);
}
