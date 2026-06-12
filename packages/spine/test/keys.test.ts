import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadOrCreateKeyPair, resolveKeyPair } from '../src/keys.js';
import { generateSpineKeyPair, verifySignature, signMessage } from '../src/signing.js';

describe('key management', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-keys-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('generates and persists a keypair on first use, then reloads it', () => {
    const path = join(dir, 'nested', 'signing-key.json');
    const created = loadOrCreateKeyPair(path);
    const reloaded = loadOrCreateKeyPair(path);
    expect(reloaded).toEqual(created);

    const msg = Buffer.from('x');
    expect(
      verifySignature(created.publicKeyHex, msg, signMessage(created.privateKeyHex, msg)),
    ).toBe(true);
  });

  it('throws on a malformed key file', () => {
    const badPath = join(dir, 'bad.json');
    writeFileSync(badPath, JSON.stringify({ foo: 'bar' }));
    expect(() => loadOrCreateKeyPair(badPath)).toThrow();
  });

  it('resolveKeyPair prefers an inline env key', () => {
    const inline = generateSpineKeyPair();
    const resolved = resolveKeyPair(join(dir, 'unused.json'), {
      ATTESTOR_SIGNING_KEY: inline.privateKeyHex,
    } as NodeJS.ProcessEnv);
    expect(resolved.privateKeyHex).toBe(inline.privateKeyHex);
    expect(resolved.publicKeyHex).toBe(inline.publicKeyHex);
  });

  it('resolveKeyPair falls back to the key file when no env key is set', () => {
    const path = join(dir, 'file-key.json');
    const resolved = resolveKeyPair(path, {} as NodeJS.ProcessEnv);
    expect(resolved.privateKeyHex).toBeTruthy();
  });
});
