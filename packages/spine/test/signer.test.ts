import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceInput } from '@attestor/types';
import { Spine } from '../src/spine.js';
import { generateSpineKeyPair } from '../src/signing.js';
import { buildCheckpoint, verifyCheckpointSignature } from '../src/checkpoint.js';
import {
  LocalKeySigner,
  Pkcs11Signer,
  ED25519_SPKI_PREFIX,
  type Pkcs11SigningHandle,
} from '../src/signer.js';

const FIXED_NOW = (): string => '2026-03-01T00:00:00.000Z';

function input(n: number): EvidenceInput {
  return {
    agentId: 'agent-1',
    recordedAt: `2026-03-01T00:00:0${n}.000Z`,
    actionType: 'tool_call',
    actionName: `op_${n}`,
    inputSha256: 'a'.repeat(64),
    outputSha256: null,
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T1',
    decision: 'allow',
    policyId: 'rule.read',
    controls: [],
    reason: 'r',
    bufferedOffline: false,
  };
}

/**
 * A fake PKCS#11 token that holds an Ed25519 key and signs IN PROCESS, returning
 * the same raw bytes a real HSM would: a raw 64-byte signature and the raw
 * 32-byte public point. It exercises the Pkcs11Signer adapter (DER-wrapping the
 * point, hex-encoding the signature) against the UNCHANGED verifier — no HSM.
 */
function fakeHsm(): Pkcs11SigningHandle {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const point = spki.subarray(spki.length - 32); // last 32 bytes are the raw point
  return {
    sign: (message: Buffer): Promise<Buffer> => Promise.resolve(cryptoSign(null, message, privateKey)),
    publicKeyPoint: (): Promise<Buffer> => Promise.resolve(Buffer.from(point)),
  };
}

describe('signer abstraction & backward compatibility', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-signer-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('REGRESSION: a pre-change (legacy) checkpoint still verifies and has no keyId', async () => {
    const keys = generateSpineKeyPair();
    const spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, keys, {
      now: FIXED_NOW,
    });
    try {
      await spine.append(input(1));
      await spine.append(input(2));
      const records = await spine.getAllRecords();
      // Build a checkpoint via the UNCHANGED legacy function (no keyId).
      const legacy = buildCheckpoint(records, keys, '2026-03-01T00:00:00.000Z');
      expect(legacy).not.toHaveProperty('keyId');
      expect(verifyCheckpointSignature({ id: 1, ...legacy })).toBe(true);
    } finally {
      await spine.close();
    }
  });

  it('the default local signer produces keyId-free checkpoints that verify', async () => {
    const keys = generateSpineKeyPair();
    const spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, keys);
    try {
      await spine.append(input(1));
      const cp = await spine.checkpoint();
      expect(cp.keyId).toBeUndefined(); // byte-identical to legacy format
      expect(verifyCheckpointSignature(cp)).toBe(true);
      expect((await spine.verify()).ok).toBe(true);
    } finally {
      await spine.close();
    }
  });

  it('an HSM-style signer (raw bytes via PKCS#11) yields checkpoints the unchanged verifier accepts', async () => {
    const signer = new Pkcs11Signer(fakeHsm(), 'hsm-key-1');
    const spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, signer);
    try {
      await spine.append(input(1));
      await spine.append(input(2));
      const cp = await spine.checkpoint();
      expect(cp.keyId).toBe('hsm-key-1');
      // The adapter wrapped the raw 32-byte point into DER spki...
      expect(cp.publicKey.startsWith(ED25519_SPKI_PREFIX.toString('hex'))).toBe(true);
      // ...and the resulting checkpoint verifies with the SAME verifier as local keys.
      expect(verifyCheckpointSignature(cp)).toBe(true);
      expect((await spine.verify()).ok).toBe(true);
    } finally {
      await spine.close();
    }
  });
});

describe('key rotation', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-rotate-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('signs new checkpoints with the rotated key while OLD checkpoints stay verifiable', async () => {
    const path = join(dir, 'e.sqlite');
    const keysV1 = generateSpineKeyPair();
    const keysV2 = generateSpineKeyPair();

    // Sign the first checkpoint with key v1.
    let spine = await Spine.open({ kind: 'sqlite', path }, new LocalKeySigner(keysV1, 'key-v1'), {
      now: FIXED_NOW,
    });
    await spine.append(input(1));
    await spine.append(input(2));
    await spine.checkpoint();
    await spine.close();

    // Rotate: reopen the SAME store with key v2 and checkpoint again.
    spine = await Spine.open({ kind: 'sqlite', path }, new LocalKeySigner(keysV2, 'key-v2'), {
      now: FIXED_NOW,
    });
    await spine.append(input(3));
    await spine.checkpoint();
    const checkpoints = await spine.getCheckpoints();
    const verification = await spine.verify();
    await spine.close();

    expect(verification.ok).toBe(true); // verifies across the rotation boundary
    expect(checkpoints).toHaveLength(2);
    expect(checkpoints[0]?.keyId).toBe('key-v1');
    expect(checkpoints[1]?.keyId).toBe('key-v2');
    expect(checkpoints[0]?.publicKey).not.toBe(checkpoints[1]?.publicKey);
    // Each historical checkpoint verifies against the key embedded in IT.
    const [first, second] = checkpoints;
    expect(first && verifyCheckpointSignature(first)).toBe(true);
    expect(second && verifyCheckpointSignature(second)).toBe(true);
  });
});
