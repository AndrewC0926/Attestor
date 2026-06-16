import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EvidenceInput } from '@attestor/types';
import { Spine } from '../src/spine.js';
import { verifyCheckpointSignature } from '../src/checkpoint.js';
import { Pkcs11Signer, type Pkcs11SigningHandle } from '../src/signer.js';

/**
 * Real PKCS#11 / HSM signing, end to end. Requires a live token. Because the
 * concrete binding (SoftHSM, YubiHSM, a network HSM) is deployment-specific, the
 * operator supplies a small module that default-exports a factory returning a
 * `Pkcs11SigningHandle`; point ATTESTOR_PKCS11_HANDLE_MODULE at it to run:
 *
 *   ATTESTOR_PKCS11_HANDLE_MODULE=/abs/path/to/softhsm-handle.mjs npm test
 *
 * The handle factory typically wraps `graphene-pk11` over a PKCS#11 .so: open a
 * session, log in with the PIN, find the Ed25519 key by label, and expose
 * sign()/publicKeyPoint(). When the env var is unset the suite is skipped, so CI
 * without an HSM stays green (same pattern as the live-freetsa test).
 *
 * NOTE: this path is NOT exercised in the development container (no HSM/SoftHSM
 * and no network to install one); the Pkcs11Signer adapter logic itself is fully
 * covered by signer.test.ts using an in-process fake token.
 */
const HANDLE_MODULE = process.env.ATTESTOR_PKCS11_HANDLE_MODULE;

type HandleFactory = () => Promise<Pkcs11SigningHandle>;

function input(): EvidenceInput {
  return {
    agentId: 'agent-hsm',
    recordedAt: '2026-03-01T00:00:01.000Z',
    actionType: 'tool_call',
    actionName: 'op_1',
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

describe.skipIf(!HANDLE_MODULE)('PKCS#11 / HSM signing (real token)', () => {
  const modulePath = HANDLE_MODULE as string;
  let dir: string;
  let handle: Pkcs11SigningHandle;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'attestor-hsm-'));
    const mod = (await import(modulePath)) as { default: HandleFactory };
    handle = await mod.default();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('signs a checkpoint in the HSM and the unchanged verifier accepts it', async () => {
    const signer = new Pkcs11Signer(handle, 'hsm-key-1');
    const spine = await Spine.open({ kind: 'sqlite', path: join(dir, 'e.sqlite') }, signer);
    try {
      await spine.append(input());
      const cp = await spine.checkpoint();
      expect(cp.keyId).toBe('hsm-key-1');
      expect(verifyCheckpointSignature(cp)).toBe(true);
      expect((await spine.verify()).ok).toBe(true);
    } finally {
      await spine.close();
    }
  });
});
