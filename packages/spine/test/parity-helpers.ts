import type {
  Checkpoint,
  EvidenceInput,
  EvidenceRecord,
  InclusionProof,
  VerificationResult,
} from '@attestor/types';
import { Spine } from '../src/spine.js';
import type { SpineKeyPair } from '../src/signing.js';
import type { StoreConfig } from '../src/store/index.js';

/**
 * Shared inputs and harness for the storage PARITY proof.
 *
 * The point: the spine's cryptography (record hashing, chaining, Merkle roots,
 * checkpoint signing, verification) lives ABOVE the store and is
 * storage-agnostic. Driving the SAME sequence of appends + a checkpoint through
 * two different backends — with the same key and the same injected clock — must
 * produce byte-identical record hashes, Merkle roots, checkpoint signatures, and
 * inclusion proofs, and verify identically. If a backend ever changed the
 * cryptography, these comparisons would fail.
 */

/** A fixed clock so checkpoint `createdAt` (and thus its signature) is stable. */
const FIXED_NOW = (): string => '2026-01-01T00:00:00.000Z';

/** A deterministic, varied sequence of evidence inputs (fixed timestamps). */
export const PARITY_INPUTS: readonly EvidenceInput[] = [
  {
    agentId: 'agent-1',
    recordedAt: '2026-01-01T00:00:01.000Z',
    actionType: 'tool_call',
    actionName: 'read_record',
    inputSha256: 'a'.repeat(64),
    outputSha256: 'b'.repeat(64),
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T1',
    decision: 'allow',
    policyId: 'rule.read',
    controls: ['A.6.2.4', 'A.6.2.8'],
    reason: 'read-only',
    bufferedOffline: false,
  },
  {
    agentId: 'agent-1',
    recordedAt: '2026-01-01T00:00:02.000Z',
    actionType: 'tool_call',
    actionName: 'write_disposition',
    inputSha256: 'c'.repeat(64),
    outputSha256: null,
    capture: 'full',
    inputCapture: '{"caseId":"C1"}',
    outputCapture: null,
    riskTier: 'T2',
    decision: 'allow',
    policyId: 'rule.write',
    controls: ['A.9.4'],
    reason: 'state-changing write [authorized — recorded before execution]',
    bufferedOffline: false,
  },
  {
    agentId: 'agent-1',
    recordedAt: '2026-01-01T00:00:03.000Z',
    actionType: 'tool_call',
    actionName: 'export_case_file',
    inputSha256: 'd'.repeat(64),
    outputSha256: null,
    capture: 'full',
    inputCapture: '{"caseId":"C1"}',
    outputCapture: null,
    riskTier: 'T3',
    decision: 'escalate',
    policyId: 'rule.export',
    controls: ['A.9.2', 'A.10.4'],
    reason: 'export requires approval',
    bufferedOffline: false,
  },
  {
    agentId: 'agent-2',
    recordedAt: '2026-01-01T00:00:04.000Z',
    actionType: 'tool_call',
    actionName: 'purge_records',
    inputSha256: 'e'.repeat(64),
    outputSha256: null,
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T3',
    decision: 'deny',
    policyId: 'rule.purge',
    controls: ['A.9.2'],
    reason: 'destructive — denied',
    bufferedOffline: false,
  },
];

export interface SequenceResult {
  readonly records: readonly EvidenceRecord[];
  readonly recordHashes: readonly string[];
  readonly checkpoints: readonly Checkpoint[];
  readonly merkleRoots: readonly string[];
  readonly verification: VerificationResult;
  readonly inclusion: readonly InclusionProof[];
}

/**
 * Run the parity sequence through one backend: append all inputs, checkpoint
 * over the whole log, then collect records, checkpoints, verification, and an
 * inclusion proof for every record.
 */
export async function runParitySequence(
  config: StoreConfig,
  keys: SpineKeyPair,
): Promise<SequenceResult> {
  const spine = await Spine.open(config, keys, { now: FIXED_NOW });
  try {
    for (const input of PARITY_INPUTS) {
      await spine.append(input);
    }
    await spine.checkpoint();
    const [records, checkpoints, verification] = await Promise.all([
      spine.getAllRecords(),
      spine.getCheckpoints(),
      spine.verify(),
    ]);
    const inclusion: InclusionProof[] = [];
    for (let seq = 1; seq <= records.length; seq++) {
      inclusion.push(await spine.proveInclusion(seq));
    }
    return {
      records,
      recordHashes: records.map((r) => r.recordHash),
      checkpoints,
      merkleRoots: checkpoints.map((c) => c.merkleRoot),
      verification,
      inclusion,
    };
  } finally {
    await spine.close();
  }
}
