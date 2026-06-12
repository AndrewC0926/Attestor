import type { EvidenceInput, EvidenceRecord } from '@attestor/types';
import { GENESIS_HASH } from '@attestor/types';
import { canonicalize, type CanonicalValue } from './canonical.js';
import { sha256Hex } from './hash.js';

/**
 * Record hashing and chaining.
 *
 * Every record commits to the full content of its predecessor via `prevHash`,
 * so the records form a hash chain: changing any field of any record changes its
 * `recordHash`, which breaks the `prevHash` link of the next record. The Merkle
 * tree (see merkle.ts) sits on top of these record hashes for O(log n) proofs.
 */

/** The fields that the chain hash commits to: everything except `recordHash`. */
type HashableRecord = Omit<EvidenceRecord, 'recordHash'>;

/** Project a record into a canonical, key-stable object for hashing. */
function toCanonical(record: HashableRecord): CanonicalValue {
  return {
    seq: record.seq,
    prevHash: record.prevHash,
    agentId: record.agentId,
    recordedAt: record.recordedAt,
    actionType: record.actionType,
    actionName: record.actionName,
    inputSha256: record.inputSha256,
    outputSha256: record.outputSha256,
    capture: record.capture,
    inputCapture: record.inputCapture,
    outputCapture: record.outputCapture,
    riskTier: record.riskTier,
    decision: record.decision,
    policyId: record.policyId,
    controls: [...record.controls],
    reason: record.reason,
    bufferedOffline: record.bufferedOffline,
  };
}

/** Compute the hex SHA-256 record hash over all fields except `recordHash`. */
export function computeRecordHash(record: HashableRecord): string {
  return sha256Hex(canonicalize(toCanonical(record)));
}

/**
 * Derive the next record in the chain from an append input and the current tail.
 * Pure: given the same inputs it always yields the same record, which is what
 * makes the chain independently reproducible during verification.
 */
export function chainRecord(
  input: EvidenceInput,
  prevSeq: number,
  prevHash: string,
): EvidenceRecord {
  const seq = prevSeq + 1;
  const base: HashableRecord = { ...input, seq, prevHash };
  return { ...base, recordHash: computeRecordHash(base) };
}

/** The (seq, prevHash) a genesis append starts from. */
export const GENESIS_TAIL = { seq: 0, hash: GENESIS_HASH } as const;
