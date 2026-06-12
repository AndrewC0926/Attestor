import type {
  Checkpoint,
  EvidenceRecord,
  VerificationFailure,
  VerificationResult,
} from '@attestor/types';
import { GENESIS_HASH } from '@attestor/types';
import { computeRecordHash } from './chain.js';
import { merkleRootHex } from './merkle.js';
import { verifyCheckpointSignature } from './checkpoint.js';

/**
 * Pure integrity verification over an ordered set of records and checkpoints.
 *
 * This function is the heart of the tamper-evidence guarantee. It is pure so it
 * can be exhaustively unit-tested by feeding it deliberately corrupted inputs;
 * the Spine wires it to the store for end-to-end verification. Three independent
 * checks must all hold:
 *   1. Each record's hash recomputes from its own fields (no field was altered).
 *   2. Each record links to its predecessor (no record was reordered/removed).
 *   3. Each signed checkpoint's Merkle root recomputes and its signature holds
 *      (no wholesale rewrite can forge a historical root).
 */
export function verifyLog(
  records: readonly EvidenceRecord[],
  checkpoints: readonly Checkpoint[],
): VerificationResult {
  const failures: VerificationFailure[] = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i] as EvidenceRecord;
    const expectedSeq = i + 1;
    if (record.seq !== expectedSeq) {
      failures.push({
        kind: 'sequence_gap',
        at: record.seq,
        detail: `expected sequence ${expectedSeq} at position ${i}, found ${record.seq}`,
      });
    }

    const expectedPrev =
      i === 0 ? GENESIS_HASH : (records[i - 1] as EvidenceRecord).recordHash;
    if (record.prevHash !== expectedPrev) {
      failures.push({
        kind: 'chain_link_mismatch',
        at: record.seq,
        detail: `prevHash does not match the preceding record's hash`,
      });
    }

    const { recordHash: _stored, ...hashable } = record;
    const recomputed = computeRecordHash(hashable);
    if (recomputed !== record.recordHash) {
      failures.push({
        kind: 'record_hash_mismatch',
        at: record.seq,
        detail: `record content does not match its stored hash`,
      });
    }
  }

  for (const checkpoint of checkpoints) {
    if (checkpoint.treeSize > records.length) {
      failures.push({
        kind: 'checkpoint_root_mismatch',
        at: checkpoint.id,
        detail: `checkpoint covers ${checkpoint.treeSize} records but only ${records.length} are present`,
      });
    } else {
      const leaves = records
        .slice(0, checkpoint.treeSize)
        .map((r) => Buffer.from(r.recordHash, 'hex'));
      const root = merkleRootHex(leaves);
      if (root !== checkpoint.merkleRoot) {
        failures.push({
          kind: 'checkpoint_root_mismatch',
          at: checkpoint.id,
          detail: `recomputed Merkle root does not match the signed checkpoint root`,
        });
      }
    }

    if (!verifyCheckpointSignature(checkpoint)) {
      failures.push({
        kind: 'checkpoint_signature_invalid',
        at: checkpoint.id,
        detail: `checkpoint signature failed Ed25519 verification`,
      });
    }
  }

  return {
    ok: failures.length === 0,
    recordsChecked: records.length,
    checkpointsChecked: checkpoints.length,
    failures,
  };
}
