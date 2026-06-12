import type { Checkpoint, EvidenceInput, EvidenceRecord } from '@attestor/types';

/**
 * The evidence store contract.
 *
 * RULE (sacred): the ONLY method that writes evidence is `append`. There is no
 * update, no delete, no upsert. Backends additionally enforce append-only at the
 * database layer (triggers + privilege revocation) so that even a buggy or
 * malicious application process cannot mutate history through this interface.
 */
export interface EvidenceStore {
  /** Create schema and install append-only protections. Idempotent. */
  init(): Promise<void>;

  /**
   * Atomically read the chain tail, derive the next hash-chained record, and
   * insert it. The single sanctioned write path for evidence.
   */
  append(input: EvidenceInput): Promise<EvidenceRecord>;

  /** Fetch a single record by sequence number. */
  getRecord(seq: number): Promise<EvidenceRecord | null>;

  /** The current chain tail, or null if the log is empty. */
  getTail(): Promise<EvidenceRecord | null>;

  /** Inclusive range of records ordered by sequence. */
  getRange(fromSeq: number, toSeq: number): Promise<EvidenceRecord[]>;

  /** All records in sequence order (used by full verification). */
  getAllRecords(): Promise<EvidenceRecord[]>;

  /** Total number of evidence records. */
  count(): Promise<number>;

  /** Persist a signed checkpoint (also append-only). */
  appendCheckpoint(checkpoint: Omit<Checkpoint, 'id'>): Promise<Checkpoint>;

  /** All checkpoints in id order. */
  getCheckpoints(): Promise<Checkpoint[]>;

  /** The most recent checkpoint, or null if none. */
  getLatestCheckpoint(): Promise<Checkpoint | null>;

  /** Release underlying resources. */
  close(): Promise<void>;
}
