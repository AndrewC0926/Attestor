import type {
  Checkpoint,
  EvidenceInput,
  EvidenceRecord,
  InclusionProof,
  VerificationResult,
} from '@attestor/types';
import type { SpineKeyPair } from './signing.js';
import type { EvidenceStore, StoreConfig } from './store/index.js';
import { createStore } from './store/index.js';
import { buildCheckpoint } from './checkpoint.js';
import { buildInclusionProof, verifyInclusionProof } from './merkle.js';
import { verifyLog } from './verify.js';

export interface SpineOptions {
  /** Emit a checkpoint automatically after every N appended records (0 = off). */
  readonly checkpointInterval?: number;
  /** Clock injection point for deterministic tests. */
  readonly now?: () => string;
}

/**
 * The Spine is the evidence system of record: append, checkpoint, verify, and
 * prove. It owns the only sanctioned write path (delegated to the store's single
 * `append`) and never exposes a mutation surface.
 */
export class Spine {
  private appendedSinceCheckpoint = 0;

  private constructor(
    private readonly store: EvidenceStore,
    private readonly keys: SpineKeyPair,
    private readonly checkpointInterval: number,
    private readonly now: () => string,
  ) {}

  /** Open a spine over a configured store; initializes schema and protections. */
  static async open(
    config: StoreConfig,
    keys: SpineKeyPair,
    options: SpineOptions = {},
  ): Promise<Spine> {
    const store = createStore(config);
    return Spine.fromStore(store, keys, options);
  }

  /** Wrap an already-constructed store (used by tests with a shared handle). */
  static async fromStore(
    store: EvidenceStore,
    keys: SpineKeyPair,
    options: SpineOptions = {},
  ): Promise<Spine> {
    await store.init();
    return new Spine(
      store,
      keys,
      options.checkpointInterval ?? 0,
      options.now ?? ((): string => new Date().toISOString()),
    );
  }

  /** Append one evidence record, auto-checkpointing on the configured interval. */
  async append(input: EvidenceInput): Promise<EvidenceRecord> {
    const record = await this.store.append(input);
    this.appendedSinceCheckpoint += 1;
    if (
      this.checkpointInterval > 0 &&
      this.appendedSinceCheckpoint >= this.checkpointInterval
    ) {
      await this.checkpoint();
    }
    return record;
  }

  /** Create and persist a signed checkpoint over the entire log. */
  async checkpoint(): Promise<Checkpoint> {
    const records = await this.store.getAllRecords();
    const body = buildCheckpoint(records, this.keys, this.now());
    const checkpoint = await this.store.appendCheckpoint(body);
    this.appendedSinceCheckpoint = 0;
    return checkpoint;
  }

  /** Full integrity verification of the entire log against all checkpoints. */
  async verify(): Promise<VerificationResult> {
    const [records, checkpoints] = await Promise.all([
      this.store.getAllRecords(),
      this.store.getCheckpoints(),
    ]);
    return verifyLog(records, checkpoints);
  }

  /**
   * Build an O(log n) inclusion proof that the record at `seq` is committed to by
   * the full current log (tree size = record count).
   */
  async proveInclusion(seq: number): Promise<InclusionProof> {
    const records = await this.store.getAllRecords();
    const index = seq - 1;
    if (index < 0 || index >= records.length) {
      throw new RangeError(`sequence ${seq} is out of range`);
    }
    const leaves = records.map((r) => Buffer.from(r.recordHash, 'hex'));
    return buildInclusionProof(index, leaves);
  }

  /** Verify a record's membership via its inclusion proof. O(log n). */
  async verifyInclusion(seq: number): Promise<boolean> {
    const record = await this.store.getRecord(seq);
    if (!record) {
      return false;
    }
    const proof = await this.proveInclusion(seq);
    return verifyInclusionProof(Buffer.from(record.recordHash, 'hex'), proof);
  }

  getRecord(seq: number): Promise<EvidenceRecord | null> {
    return this.store.getRecord(seq);
  }

  getRange(fromSeq: number, toSeq: number): Promise<EvidenceRecord[]> {
    return this.store.getRange(fromSeq, toSeq);
  }

  getAllRecords(): Promise<EvidenceRecord[]> {
    return this.store.getAllRecords();
  }

  getCheckpoints(): Promise<Checkpoint[]> {
    return this.store.getCheckpoints();
  }

  count(): Promise<number> {
    return this.store.count();
  }

  close(): Promise<void> {
    return this.store.close();
  }
}
