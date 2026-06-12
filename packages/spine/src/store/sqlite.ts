import Database from 'better-sqlite3';
import type { Checkpoint, EvidenceInput, EvidenceRecord } from '@attestor/types';
import { GENESIS_HASH } from '@attestor/types';
import { chainRecord } from '../chain.js';
import type { EvidenceStore } from './types.js';

/**
 * SQLite-backed evidence store for laptop-demo and CI use. Append-only is
 * enforced with BEFORE UPDATE / BEFORE DELETE triggers that abort any mutation,
 * mirroring the Postgres backend's guarantees so behaviour is identical in tests
 * and in production-shaped deployments.
 */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS evidence_record (
  seq             INTEGER PRIMARY KEY,
  agent_id        TEXT    NOT NULL,
  recorded_at     TEXT    NOT NULL,
  action_type     TEXT    NOT NULL,
  action_name     TEXT    NOT NULL,
  input_sha256    TEXT    NOT NULL,
  output_sha256   TEXT,
  capture         TEXT    NOT NULL,
  input_capture   TEXT,
  output_capture  TEXT,
  risk_tier       TEXT    NOT NULL,
  decision        TEXT    NOT NULL,
  policy_id       TEXT    NOT NULL,
  controls        TEXT    NOT NULL,
  reason          TEXT    NOT NULL,
  buffered_offline INTEGER NOT NULL,
  prev_hash       TEXT    NOT NULL,
  record_hash     TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS evidence_record_no_update
  BEFORE UPDATE ON evidence_record
BEGIN
  SELECT RAISE(ABORT, 'evidence_record is append-only');
END;

CREATE TRIGGER IF NOT EXISTS evidence_record_no_delete
  BEFORE DELETE ON evidence_record
BEGIN
  SELECT RAISE(ABORT, 'evidence_record is append-only');
END;

CREATE TABLE IF NOT EXISTS evidence_checkpoint (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  tree_size    INTEGER NOT NULL,
  merkle_root  TEXT    NOT NULL,
  created_at   TEXT    NOT NULL,
  signature    TEXT    NOT NULL,
  public_key   TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS evidence_checkpoint_no_update
  BEFORE UPDATE ON evidence_checkpoint
BEGIN
  SELECT RAISE(ABORT, 'evidence_checkpoint is append-only');
END;

CREATE TRIGGER IF NOT EXISTS evidence_checkpoint_no_delete
  BEFORE DELETE ON evidence_checkpoint
BEGIN
  SELECT RAISE(ABORT, 'evidence_checkpoint is append-only');
END;
`;

interface RecordRow {
  seq: number;
  agent_id: string;
  recorded_at: string;
  action_type: string;
  action_name: string;
  input_sha256: string;
  output_sha256: string | null;
  capture: string;
  input_capture: string | null;
  output_capture: string | null;
  risk_tier: string;
  decision: string;
  policy_id: string;
  controls: string;
  reason: string;
  buffered_offline: number;
  prev_hash: string;
  record_hash: string;
}

interface CheckpointRow {
  id: number;
  tree_size: number;
  merkle_root: string;
  created_at: string;
  signature: string;
  public_key: string;
}

function rowToRecord(row: RecordRow): EvidenceRecord {
  return {
    seq: row.seq,
    agentId: row.agent_id,
    recordedAt: row.recorded_at,
    actionType: row.action_type as EvidenceRecord['actionType'],
    actionName: row.action_name,
    inputSha256: row.input_sha256,
    outputSha256: row.output_sha256,
    capture: row.capture as EvidenceRecord['capture'],
    inputCapture: row.input_capture,
    outputCapture: row.output_capture,
    riskTier: row.risk_tier as EvidenceRecord['riskTier'],
    decision: row.decision as EvidenceRecord['decision'],
    policyId: row.policy_id,
    controls: JSON.parse(row.controls) as string[],
    reason: row.reason,
    bufferedOffline: row.buffered_offline === 1,
    prevHash: row.prev_hash,
    recordHash: row.record_hash,
  };
}

function rowToCheckpoint(row: CheckpointRow): Checkpoint {
  return {
    id: row.id,
    treeSize: row.tree_size,
    merkleRoot: row.merkle_root,
    createdAt: row.created_at,
    signature: row.signature,
    publicKey: row.public_key,
  };
}

export class SqliteEvidenceStore implements EvidenceStore {
  private readonly db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
  }

  init(): Promise<void> {
    this.db.exec(SCHEMA);
    return Promise.resolve();
  }

  append(input: EvidenceInput): Promise<EvidenceRecord> {
    const insert = this.db.prepare<unknown[]>(
      `INSERT INTO evidence_record (
         seq, agent_id, recorded_at, action_type, action_name, input_sha256,
         output_sha256, capture, input_capture, output_capture, risk_tier,
         decision, policy_id, controls, reason, buffered_offline, prev_hash,
         record_hash
       ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    );
    const tailStmt = this.db.prepare<[], RecordRow>(
      'SELECT * FROM evidence_record ORDER BY seq DESC LIMIT 1',
    );
    // better-sqlite3 transactions are synchronous and atomic; concurrent writers
    // are serialized by SQLite's write lock, so the read-tail/insert is safe.
    const txn = this.db.transaction((): EvidenceRecord => {
      const tail = tailStmt.get();
      const prevSeq = tail ? tail.seq : 0;
      const prevHash = tail ? tail.record_hash : GENESIS_HASH;
      const record = chainRecord(input, prevSeq, prevHash);
      insert.run(
        record.seq,
        record.agentId,
        record.recordedAt,
        record.actionType,
        record.actionName,
        record.inputSha256,
        record.outputSha256,
        record.capture,
        record.inputCapture,
        record.outputCapture,
        record.riskTier,
        record.decision,
        record.policyId,
        JSON.stringify(record.controls),
        record.reason,
        record.bufferedOffline ? 1 : 0,
        record.prevHash,
        record.recordHash,
      );
      return record;
    });
    return Promise.resolve(txn());
  }

  getRecord(seq: number): Promise<EvidenceRecord | null> {
    const row = this.db
      .prepare<[number], RecordRow>('SELECT * FROM evidence_record WHERE seq = ?')
      .get(seq);
    return Promise.resolve(row ? rowToRecord(row) : null);
  }

  getTail(): Promise<EvidenceRecord | null> {
    const row = this.db
      .prepare<[], RecordRow>('SELECT * FROM evidence_record ORDER BY seq DESC LIMIT 1')
      .get();
    return Promise.resolve(row ? rowToRecord(row) : null);
  }

  getRange(fromSeq: number, toSeq: number): Promise<EvidenceRecord[]> {
    const rows = this.db
      .prepare<[number, number], RecordRow>(
        'SELECT * FROM evidence_record WHERE seq >= ? AND seq <= ? ORDER BY seq ASC',
      )
      .all(fromSeq, toSeq);
    return Promise.resolve(rows.map(rowToRecord));
  }

  getAllRecords(): Promise<EvidenceRecord[]> {
    const rows = this.db
      .prepare<[], RecordRow>('SELECT * FROM evidence_record ORDER BY seq ASC')
      .all();
    return Promise.resolve(rows.map(rowToRecord));
  }

  count(): Promise<number> {
    const row = this.db
      .prepare<[], { n: number }>('SELECT COUNT(*) AS n FROM evidence_record')
      .get();
    return Promise.resolve(row ? row.n : 0);
  }

  appendCheckpoint(checkpoint: Omit<Checkpoint, 'id'>): Promise<Checkpoint> {
    const info = this.db
      .prepare<unknown[]>(
        `INSERT INTO evidence_checkpoint
           (tree_size, merkle_root, created_at, signature, public_key)
         VALUES (?,?,?,?,?)`,
      )
      .run(
        checkpoint.treeSize,
        checkpoint.merkleRoot,
        checkpoint.createdAt,
        checkpoint.signature,
        checkpoint.publicKey,
      );
    return Promise.resolve({ id: Number(info.lastInsertRowid), ...checkpoint });
  }

  getCheckpoints(): Promise<Checkpoint[]> {
    const rows = this.db
      .prepare<[], CheckpointRow>('SELECT * FROM evidence_checkpoint ORDER BY id ASC')
      .all();
    return Promise.resolve(rows.map(rowToCheckpoint));
  }

  getLatestCheckpoint(): Promise<Checkpoint | null> {
    const row = this.db
      .prepare<[], CheckpointRow>(
        'SELECT * FROM evidence_checkpoint ORDER BY id DESC LIMIT 1',
      )
      .get();
    return Promise.resolve(row ? rowToCheckpoint(row) : null);
  }

  close(): Promise<void> {
    this.db.close();
    return Promise.resolve();
  }
}
