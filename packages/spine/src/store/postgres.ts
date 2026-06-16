import { Pool, type PoolClient } from 'pg';
import type { Checkpoint, EvidenceInput, EvidenceRecord } from '@attestor/types';
import { GENESIS_HASH } from '@attestor/types';
import { chainRecord } from '../chain.js';
import type { EvidenceStore } from './types.js';

/**
 * Postgres-backed evidence store for production-shaped deployments.
 *
 * Append-only is enforced two ways: a BEFORE UPDATE OR DELETE trigger that raises
 * (defends against the application role), and a REVOKE of UPDATE/DELETE from the
 * connecting role (defends against ad-hoc SQL). The trigger is the primary
 * guarantee because it also binds the table owner, which REVOKE does not.
 *
 * Concurrency: the hash chain requires that appends are strictly serialized —
 * each new record commits to the previous record's hash, so two appends must
 * not read the same tail. `append` takes a transaction-scoped advisory lock
 * (`pg_advisory_xact_lock`) before reading the tail and inserting, so exactly
 * one appender derives `prevHash → record_hash → insert` at a time and the lock
 * releases on COMMIT/ROLLBACK. This serializes the read-tail/insert critical
 * section itself, so it is correct regardless of isolation level and keeps `seq`
 * gap-free and the chain intact under concurrent writers; reads are unaffected.
 * (Proven by the concurrency test in postgres-parity.test.ts.)
 *
 * Retention: records are never deleted — append-only already guarantees that, so
 * the 5-year SAR/CTR recordkeeping floor is met simply by *keeping* the table.
 * There is deliberately no time-based deletion path; deleting evidence would
 * contradict the immutability guarantee. Meeting a real 5-year retention SLA is
 * therefore an operational concern (durable storage + a backup/recovery regime,
 * and optionally time-range PARTITIONing of `evidence_record` by `recorded_at`
 * for very large logs); it does not change this store's contract.
 */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS evidence_record (
  seq             BIGINT  PRIMARY KEY,
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
  controls        JSONB   NOT NULL,
  reason          TEXT    NOT NULL,
  buffered_offline BOOLEAN NOT NULL,
  prev_hash       TEXT    NOT NULL,
  record_hash     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_checkpoint (
  id           BIGSERIAL PRIMARY KEY,
  tree_size    BIGINT  NOT NULL,
  merkle_root  TEXT    NOT NULL,
  created_at   TEXT    NOT NULL,
  signature    TEXT    NOT NULL,
  public_key   TEXT    NOT NULL,
  key_id       TEXT
);

-- Additive migration for pre-existing databases (legacy rows keep key_id NULL).
ALTER TABLE evidence_checkpoint ADD COLUMN IF NOT EXISTS key_id TEXT;

CREATE OR REPLACE FUNCTION attestor_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'evidence is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS evidence_record_append_only ON evidence_record;
CREATE TRIGGER evidence_record_append_only
  BEFORE UPDATE OR DELETE ON evidence_record
  FOR EACH ROW EXECUTE FUNCTION attestor_block_mutation();

DROP TRIGGER IF EXISTS evidence_checkpoint_append_only ON evidence_checkpoint;
CREATE TRIGGER evidence_checkpoint_append_only
  BEFORE UPDATE OR DELETE ON evidence_checkpoint
  FOR EACH ROW EXECUTE FUNCTION attestor_block_mutation();

-- Defense in depth: strip UPDATE/DELETE from PUBLIC. The trigger above is the
-- primary, owner-binding guarantee; for least-privilege deployments, connect as
-- a non-owner role granted only SELECT and INSERT (see deploy/postgres-grants.sql).
REVOKE UPDATE, DELETE ON evidence_record FROM PUBLIC;
REVOKE UPDATE, DELETE ON evidence_checkpoint FROM PUBLIC;
`;

/** Advisory lock key that serializes appends to the single chain. */
const APPEND_LOCK_KEY = 4242420001;

interface RecordRow {
  seq: string;
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
  controls: string[];
  reason: string;
  buffered_offline: boolean;
  prev_hash: string;
  record_hash: string;
}

interface CheckpointRow {
  id: string;
  tree_size: string;
  merkle_root: string;
  created_at: string;
  signature: string;
  public_key: string;
  key_id: string | null;
}

function rowToRecord(row: RecordRow): EvidenceRecord {
  return {
    seq: Number(row.seq),
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
    controls: row.controls,
    reason: row.reason,
    bufferedOffline: row.buffered_offline,
    prevHash: row.prev_hash,
    recordHash: row.record_hash,
  };
}

function rowToCheckpoint(row: CheckpointRow): Checkpoint {
  return {
    id: Number(row.id),
    treeSize: Number(row.tree_size),
    merkleRoot: row.merkle_root,
    createdAt: row.created_at,
    signature: row.signature,
    publicKey: row.public_key,
    ...(row.key_id ? { keyId: row.key_id } : {}),
  };
}

export class PostgresEvidenceStore implements EvidenceStore {
  private readonly pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
  }

  async init(): Promise<void> {
    await this.pool.query(SCHEMA);
  }

  async append(input: EvidenceInput): Promise<EvidenceRecord> {
    const client: PoolClient = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Serialize concurrent appends so the hash chain stays strictly ordered.
      await client.query('SELECT pg_advisory_xact_lock($1)', [APPEND_LOCK_KEY]);
      const tail = await client.query<RecordRow>(
        'SELECT * FROM evidence_record ORDER BY seq DESC LIMIT 1',
      );
      const prev = tail.rows[0];
      const prevSeq = prev ? Number(prev.seq) : 0;
      const prevHash = prev ? prev.record_hash : GENESIS_HASH;
      const record = chainRecord(input, prevSeq, prevHash);
      await client.query(
        `INSERT INTO evidence_record (
           seq, agent_id, recorded_at, action_type, action_name, input_sha256,
           output_sha256, capture, input_capture, output_capture, risk_tier,
           decision, policy_id, controls, reason, buffered_offline, prev_hash,
           record_hash
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
        [
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
          record.bufferedOffline,
          record.prevHash,
          record.recordHash,
        ],
      );
      await client.query('COMMIT');
      return record;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async getRecord(seq: number): Promise<EvidenceRecord | null> {
    const res = await this.pool.query<RecordRow>(
      'SELECT * FROM evidence_record WHERE seq = $1',
      [seq],
    );
    return res.rows[0] ? rowToRecord(res.rows[0]) : null;
  }

  async getTail(): Promise<EvidenceRecord | null> {
    const res = await this.pool.query<RecordRow>(
      'SELECT * FROM evidence_record ORDER BY seq DESC LIMIT 1',
    );
    return res.rows[0] ? rowToRecord(res.rows[0]) : null;
  }

  async getRange(fromSeq: number, toSeq: number): Promise<EvidenceRecord[]> {
    const res = await this.pool.query<RecordRow>(
      'SELECT * FROM evidence_record WHERE seq >= $1 AND seq <= $2 ORDER BY seq ASC',
      [fromSeq, toSeq],
    );
    return res.rows.map(rowToRecord);
  }

  async getAllRecords(): Promise<EvidenceRecord[]> {
    const res = await this.pool.query<RecordRow>(
      'SELECT * FROM evidence_record ORDER BY seq ASC',
    );
    return res.rows.map(rowToRecord);
  }

  async count(): Promise<number> {
    const res = await this.pool.query<{ n: string }>(
      'SELECT COUNT(*) AS n FROM evidence_record',
    );
    return Number(res.rows[0]?.n ?? 0);
  }

  async appendCheckpoint(checkpoint: Omit<Checkpoint, 'id'>): Promise<Checkpoint> {
    const res = await this.pool.query<{ id: string }>(
      `INSERT INTO evidence_checkpoint
         (tree_size, merkle_root, created_at, signature, public_key, key_id)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [
        checkpoint.treeSize,
        checkpoint.merkleRoot,
        checkpoint.createdAt,
        checkpoint.signature,
        checkpoint.publicKey,
        checkpoint.keyId ?? null,
      ],
    );
    return { id: Number(res.rows[0]?.id), ...checkpoint };
  }

  async getCheckpoints(): Promise<Checkpoint[]> {
    const res = await this.pool.query<CheckpointRow>(
      'SELECT * FROM evidence_checkpoint ORDER BY id ASC',
    );
    return res.rows.map(rowToCheckpoint);
  }

  async getLatestCheckpoint(): Promise<Checkpoint | null> {
    const res = await this.pool.query<CheckpointRow>(
      'SELECT * FROM evidence_checkpoint ORDER BY id DESC LIMIT 1',
    );
    return res.rows[0] ? rowToCheckpoint(res.rows[0]) : null;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
