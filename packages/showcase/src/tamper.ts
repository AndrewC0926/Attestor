import Database from 'better-sqlite3';

/**
 * Out-of-band tamper helpers for the built-in `--prove-tamper` demo.
 *
 * These mutate ONE byte of ONE evidence record directly in the SQLite file,
 * exactly as the hand-run sequence in SHOWCASE.md does — to demonstrate that
 * the spine's existing `verify()` detects it. Detection is entirely the spine's
 * job; nothing here re-implements verification. The append-only trigger is
 * dropped first because the spine recreates it on every open, so an out-of-band
 * write must remove it (this simulates an attacker with full DB access).
 *
 * The mutation flips the low bit of the first hex nibble of `input_sha256`,
 * which is its own inverse: applying it twice restores the original byte.
 *
 * IMPORTANT: callers must only ever pass the isolated showcase store path.
 */

const APPEND_ONLY_TRIGGER = 'evidence_record_no_update';

/** What a tamper/restore touched. */
export interface TamperResult {
  readonly seq: number;
  readonly column: 'input_sha256';
  /** The acting tool recorded at this seq (for legible output). */
  readonly action: string;
  readonly before: string;
  readonly after: string;
}

function xorFirstNibble(sqlitePath: string, seq: number): TamperResult {
  const db = new Database(sqlitePath);
  try {
    // Simulate an attacker with raw DB access: remove the append-only guard.
    db.exec(`DROP TRIGGER IF EXISTS ${APPEND_ONLY_TRIGGER}`);
    const row = db
      .prepare('SELECT input_sha256 AS v, action_name AS action FROM evidence_record WHERE seq = ?')
      .get(seq) as { v: string; action: string } | undefined;
    if (!row) {
      throw new Error(`no evidence record at seq ${seq}`);
    }
    const before = row.v;
    const firstHex = before.slice(0, 1);
    const flipped = (parseInt(firstHex, 16) ^ 1).toString(16);
    const after = flipped + before.slice(1);
    db.prepare('UPDATE evidence_record SET input_sha256 = ? WHERE seq = ?').run(after, seq);
    return { seq, column: 'input_sha256', action: row.action, before, after };
  } finally {
    db.close();
  }
}

/** Flip exactly one byte of record `seq`'s input digest, out of band. */
export function flipEvidenceByte(sqlitePath: string, seq: number): TamperResult {
  return xorFirstNibble(sqlitePath, seq);
}

/** Reverse the flip — the operation is its own inverse. */
export function restoreEvidenceByte(sqlitePath: string, seq: number): TamperResult {
  return xorFirstNibble(sqlitePath, seq);
}
