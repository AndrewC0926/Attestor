import type { EvidenceRecord } from '@attestor/types';

/**
 * A single line of the reconstructed account, derived purely from an evidence
 * record. Replay never reads the scenario script — only the signed log — so it
 * is a faithful demonstration that the evidence alone tells the whole story.
 */
export interface ReplayEntry {
  readonly seq: number;
  readonly recordedAt: string;
  readonly actionName: string;
  readonly riskTier: string;
  readonly decision: string;
  readonly reason: string;
  readonly inputSha256: string;
  readonly recordHash: string;
  /** Raw input, present only for records whose policy opted into full capture. */
  readonly capturedInput: string | null;
}

/** Project evidence records into an ordered, human-legible replay. */
export function projectReplay(records: readonly EvidenceRecord[]): ReplayEntry[] {
  return records.map((r) => ({
    seq: r.seq,
    recordedAt: r.recordedAt,
    actionName: r.actionName,
    riskTier: r.riskTier,
    decision: r.decision,
    reason: r.reason,
    inputSha256: r.inputSha256,
    recordHash: r.recordHash,
    capturedInput: r.inputCapture,
  }));
}
