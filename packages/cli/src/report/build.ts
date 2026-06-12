import type {
  Checkpoint,
  EvidenceRecord,
  PolicyDecision,
  RiskTier,
  VerificationFailure,
  VerificationResult,
} from '@attestor/types';
import { RISK_TIERS, POLICY_DECISIONS } from '@attestor/types';
import { controlTitle, type ControlCatalog } from '../controls.js';

export interface AttestationReport {
  readonly generatedAt: string;
  readonly from: string | null;
  readonly to: string | null;
  readonly framework: string;
  readonly integrity: {
    readonly ok: boolean;
    readonly recordsChecked: number;
    readonly checkpointsChecked: number;
    readonly failures: readonly VerificationFailure[];
    readonly latestCheckpoint: {
      readonly treeSize: number;
      readonly merkleRoot: string;
      readonly createdAt: string;
      readonly publicKey: string;
    } | null;
  };
  readonly totals: {
    readonly records: number;
    readonly byTier: Record<RiskTier, number>;
    readonly byDecision: Record<PolicyDecision, number>;
    readonly bufferedOffline: number;
  };
  readonly controlCoverage: ReadonlyArray<{
    readonly id: string;
    readonly title: string;
    readonly count: number;
  }>;
  readonly records: readonly EvidenceRecord[];
}

export interface BuildReportArgs {
  readonly records: readonly EvidenceRecord[];
  readonly checkpoints: readonly Checkpoint[];
  readonly verification: VerificationResult;
  readonly catalog: ControlCatalog;
  readonly from: string | null;
  readonly to: string | null;
  readonly generatedAt: string;
}

/** Inclusive timestamp-range filter over RFC 3339 strings. */
function inRange(recordedAt: string, from: string | null, to: string | null): boolean {
  if (from && recordedAt < from) {
    return false;
  }
  if (to && recordedAt > to) {
    return false;
  }
  return true;
}

export function buildReport(args: BuildReportArgs): AttestationReport {
  const records = args.records.filter((r) => inRange(r.recordedAt, args.from, args.to));

  const byTier = Object.fromEntries(RISK_TIERS.map((t) => [t, 0])) as Record<
    RiskTier,
    number
  >;
  const byDecision = Object.fromEntries(POLICY_DECISIONS.map((d) => [d, 0])) as Record<
    PolicyDecision,
    number
  >;
  const controlCounts = new Map<string, number>();
  let bufferedOffline = 0;

  for (const record of records) {
    byTier[record.riskTier] += 1;
    byDecision[record.decision] += 1;
    if (record.bufferedOffline) {
      bufferedOffline += 1;
    }
    for (const control of record.controls) {
      controlCounts.set(control, (controlCounts.get(control) ?? 0) + 1);
    }
  }

  const controlCoverage = [...controlCounts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([id, count]) => ({ id, title: controlTitle(args.catalog, id), count }));

  const latest = args.checkpoints.at(-1) ?? null;

  return {
    generatedAt: args.generatedAt,
    from: args.from,
    to: args.to,
    framework: args.catalog.framework,
    integrity: {
      ok: args.verification.ok,
      recordsChecked: args.verification.recordsChecked,
      checkpointsChecked: args.verification.checkpointsChecked,
      failures: args.verification.failures,
      latestCheckpoint: latest
        ? {
            treeSize: latest.treeSize,
            merkleRoot: latest.merkleRoot,
            createdAt: latest.createdAt,
            publicKey: latest.publicKey,
          }
        : null,
    },
    totals: {
      records: records.length,
      byTier,
      byDecision,
      bufferedOffline,
    },
    controlCoverage,
    records,
  };
}
