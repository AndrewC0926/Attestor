import type { Checkpoint, EvidenceRecord, VerificationResult } from '@attestor/types';
import { verifyLog, buildInclusionProof, verifyInclusionProof } from '@attestor/spine';
import type { AnchoredBundle } from './bundle.js';
import { verifyTimeStampToken } from './rfc3161.js';

/**
 * Independent, three-part verification of an exported bundle. It reuses the
 * spine's exported pure functions for chain integrity and Merkle inclusion, and
 * the RFC 3161 verifier for the external anchor. It needs no live database and
 * trusts no operator — only the math and the TSA.
 */

/** Result of validating one checkpoint's external anchor. */
export interface AnchorCheck {
  readonly checkpointId: number;
  readonly treeSize: number;
  readonly status: string;
  /** True when the token verifies AND its digest is the checkpoint's root. */
  readonly ok: boolean;
  readonly genTime: string | null;
  readonly tsaName: string;
  readonly tsaSubject: string | null;
  readonly failures: readonly string[];
}

/** Result of proving one record is contained in an anchored root. */
export interface InclusionCheck {
  readonly seq: number;
  readonly ok: boolean;
  /** The anchored checkpoint whose root contains the record, if found. */
  readonly checkpointId: number | null;
  readonly merkleRoot: string | null;
  readonly detail: string;
}

export interface AnchoredVerification {
  /** (1) internal chain integrity (reused spine verifyLog). */
  readonly chain: VerificationResult;
  /** (2) each checkpoint's external RFC 3161 anchor. */
  readonly anchors: readonly AnchorCheck[];
  /** (3) inclusion of a specific record in an anchored root (when requested). */
  readonly inclusion: InclusionCheck | null;
  readonly ok: boolean;
}

function findCheckpoint(
  checkpoints: readonly Checkpoint[],
  id: number,
): Checkpoint | undefined {
  return checkpoints.find((c) => c.id === id);
}

/** Verify a bundle's chain, anchors, and (optionally) one record's inclusion. */
export async function verifyAnchoredBundle(
  bundle: AnchoredBundle,
  options: { seq?: number } = {},
): Promise<AnchoredVerification> {
  // (1) Internal chain integrity — reuse the spine's verifier verbatim.
  const chain = verifyLog(bundle.records, bundle.checkpoints);

  // (2) External anchors — validate each RFC 3161 token against the TSA.
  const anchors: AnchorCheck[] = [];
  for (const anchor of bundle.anchors) {
    const checkpoint = findCheckpoint(bundle.checkpoints, anchor.checkpointId);
    const failures: string[] = [];
    let genTime: string | null = anchor.genTime;
    let tsaSubject: string | null = null;

    if (anchor.status !== 'anchored' || !anchor.tokenBase64) {
      failures.push(`checkpoint ${anchor.checkpointId} is not anchored (status: ${anchor.status})`);
    } else if (!checkpoint) {
      failures.push(`bundle has no checkpoint ${anchor.checkpointId} for this anchor`);
    } else if (checkpoint.merkleRoot !== anchor.merkleRoot) {
      failures.push('anchor root does not match the checkpoint root');
    } else {
      const token = Buffer.from(anchor.tokenBase64, 'base64');
      const digest = Buffer.from(checkpoint.merkleRoot, 'hex');
      const result = await verifyTimeStampToken(token, digest, bundle.tsaCertsPem);
      genTime = result.genTime;
      tsaSubject = result.tsaSubject;
      failures.push(...result.failures);
    }

    anchors.push({
      checkpointId: anchor.checkpointId,
      treeSize: anchor.treeSize,
      status: anchor.status,
      ok: failures.length === 0,
      genTime,
      tsaName: anchor.tsaName,
      tsaSubject,
      failures,
    });
  }

  // (3) Inclusion of a specific record in an anchored root.
  let inclusion: InclusionCheck | null = null;
  if (options.seq !== undefined) {
    inclusion = checkInclusion(bundle, options.seq, anchors);
  }

  const anchorsOk = anchors.every((a) => a.ok);
  const inclusionOk = inclusion ? inclusion.ok : true;
  return {
    chain,
    anchors,
    inclusion,
    ok: chain.ok && anchorsOk && inclusionOk,
  };
}

function checkInclusion(
  bundle: AnchoredBundle,
  seq: number,
  anchors: readonly AnchorCheck[],
): InclusionCheck {
  const record = bundle.records.find((r) => r.seq === seq);
  if (!record) {
    return { seq, ok: false, checkpointId: null, merkleRoot: null, detail: `no record at seq ${seq}` };
  }

  // Choose the smallest VALID anchored checkpoint that covers this record.
  const candidate = bundle.checkpoints
    .filter((c) => c.treeSize >= seq && anchors.some((a) => a.checkpointId === c.id && a.ok))
    .sort((a, b) => a.treeSize - b.treeSize)[0];

  if (!candidate) {
    return {
      seq,
      ok: false,
      checkpointId: null,
      merkleRoot: null,
      detail: `no anchored checkpoint covers record ${seq}`,
    };
  }

  const leaves = bundle.records
    .slice(0, candidate.treeSize)
    .map((r: EvidenceRecord) => Buffer.from(r.recordHash, 'hex'));
  const proof = buildInclusionProof(seq - 1, leaves);
  const proofOk = verifyInclusionProof(Buffer.from(record.recordHash, 'hex'), proof);
  const rootMatches = proof.merkleRoot === candidate.merkleRoot;

  return {
    seq,
    ok: proofOk && rootMatches,
    checkpointId: candidate.id,
    merkleRoot: candidate.merkleRoot,
    detail:
      proofOk && rootMatches
        ? `record ${seq} is provably included in anchored checkpoint ${candidate.id} (tree size ${candidate.treeSize})`
        : 'inclusion proof did not reconcile with the anchored root',
  };
}
