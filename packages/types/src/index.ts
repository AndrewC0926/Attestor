/**
 * @attestor/types — shared, dependency-free contracts for the Attestor platform.
 *
 * These types are the wire contract between the gateway (which observes agent
 * actions), the spine (which records them immutably), and the CLI (which attests
 * and verifies them). Keeping them in a zero-dependency package means the
 * contract cannot drift between packages.
 */

/**
 * Risk tier of an observed action. Tiers drive fail-open vs fail-closed policy.
 *
 *  - T0: read-only, non-sensitive (e.g. list available tools).
 *  - T1: read-only, sensitive (e.g. read a record, query data).
 *  - T2: state-changing within the operator's own systems (e.g. write a file).
 *  - T3: financial, destructive, or external-communication (e.g. send money,
 *        delete data, email a third party).
 */
export type RiskTier = 'T0' | 'T1' | 'T2' | 'T3';

export const RISK_TIERS: readonly RiskTier[] = ['T0', 'T1', 'T2', 'T3'] as const;

/** Whether a tier fails open (pass through) or closed (block) on degradation. */
export function tierFailsClosed(tier: RiskTier): boolean {
  return tier === 'T2' || tier === 'T3';
}

/** The kind of action that passed through the gateway. */
export type ActionType = 'tool_call' | 'model_call' | 'agent_message';

export const ACTION_TYPES: readonly ActionType[] = [
  'tool_call',
  'model_call',
  'agent_message',
] as const;

/** The policy engine's decision for an action. */
export type PolicyDecision = 'allow' | 'deny' | 'escalate';

export const POLICY_DECISIONS: readonly PolicyDecision[] = [
  'allow',
  'deny',
  'escalate',
] as const;

/**
 * Payload capture mode. Privacy by design: the default is digest-only. Raw
 * payloads are persisted only when a matched policy explicitly opts in.
 */
export type CaptureMode = 'digest' | 'full';

/**
 * The append-input for a single evidence record. Everything the caller controls;
 * the spine derives sequence, prevHash, and recordHash on append.
 */
export interface EvidenceInput {
  /** Stable identity of the acting agent (e.g. service account / agent id). */
  readonly agentId: string;
  /** RFC 3339 timestamp of when the action was observed. */
  readonly recordedAt: string;
  readonly actionType: ActionType;
  /** Tool/method name for tool_call and model_call; channel for agent_message. */
  readonly actionName: string;
  /** Hex SHA-256 of the canonicalized input payload. */
  readonly inputSha256: string;
  /** Hex SHA-256 of the canonicalized output payload, if any. */
  readonly outputSha256: string | null;
  /** Capture mode used for this record. */
  readonly capture: CaptureMode;
  /** Raw input, present only when capture === 'full'. */
  readonly inputCapture: string | null;
  /** Raw output, present only when capture === 'full'. */
  readonly outputCapture: string | null;
  readonly riskTier: RiskTier;
  readonly decision: PolicyDecision;
  /** Id of the policy rule that produced the decision. */
  readonly policyId: string;
  /** ISO 42001 (and future framework) control ids attached to the decision. */
  readonly controls: readonly string[];
  /** Human-readable justification for the decision. No raw payloads here. */
  readonly reason: string;
  /**
   * True when this record was buffered locally during a spine outage and later
   * flushed. Captured for transparency in the evidence itself.
   */
  readonly bufferedOffline: boolean;
}

/**
 * A persisted, hash-chained evidence record. `seq`, `prevHash`, and `recordHash`
 * are assigned by the spine and are never set by callers.
 */
export interface EvidenceRecord extends EvidenceInput {
  /** Monotonic 1-based sequence number. */
  readonly seq: number;
  /** Hex recordHash of the previous record, or GENESIS_HASH for seq 1. */
  readonly prevHash: string;
  /** Hex SHA-256 over the canonical record (all fields except recordHash). */
  readonly recordHash: string;
}

/** The all-zero hash that anchors the genesis record's prevHash. */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * A signed checkpoint (a "signed tree head" in CT terms): a Merkle root over the
 * first `treeSize` records, signed with the spine's Ed25519 key.
 */
export interface Checkpoint {
  /** Monotonic 1-based checkpoint id. */
  readonly id: number;
  /** Number of records covered by this checkpoint's Merkle tree. */
  readonly treeSize: number;
  /** Hex Merkle root (RFC 6962 tree hash) over records 1..treeSize. */
  readonly merkleRoot: string;
  readonly createdAt: string;
  /** Hex Ed25519 signature over the canonical checkpoint body. */
  readonly signature: string;
  /** Hex Ed25519 public key the signature verifies against. */
  readonly publicKey: string;
  /**
   * Optional key-version id of the signer that produced this checkpoint, for key
   * rotation. Additive and backward-compatible: legacy checkpoints omit it, and
   * it is NOT part of the signed bytes — verification uses `publicKey` +
   * `signature` only, so rotation never breaks verification of historical
   * checkpoints (each verifies against the key embedded in it).
   */
  readonly keyId?: string;
}

/** Outcome of a full or partial integrity verification pass. */
export interface VerificationResult {
  readonly ok: boolean;
  readonly recordsChecked: number;
  readonly checkpointsChecked: number;
  /** Human-readable failures; empty when ok is true. */
  readonly failures: readonly VerificationFailure[];
}

export type VerificationFailureKind =
  | 'record_hash_mismatch'
  | 'chain_link_mismatch'
  | 'sequence_gap'
  | 'checkpoint_root_mismatch'
  | 'checkpoint_signature_invalid'
  | 'empty_log';

export interface VerificationFailure {
  readonly kind: VerificationFailureKind;
  /** Sequence number or checkpoint id the failure concerns, when applicable. */
  readonly at: number | null;
  readonly detail: string;
}

/** A Merkle inclusion proof for a single record (RFC 6962 audit path). */
export interface InclusionProof {
  readonly leafIndex: number;
  readonly treeSize: number;
  /** Hex sibling hashes from leaf to root. */
  readonly auditPath: readonly string[];
  readonly merkleRoot: string;
}
