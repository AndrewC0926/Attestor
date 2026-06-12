import type {
  ActionType,
  CaptureMode,
  PolicyDecision,
  RiskTier,
} from '@attestor/types';

/** What the engine is asked to decide about. */
export interface PolicyInput {
  readonly agentId: string;
  readonly actionType: ActionType;
  /** Tool/method name, e.g. "payments.transfer". */
  readonly actionName: string;
  /** Canonical JSON of the call arguments (used for matching and hashing). */
  readonly argumentsJson: string;
}

/** The engine's verdict for a single action. */
export interface PolicyResult {
  readonly decision: PolicyDecision;
  readonly riskTier: RiskTier;
  /** Id of the rule that produced this verdict. */
  readonly policyId: string;
  readonly controls: readonly string[];
  readonly reason: string;
  /** Whether to retain raw payloads for this action (privacy opt-in). */
  readonly capture: CaptureMode;
}

/**
 * The policy evaluation interface. v0 is a local, synchronous rule engine, but
 * the method is async so a networked engine (OPA / Cedar) can be slotted in
 * behind the same interface in Phase 2 without changing the gateway.
 */
export interface PolicyEngine {
  readonly name: string;
  evaluate(input: PolicyInput): Promise<PolicyResult>;
}
