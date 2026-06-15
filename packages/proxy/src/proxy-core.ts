import type { EvidenceInput, EvidenceRecord, PolicyDecision, RiskTier } from '@attestor/types';
import { tierFailsClosed } from '@attestor/types';
import { sha256Hex } from '@attestor/spine';
import { canonicalJson, type EvidenceSink, type EvidenceBuffer } from '@attestor/gateway';
import type { PolicyEngine, PolicyResult } from '@attestor/gateway';

/**
 * The real-traffic hot path. This is what turns the prototype into a system
 * processing real agent traffic: every tool call an agent makes through the
 * Attestor MCP proxy is classified, recorded as evidence, and only then (if
 * allowed) forwarded to the real downstream tool.
 *
 * It REUSES the gateway's decision logic (the injected `PolicyEngine`) and the
 * spine (via the `EvidenceSink`); it does NOT reimplement classification. What
 * it owns is the ORDERING, which differs from `GatewayCore.handleToolCall` on
 * purpose:
 *
 *   - deny / escalate            → record the blocked attempt, NEVER forward.
 *   - allow, T2/T3 (fail-closed) → record an `authorized` event DURABLY BEFORE
 *                                  forwarding; if that write fails, DENY (no
 *                                  action without evidence); then forward; then
 *                                  record the `result`. Two records: the
 *                                  authorization is provable independently of
 *                                  the outcome — exactly what an examiner needs.
 *   - allow, T0/T1 (fail-open)   → forward, then record the result.
 *
 * LATENCY IMPLICATION: a T2/T3 action pays one durable evidence write (an fsync
 * to the spine) BEFORE the downstream call begins. That is the deliberate cost
 * of "no action without evidence" — reads (T0/T1) do not pay it.
 */

/** A tool invocation arriving at the proxy. */
export interface ProxyCall {
  readonly agentId: string;
  readonly toolName: string;
  readonly arguments: unknown;
}

/** Forwards an allowed call to the real downstream MCP tool. */
export type Forward = (call: ProxyCall) => Promise<unknown>;

export type ProxyErrorCode =
  | 'policy_denied'
  | 'escalation_required'
  | 'evidence_unavailable'
  | 'policy_unavailable'
  | 'downstream_unavailable';

export interface ProxyError {
  readonly code: ProxyErrorCode;
  readonly message: string;
  readonly reason: string;
}

/** What the proxy decided and did for one call. */
export interface ProxyOutcome {
  readonly allowed: boolean;
  /** Downstream result, present only when allowed and the forward succeeded. */
  readonly response?: unknown;
  readonly error?: ProxyError;
  readonly decision: PolicyDecision;
  readonly riskTier: RiskTier;
  /** Evidence appended for this call (0, 1, or 2 records). */
  readonly records: readonly EvidenceRecord[];
  /** True if a record could not be written and was buffered offline. */
  readonly buffered: boolean;
}

export interface ProxyCoreOptions {
  readonly now?: () => string;
  /** Bound the downstream call so a hung tool can never hang the proxy. */
  readonly forwardTimeoutMs?: number;
}

type Phase = 'blocked' | 'authorized' | 'executed';

/** Reject if `promise` does not settle within `ms`. */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

export class ProxyCore {
  private readonly now: () => string;
  private readonly forwardTimeoutMs: number;

  constructor(
    private readonly engine: PolicyEngine,
    private readonly sink: EvidenceSink,
    private readonly buffer: EvidenceBuffer | null = null,
    options: ProxyCoreOptions = {},
  ) {
    this.now = options.now ?? ((): string => new Date().toISOString());
    this.forwardTimeoutMs = options.forwardTimeoutMs ?? 10_000;
  }

  async handle(call: ProxyCall, forward: Forward): Promise<ProxyOutcome> {
    const argumentsJson = canonicalJson(call.arguments);
    const inputSha256 = sha256Hex(argumentsJson);

    const policy = await this.classify(call, argumentsJson);
    if (!policy) {
      // Cannot classify → fail closed, record the block, never forward.
      return this.block(
        unclassifiedPolicy(),
        call,
        inputSha256,
        argumentsJson,
        'policy_unavailable',
        'Policy engine unavailable; failing closed for an unclassifiable action.',
      );
    }

    if (policy.decision === 'deny' || policy.decision === 'escalate') {
      const code: ProxyErrorCode =
        policy.decision === 'deny' ? 'policy_denied' : 'escalation_required';
      const message =
        policy.decision === 'deny'
          ? `Action '${call.toolName}' denied by policy ${policy.policyId}.`
          : `Action '${call.toolName}' requires human approval (policy ${policy.policyId}).`;
      return this.block(policy, call, inputSha256, argumentsJson, code, message);
    }

    // Allowed.
    if (tierFailsClosed(policy.riskTier)) {
      return this.allowFailClosed(policy, call, inputSha256, argumentsJson, forward);
    }
    return this.allowFailOpen(policy, call, inputSha256, argumentsJson, forward);
  }

  private async classify(call: ProxyCall, argumentsJson: string): Promise<PolicyResult | null> {
    try {
      return await this.engine.evaluate({
        agentId: call.agentId,
        actionType: 'tool_call',
        actionName: call.toolName,
        argumentsJson,
      });
    } catch {
      return null;
    }
  }

  /** Record a blocked (deny/escalate/unclassified) attempt; never forward. */
  private async block(
    policy: PolicyResult,
    call: ProxyCall,
    inputSha256: string,
    argumentsJson: string,
    code: ProxyErrorCode,
    message: string,
  ): Promise<ProxyOutcome> {
    const { record, buffered } = await this.tryRecord(
      this.evidence('blocked', policy, call, inputSha256, argumentsJson, null),
    );
    return {
      allowed: false,
      error: { code, message, reason: policy.reason },
      decision: policy.decision,
      riskTier: policy.riskTier,
      records: record ? [record] : [],
      buffered,
    };
  }

  /**
   * T2/T3: record the authorization DURABLY before forwarding. If that write
   * fails, the action is denied (no action without evidence). Then forward, then
   * record the result.
   */
  private async allowFailClosed(
    policy: PolicyResult,
    call: ProxyCall,
    inputSha256: string,
    argumentsJson: string,
    forward: Forward,
  ): Promise<ProxyOutcome> {
    let authorized: EvidenceRecord;
    try {
      authorized = await this.sink.append(
        this.evidence('authorized', policy, call, inputSha256, argumentsJson, null),
      );
    } catch {
      // Fail-closed: we could not durably record the authorization, so the
      // action must not happen. Best-effort buffer the denied attempt.
      this.buffer?.add({
        ...this.evidence('blocked', policy, call, inputSha256, argumentsJson, null),
        bufferedOffline: true,
      });
      return {
        allowed: false,
        error: {
          code: 'evidence_unavailable',
          message: `Action '${call.toolName}' blocked: evidence store unreachable and tier ${policy.riskTier} fails closed.`,
          reason: 'Tier T2/T3 actions are denied when their authorization cannot be recorded.',
        },
        decision: 'deny',
        riskTier: policy.riskTier,
        records: [],
        buffered: true,
      };
    }

    // Authorization is on the ledger; now perform the action.
    try {
      const output = await withTimeout(forward(call), this.forwardTimeoutMs, call.toolName);
      const { record, buffered } = await this.tryRecord(
        this.evidence('executed', policy, call, inputSha256, argumentsJson, output),
      );
      return {
        allowed: true,
        response: output,
        decision: policy.decision,
        riskTier: policy.riskTier,
        records: record ? [authorized, record] : [authorized],
        buffered,
      };
    } catch (err) {
      // Downstream failed AFTER authorization: record the failed result so the
      // chain reflects exactly what happened; return a clean error, never hang.
      const { record } = await this.tryRecord(
        this.evidence('executed', policy, call, inputSha256, argumentsJson, null, errMessage(err)),
      );
      return {
        allowed: false,
        error: {
          code: 'downstream_unavailable',
          message: `Action '${call.toolName}' was authorized and recorded, but the downstream tool failed: ${errMessage(err)}`,
          reason: 'Downstream tool unreachable or timed out.',
        },
        decision: policy.decision,
        riskTier: policy.riskTier,
        records: record ? [authorized, record] : [authorized],
        buffered: false,
      };
    }
  }

  /** T0/T1: fail-open reads — forward first, then record (recording may lag). */
  private async allowFailOpen(
    policy: PolicyResult,
    call: ProxyCall,
    inputSha256: string,
    argumentsJson: string,
    forward: Forward,
  ): Promise<ProxyOutcome> {
    try {
      const output = await withTimeout(forward(call), this.forwardTimeoutMs, call.toolName);
      const { record, buffered } = await this.tryRecord(
        this.evidence('executed', policy, call, inputSha256, argumentsJson, output),
      );
      return {
        allowed: true,
        response: output,
        decision: policy.decision,
        riskTier: policy.riskTier,
        records: record ? [record] : [],
        buffered,
      };
    } catch (err) {
      const { record } = await this.tryRecord(
        this.evidence('executed', policy, call, inputSha256, argumentsJson, null, errMessage(err)),
      );
      return {
        allowed: false,
        error: {
          code: 'downstream_unavailable',
          message: `Action '${call.toolName}' failed: ${errMessage(err)}`,
          reason: 'Downstream tool unreachable or timed out.',
        },
        decision: policy.decision,
        riskTier: policy.riskTier,
        records: record ? [record] : [],
        buffered: false,
      };
    }
  }

  /** Append an evidence record, falling back to the offline buffer on failure. */
  private async tryRecord(
    input: EvidenceInput,
  ): Promise<{ record: EvidenceRecord | null; buffered: boolean }> {
    try {
      return { record: await this.sink.append(input), buffered: false };
    } catch {
      this.buffer?.add({ ...input, bufferedOffline: true });
      return { record: null, buffered: true };
    }
  }

  /** Build the evidence record for a given phase of one call. */
  private evidence(
    phase: Phase,
    policy: PolicyResult,
    call: ProxyCall,
    inputSha256: string,
    argumentsJson: string,
    output: unknown,
    failure?: string,
  ): EvidenceInput {
    const hasOutput = output !== null && output !== undefined;
    const outputJson = hasOutput ? canonicalJson(output) : null;
    const full = policy.capture === 'full';
    const phaseNote =
      phase === 'authorized'
        ? ' [authorized — recorded before execution]'
        : phase === 'executed'
          ? failure
            ? ` [execution failed: ${failure}]`
            : ' [executed]'
          : '';
    return {
      agentId: call.agentId,
      recordedAt: this.now(),
      actionType: 'tool_call',
      actionName: call.toolName,
      inputSha256,
      outputSha256: outputJson ? sha256Hex(outputJson) : null,
      capture: policy.capture,
      inputCapture: full ? argumentsJson : null,
      outputCapture: full ? outputJson : null,
      riskTier: policy.riskTier,
      decision: policy.decision,
      policyId: policy.policyId,
      controls: policy.controls,
      reason: `${policy.reason}${phaseNote}`,
      bufferedOffline: false,
    };
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function unclassifiedPolicy(): PolicyResult {
  return {
    decision: 'deny',
    riskTier: 'T3',
    policyId: 'engine.unavailable',
    controls: [],
    reason: 'Policy engine unavailable; failing closed for an unclassifiable action.',
    capture: 'digest',
  };
}
