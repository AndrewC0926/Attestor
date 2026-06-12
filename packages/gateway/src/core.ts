import type { EvidenceInput, EvidenceRecord, RiskTier } from '@attestor/types';
import { tierFailsClosed } from '@attestor/types';
import { sha256Hex } from '@attestor/spine';
import { canonicalJson } from './canonical-json.js';
import type { PolicyEngine, PolicyResult } from './policy/types.js';
import type { EvidenceSink } from './sink.js';
import type { EvidenceBuffer } from './buffer.js';

/** A tool invocation observed by the gateway. */
export interface ToolCall {
  readonly agentId: string;
  readonly toolName: string;
  readonly arguments: unknown;
}

/** Forwards an allowed call to the downstream MCP server and returns its result. */
export type ForwardFn = (call: ToolCall) => Promise<unknown>;

export type GatewayErrorCode =
  | 'policy_denied'
  | 'escalation_required'
  | 'evidence_unavailable'
  | 'policy_unavailable';

export interface GatewayError {
  readonly code: GatewayErrorCode;
  readonly message: string;
  readonly reason: string;
}

export interface GatewayDecision {
  readonly allowed: boolean;
  /** Downstream result, present only when allowed. */
  readonly response?: unknown;
  /** Structured error returned to the agent, present only when blocked. */
  readonly error?: GatewayError;
  /** The appended evidence record, or null when buffered during an outage. */
  readonly record: EvidenceRecord | null;
  readonly policy: PolicyResult;
  readonly bufferedOffline: boolean;
}

export interface GatewayCoreOptions {
  readonly now?: () => string;
}

/**
 * Transport-agnostic audit core. Given a tool call and a way to forward it, it
 * classifies the call, enforces the policy decision, records signed evidence,
 * and applies the fail-open (T0/T1) / fail-closed (T2/T3) contract when the
 * evidence store is unreachable. All MCP transports wrap this one method.
 */
export class GatewayCore {
  private readonly now: () => string;

  constructor(
    private readonly engine: PolicyEngine,
    private readonly sink: EvidenceSink,
    private readonly buffer: EvidenceBuffer,
    options: GatewayCoreOptions = {},
  ) {
    this.now = options.now ?? ((): string => new Date().toISOString());
  }

  async handleToolCall(call: ToolCall, forward: ForwardFn): Promise<GatewayDecision> {
    const argumentsJson = canonicalJson(call.arguments);
    const inputSha256 = sha256Hex(argumentsJson);

    // Opportunistically drain the buffer when the store is reachable again.
    let storeUp = await this.sink.healthy();
    if (storeUp && this.buffer.size() > 0) {
      try {
        await this.buffer.flush(this.sink);
      } catch {
        storeUp = false;
      }
    }

    const policy = await this.classify(call, argumentsJson);
    if (!policy) {
      // Cannot classify: fail closed, treat as highest tier, record the block.
      return this.blockUnclassified(call, inputSha256, argumentsJson, storeUp);
    }

    if (policy.decision === 'deny' || policy.decision === 'escalate') {
      return this.blockByPolicy(policy, call, inputSha256, argumentsJson, storeUp);
    }

    return this.allow(policy, call, inputSha256, argumentsJson, storeUp, forward);
  }

  private async classify(
    call: ToolCall,
    argumentsJson: string,
  ): Promise<PolicyResult | null> {
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

  /** Persist an evidence record, falling back to the local buffer on outage. */
  private async record(
    input: EvidenceInput,
    storeUp: boolean,
  ): Promise<{ record: EvidenceRecord | null; buffered: boolean }> {
    if (storeUp) {
      try {
        return { record: await this.sink.append(input), buffered: false };
      } catch {
        // Store died between the health probe and the write.
      }
    }
    this.buffer.add({ ...input, bufferedOffline: true });
    return { record: null, buffered: true };
  }

  private buildEvidence(args: {
    policy: PolicyResult;
    call: ToolCall;
    inputSha256: string;
    argumentsJson: string;
    outputSha256: string | null;
    outputJson: string | null;
    decisionReasonSuffix?: string;
  }): EvidenceInput {
    const { policy, call, inputSha256, argumentsJson, outputSha256, outputJson } = args;
    const full = policy.capture === 'full';
    return {
      agentId: call.agentId,
      recordedAt: this.now(),
      actionType: 'tool_call',
      actionName: call.toolName,
      inputSha256,
      outputSha256,
      capture: policy.capture,
      inputCapture: full ? argumentsJson : null,
      outputCapture: full ? outputJson : null,
      riskTier: policy.riskTier,
      decision: policy.decision,
      policyId: policy.policyId,
      controls: policy.controls,
      reason: args.decisionReasonSuffix
        ? `${policy.reason} ${args.decisionReasonSuffix}`
        : policy.reason,
      bufferedOffline: false,
    };
  }

  private async blockByPolicy(
    policy: PolicyResult,
    call: ToolCall,
    inputSha256: string,
    argumentsJson: string,
    storeUp: boolean,
  ): Promise<GatewayDecision> {
    // Denied/escalated calls are NEVER forwarded downstream.
    const input = this.buildEvidence({
      policy,
      call,
      inputSha256,
      argumentsJson,
      outputSha256: null,
      outputJson: null,
    });
    const { record, buffered } = await this.record(input, storeUp);
    const code: GatewayErrorCode =
      policy.decision === 'deny' ? 'policy_denied' : 'escalation_required';
    return {
      allowed: false,
      error: {
        code,
        message:
          policy.decision === 'deny'
            ? `Action '${call.toolName}' denied by policy ${policy.policyId}.`
            : `Action '${call.toolName}' requires human approval (policy ${policy.policyId}).`,
        reason: policy.reason,
      },
      record,
      policy,
      bufferedOffline: buffered,
    };
  }

  private async allow(
    policy: PolicyResult,
    call: ToolCall,
    inputSha256: string,
    argumentsJson: string,
    storeUp: boolean,
    forward: ForwardFn,
  ): Promise<GatewayDecision> {
    // Fail-closed contract: a T2/T3 action must not run if we cannot record it.
    if (!storeUp && tierFailsClosed(policy.riskTier)) {
      const input: EvidenceInput = {
        ...this.buildEvidence({
          policy,
          call,
          inputSha256,
          argumentsJson,
          outputSha256: null,
          outputJson: null,
          decisionReasonSuffix: '[blocked: evidence store unreachable]',
        }),
        bufferedOffline: true,
      };
      this.buffer.add(input);
      return {
        allowed: false,
        error: {
          code: 'evidence_unavailable',
          message: `Action '${call.toolName}' blocked: evidence store unreachable and tier ${policy.riskTier} fails closed.`,
          reason: 'Tier T2/T3 actions are blocked when evidence cannot be recorded.',
        },
        record: null,
        policy,
        bufferedOffline: true,
      };
    }

    // T0/T1 fail open (or store healthy): perform the action, then record.
    const output = await forward(call);
    const outputJson = canonicalJson(output);
    const outputSha256 = sha256Hex(outputJson);
    const input = this.buildEvidence({
      policy,
      call,
      inputSha256,
      argumentsJson,
      outputSha256,
      outputJson,
    });
    const { record, buffered } = await this.record(input, storeUp);
    return {
      allowed: true,
      response: output,
      record,
      policy,
      bufferedOffline: buffered,
    };
  }

  private async blockUnclassified(
    call: ToolCall,
    inputSha256: string,
    argumentsJson: string,
    storeUp: boolean,
  ): Promise<GatewayDecision> {
    const tier: RiskTier = 'T3';
    const policy: PolicyResult = {
      decision: 'deny',
      riskTier: tier,
      policyId: 'engine.unavailable',
      controls: [],
      reason: 'Policy engine unavailable; failing closed for an unclassifiable action.',
      capture: 'digest',
    };
    const input = this.buildEvidence({
      policy,
      call,
      inputSha256,
      argumentsJson,
      outputSha256: null,
      outputJson: null,
    });
    const { record, buffered } = await this.record(input, storeUp);
    return {
      allowed: false,
      error: {
        code: 'policy_unavailable',
        message: `Action '${call.toolName}' blocked: policy engine unavailable.`,
        reason: policy.reason,
      },
      record,
      policy,
      bufferedOffline: buffered,
    };
  }
}
