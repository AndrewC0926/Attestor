import type { EvidenceInput } from '@attestor/types';

let clock = 0;

/** Deterministic evidence input for tests; override any field as needed. */
export function makeInput(overrides: Partial<EvidenceInput> = {}): EvidenceInput {
  clock += 1;
  return {
    agentId: 'agent-test',
    recordedAt: `2026-01-01T00:00:${String(clock).padStart(2, '0')}.000Z`,
    actionType: 'tool_call',
    actionName: 'fs.read',
    inputSha256: 'a'.repeat(64),
    outputSha256: 'b'.repeat(64),
    capture: 'digest',
    inputCapture: null,
    outputCapture: null,
    riskTier: 'T1',
    decision: 'allow',
    policyId: 'rule.test',
    controls: ['A.6.2.4'],
    reason: 'test record',
    bufferedOffline: false,
    ...overrides,
  };
}

/** A fixed clock factory for deterministic checkpoint timestamps. */
export function fixedClock(iso = '2026-01-01T00:00:00.000Z'): () => string {
  return () => iso;
}
