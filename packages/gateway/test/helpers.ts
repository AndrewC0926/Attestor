import type { EvidenceInput, EvidenceRecord } from '@attestor/types';
import type { EvidenceSink } from '../src/sink.js';

/** Controllable in-memory sink for exercising outage behaviour. */
export class FakeSink implements EvidenceSink {
  up = true;
  appendFails = false;
  readonly appended: EvidenceInput[] = [];
  private seq = 0;

  healthy(): Promise<boolean> {
    return Promise.resolve(this.up);
  }

  append(input: EvidenceInput): Promise<EvidenceRecord> {
    if (this.appendFails) {
      return Promise.reject(new Error('evidence store unreachable'));
    }
    this.seq += 1;
    this.appended.push(input);
    return Promise.resolve({
      ...input,
      seq: this.seq,
      prevHash: '0'.repeat(64),
      recordHash: 'f'.repeat(64),
    });
  }
}

/** Records each forwarded call so tests can assert what reached downstream. */
export function trackingForward(): {
  calls: string[];
  fn: (call: { toolName: string }) => Promise<unknown>;
} {
  const calls: string[] = [];
  return {
    calls,
    fn: (call): Promise<unknown> => {
      calls.push(call.toolName);
      return Promise.resolve({ content: [{ type: 'text', text: 'ok' }] });
    },
  };
}
