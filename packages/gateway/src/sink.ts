import type { EvidenceInput, EvidenceRecord } from '@attestor/types';
import type { Spine } from '@attestor/spine';

/**
 * The evidence sink the gateway writes to. Abstracting the spine behind this
 * interface lets the fail-open/fail-closed logic be tested by simulating an
 * unreachable evidence store without a database.
 */
export interface EvidenceSink {
  append(input: EvidenceInput): Promise<EvidenceRecord>;
  /** Cheap liveness probe used to decide fail-open vs fail-closed behaviour. */
  healthy(): Promise<boolean>;
}

/** Adapts a Spine to the EvidenceSink interface. */
export class SpineEvidenceSink implements EvidenceSink {
  constructor(private readonly spine: Spine) {}

  append(input: EvidenceInput): Promise<EvidenceRecord> {
    return this.spine.append(input);
  }

  async healthy(): Promise<boolean> {
    try {
      await this.spine.count();
      return true;
    } catch {
      return false;
    }
  }
}
