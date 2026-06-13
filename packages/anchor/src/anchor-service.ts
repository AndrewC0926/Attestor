import type { Checkpoint } from '@attestor/types';
import { AnchorStore, type AnchorReceipt } from './anchor-store.js';
import type { TsaClient } from './tsa-client.js';
import { verifyTimeStampToken } from './rfc3161.js';

/**
 * Anchors signed checkpoints to an external TSA, asynchronously and safely.
 *
 * The spine creates and signs a checkpoint synchronously; anchoring happens
 * AFTER, here, and never blocks that path. `enqueue` durably records a pending
 * receipt first, so a checkpoint can never be lost because the TSA was down —
 * a failed attempt simply stays queued (a flagged gap) for a later retry.
 */
export class AnchorService {
  constructor(
    private readonly store: AnchorStore,
    private readonly client: TsaClient,
  ) {}

  /** Durably queue a checkpoint for anchoring (synchronous, no network). */
  enqueue(checkpoint: Checkpoint): AnchorReceipt {
    const existing = this.store.get(checkpoint.id);
    if (existing) {
      return existing;
    }
    return this.store.upsert({
      checkpointId: checkpoint.id,
      treeSize: checkpoint.treeSize,
      merkleRoot: checkpoint.merkleRoot,
      checkpointCreatedAt: checkpoint.createdAt,
      tsaName: this.client.config.name,
      tsaUrl: this.client.config.url,
      status: 'pending',
      tokenBase64: null,
      genTime: null,
      anchoredAt: null,
      error: null,
      attempts: 0,
    });
  }

  /** Queue then attempt to anchor a checkpoint. Never throws. */
  async anchor(checkpoint: Checkpoint): Promise<AnchorReceipt> {
    this.enqueue(checkpoint);
    return this.attempt(checkpoint.id);
  }

  /** Retry every not-yet-anchored receipt. Returns the updated receipts. */
  async processPending(): Promise<AnchorReceipt[]> {
    const results: AnchorReceipt[] = [];
    for (const receipt of [...this.store.pending()]) {
      results.push(await this.attempt(receipt.checkpointId));
    }
    return results;
  }

  private async attempt(checkpointId: number): Promise<AnchorReceipt> {
    const receipt = this.store.get(checkpointId);
    if (!receipt) {
      throw new Error(`no anchor receipt for checkpoint ${checkpointId}`);
    }
    const digest = Buffer.from(receipt.merkleRoot, 'hex');
    const next: AnchorReceipt = { ...receipt, attempts: receipt.attempts + 1 };
    try {
      const token = await this.client.stamp(digest);
      // Sanity-check the token we just received before trusting it.
      const verification = await verifyTimeStampToken(token, digest);
      next.status = 'anchored';
      next.tokenBase64 = token.toString('base64');
      next.genTime = verification.genTime;
      next.anchoredAt = new Date().toISOString();
      next.error = verification.ok
        ? null
        : `token received but self-check failed: ${verification.failures.join('; ')}`;
    } catch (err) {
      next.status = 'failed';
      next.error = (err as Error).message;
    }
    return this.store.upsert(next);
  }
}
