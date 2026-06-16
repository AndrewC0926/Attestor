import type { Checkpoint } from '@attestor/types';
import { AnchorStore, type AnchorReceipt } from './anchor-store.js';
import type { TsaClient } from './tsa-client.js';
import { verifyTimeStampToken } from './rfc3161.js';

/**
 * Anchors signed checkpoints to one or more external TSAs, asynchronously and
 * safely.
 *
 * The spine creates and signs a checkpoint synchronously; anchoring happens
 * AFTER, here, and never blocks that path. `enqueue` durably records a pending
 * receipt first, so a checkpoint can never be lost because a TSA was down.
 *
 * Redundancy: configure a PRIMARY plus ordered FALLBACK TSAs. An attempt tries
 * them in order and accepts the first token that SELF-VERIFIES against the
 * checkpoint root (`verifyTimeStampToken(token, root).ok` — which already
 * requires the token's messageImprint to equal the root, a valid signature, the
 * timestamping EKU, and chain-to-trust when certs are supplied). If EVERY TSA
 * fails, the receipt stays queued (status `failed`/`pending`) for a later retry
 * — it is never silently marked anchored and never lost.
 */
export interface AnchorLag {
  readonly anchored: number;
  readonly pending: number;
  readonly failed: number;
  /** Oldest not-yet-anchored checkpoint id, or null if fully caught up. */
  readonly oldestPendingCheckpointId: number | null;
  /** Age of that oldest unanchored checkpoint, in ms (by its createdAt). */
  readonly oldestPendingAgeMs: number | null;
}

export class AnchorService {
  private readonly clients: readonly TsaClient[];

  constructor(
    private readonly store: AnchorStore,
    clients: TsaClient | readonly TsaClient[],
  ) {
    this.clients = Array.isArray(clients) ? [...clients] : [clients];
    if (this.clients.length === 0) {
      throw new Error('AnchorService requires at least one TSA client');
    }
  }

  private get primary(): TsaClient {
    return this.clients[0] as TsaClient;
  }

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
      tsaName: this.primary.config.name,
      tsaUrl: this.primary.config.url,
      status: 'pending',
      tokenBase64: null,
      genTime: null,
      anchoredAt: null,
      error: null,
      attempts: 0,
    });
  }

  /** Queue then attempt to anchor a checkpoint (trying each TSA). Never throws. */
  async anchor(checkpoint: Checkpoint): Promise<AnchorReceipt> {
    this.enqueue(checkpoint);
    return this.attempt(checkpoint.id);
  }

  /** Retry every not-yet-anchored receipt across the TSA pool. */
  async processPending(): Promise<AnchorReceipt[]> {
    const results: AnchorReceipt[] = [];
    for (const receipt of [...this.store.pending()]) {
      results.push(await this.attempt(receipt.checkpointId));
    }
    return results;
  }

  /** Anchor lag: how far behind anchoring is (for monitoring/alarms). */
  lag(now: number = Date.now()): AnchorLag {
    const all = this.store.all();
    let oldestPendingCheckpointId: number | null = null;
    let oldestPendingAgeMs: number | null = null;
    for (const r of all) {
      if (r.status === 'anchored') {
        continue;
      }
      const t = Date.parse(r.checkpointCreatedAt);
      if (Number.isNaN(t)) {
        continue;
      }
      const age = now - t;
      if (oldestPendingAgeMs === null || age > oldestPendingAgeMs) {
        oldestPendingAgeMs = age;
        oldestPendingCheckpointId = r.checkpointId;
      }
    }
    return {
      anchored: all.filter((r) => r.status === 'anchored').length,
      pending: all.filter((r) => r.status === 'pending').length,
      failed: all.filter((r) => r.status === 'failed').length,
      oldestPendingCheckpointId,
      oldestPendingAgeMs,
    };
  }

  /** Union of every configured TSA's trust anchors, to bundle for offline verify. */
  trustedCertsPem(): string[] {
    const out: string[] = [];
    for (const client of this.clients) {
      for (const pem of client.config.certsPem ?? []) {
        if (!out.includes(pem)) {
          out.push(pem);
        }
      }
    }
    return out;
  }

  private async attempt(checkpointId: number): Promise<AnchorReceipt> {
    const receipt = this.store.get(checkpointId);
    if (!receipt) {
      throw new Error(`no anchor receipt for checkpoint ${checkpointId}`);
    }
    const digest = Buffer.from(receipt.merkleRoot, 'hex');
    const attempts = receipt.attempts + 1;
    const errors: string[] = [];

    for (const client of this.clients) {
      try {
        const token = await client.stamp(digest);
        // A response only counts as anchored if the token self-verifies AND its
        // messageImprint matches the checkpoint root (both are inside .ok).
        const verification = await verifyTimeStampToken(token, digest, client.config.certsPem ?? []);
        if (!verification.ok) {
          errors.push(`${client.config.name}: token failed self-verification (${verification.failures.join('; ')})`);
          continue;
        }
        return this.store.upsert({
          ...receipt,
          attempts,
          tsaName: client.config.name,
          tsaUrl: client.config.url,
          status: 'anchored',
          tokenBase64: token.toString('base64'),
          genTime: verification.genTime,
          anchoredAt: new Date().toISOString(),
          error: null,
        });
      } catch (err) {
        errors.push(`${client.config.name}: ${(err as Error).message}`);
      }
    }

    // Every TSA failed: keep the checkpoint queued for retry — never lost.
    return this.store.upsert({
      ...receipt,
      attempts,
      status: 'failed',
      error: errors.join(' | '),
    });
  }
}
