import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** Lifecycle of an anchor: queued, externally anchored, or failed (a flagged gap). */
export type AnchorStatus = 'pending' | 'anchored' | 'failed';

/**
 * A durable record of a checkpoint's external anchor. Stored in a sidecar file
 * owned by the anchor layer — never in the spine's database — so anchoring is
 * strictly additive. A `pending`/`failed` receipt is the flagged gap that lets
 * us retry later without ever losing a checkpoint.
 */
export interface AnchorReceipt {
  readonly checkpointId: number;
  readonly treeSize: number;
  /** Hex Merkle root that was (or will be) anchored. */
  readonly merkleRoot: string;
  readonly checkpointCreatedAt: string;
  readonly tsaName: string;
  readonly tsaUrl: string;
  status: AnchorStatus;
  /** RFC 3161 timeStampToken (DER), base64 — present once anchored. */
  tokenBase64: string | null;
  /** The TSA's asserted timestamp, once anchored. */
  genTime: string | null;
  /** When we recorded the anchor locally. */
  anchoredAt: string | null;
  /** Last failure reason, when status is `failed`. */
  error: string | null;
  attempts: number;
}

interface AnchorFile {
  readonly version: 1;
  receipts: AnchorReceipt[];
}

/**
 * A tiny durable store for anchor receipts, persisted as a single JSON file
 * under `<dir>/anchors/anchors.json`. Append/replace by checkpoint id.
 */
export class AnchorStore {
  private readonly path: string;
  private file: AnchorFile;

  constructor(dir: string) {
    this.path = join(dir, 'anchors', 'anchors.json');
    this.file = existsSync(this.path)
      ? (JSON.parse(readFileSync(this.path, 'utf8')) as AnchorFile)
      : { version: 1, receipts: [] };
  }

  private flush(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.file, null, 2), 'utf8');
  }

  get(checkpointId: number): AnchorReceipt | undefined {
    return this.file.receipts.find((r) => r.checkpointId === checkpointId);
  }

  all(): readonly AnchorReceipt[] {
    return this.file.receipts;
  }

  pending(): readonly AnchorReceipt[] {
    return this.file.receipts.filter((r) => r.status !== 'anchored');
  }

  /** Insert or replace a receipt (by checkpoint id) and persist. */
  upsert(receipt: AnchorReceipt): AnchorReceipt {
    const idx = this.file.receipts.findIndex((r) => r.checkpointId === receipt.checkpointId);
    if (idx >= 0) {
      this.file.receipts[idx] = receipt;
    } else {
      this.file.receipts.push(receipt);
    }
    this.flush();
    return receipt;
  }
}
