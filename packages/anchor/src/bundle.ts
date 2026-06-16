import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Checkpoint, EvidenceRecord } from '@attestor/types';
import type { AnchorReceipt, AnchorStatus } from './anchor-store.js';

/**
 * A self-contained, portable evidence bundle. It carries everything a third
 * party needs to verify the log WITHOUT the live spine database and WITHOUT
 * trusting the operator: the records, the signed checkpoints, the external
 * anchor tokens, and the TSA trust anchors used to validate them.
 */
export interface BundleAnchor {
  readonly checkpointId: number;
  readonly treeSize: number;
  readonly merkleRoot: string;
  readonly status: AnchorStatus;
  readonly tsaName: string;
  readonly genTime: string | null;
  /** RFC 3161 timeStampToken (DER) base64, present when anchored. */
  readonly tokenBase64: string | null;
}

export interface AnchoredBundle {
  readonly version: 1;
  readonly exportedAt: string;
  readonly records: readonly EvidenceRecord[];
  readonly checkpoints: readonly Checkpoint[];
  readonly anchors: readonly BundleAnchor[];
  /** PEM trust anchors (TSA CA / cert) for offline token validation; may be empty. */
  readonly tsaCertsPem: readonly string[];
}

function toBundleAnchor(receipt: AnchorReceipt): BundleAnchor {
  return {
    checkpointId: receipt.checkpointId,
    treeSize: receipt.treeSize,
    merkleRoot: receipt.merkleRoot,
    status: receipt.status,
    tsaName: receipt.tsaName,
    genTime: receipt.genTime,
    tokenBase64: receipt.tokenBase64,
  };
}

/** Assemble a portable bundle from live evidence plus anchor receipts. */
export function exportBundle(args: {
  records: readonly EvidenceRecord[];
  checkpoints: readonly Checkpoint[];
  anchors: readonly AnchorReceipt[];
  tsaCertsPem?: readonly string[];
  now?: () => string;
}): AnchoredBundle {
  return {
    version: 1,
    exportedAt: (args.now ?? ((): string => new Date().toISOString()))(),
    records: args.records,
    checkpoints: args.checkpoints,
    anchors: args.anchors.map(toBundleAnchor),
    tsaCertsPem: args.tsaCertsPem ?? [],
  };
}

export function writeBundle(path: string, bundle: AnchoredBundle): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(bundle, null, 2), 'utf8');
}

export function readBundle(path: string): AnchoredBundle {
  return JSON.parse(readFileSync(path, 'utf8')) as AnchoredBundle;
}
