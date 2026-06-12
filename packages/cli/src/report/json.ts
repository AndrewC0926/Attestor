import type { AttestationReport } from './build.js';

/** Render the attestation report as stable, pretty-printed JSON. */
export function renderJson(report: AttestationReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
