import type { EvidenceRecord } from '@attestor/types';
import type { AttestationReport } from './build.js';

const short = (hash: string): string => `${hash.slice(0, 12)}…`;

const decisionMark = (record: EvidenceRecord): string => {
  switch (record.decision) {
    case 'allow':
      return '✅ allow';
    case 'deny':
      return '⛔ deny';
    case 'escalate':
      return '⚠️ escalate';
  }
};

function integritySection(report: AttestationReport): string {
  const i = report.integrity;
  const lines: string[] = [];
  lines.push('## Chain integrity');
  lines.push('');
  lines.push(`**Result:** ${i.ok ? '✅ VERIFIED — log is intact' : '❌ FAILED — tampering detected'}`);
  lines.push('');
  lines.push(`- Records checked: ${i.recordsChecked}`);
  lines.push(`- Signed checkpoints checked: ${i.checkpointsChecked}`);
  if (i.latestCheckpoint) {
    lines.push(`- Latest signed Merkle root (size ${i.latestCheckpoint.treeSize}): \`${i.latestCheckpoint.merkleRoot}\``);
    lines.push(`- Checkpoint signed at: ${i.latestCheckpoint.createdAt}`);
    lines.push(`- Signing public key: \`${short(i.latestCheckpoint.publicKey)}\``);
  }
  if (!i.ok) {
    lines.push('');
    lines.push('### Integrity failures');
    lines.push('');
    lines.push('| Kind | At | Detail |');
    lines.push('| --- | --- | --- |');
    for (const f of i.failures) {
      lines.push(`| ${f.kind} | ${f.at ?? '—'} | ${f.detail} |`);
    }
  }
  return lines.join('\n');
}

function summarySection(report: AttestationReport): string {
  const t = report.totals;
  const tierRow = Object.entries(t.byTier)
    .map(([tier, n]) => `${tier}: ${n}`)
    .join(', ');
  const decisionRow = Object.entries(t.byDecision)
    .map(([d, n]) => `${d}: ${n}`)
    .join(', ');
  return [
    '## Summary',
    '',
    `- Evidence records in range: **${t.records}**`,
    `- By risk tier: ${tierRow}`,
    `- By decision: ${decisionRow}`,
    `- Recorded while offline (buffered, later flushed): ${t.bufferedOffline}`,
  ].join('\n');
}

function controlSection(report: AttestationReport): string {
  const lines: string[] = ['## Control coverage', '', `Framework: **${report.framework}**`, ''];
  if (report.controlCoverage.length === 0) {
    lines.push('_No control-mapped actions in range._');
    return lines.join('\n');
  }
  lines.push('| Control | Actions evidenced |');
  lines.push('| --- | --- |');
  for (const c of report.controlCoverage) {
    lines.push(`| ${c.title} | ${c.count} |`);
  }
  return lines.join('\n');
}

function trailSection(report: AttestationReport): string {
  const lines: string[] = ['## Incident trail', ''];
  lines.push('| Seq | Recorded (UTC) | Agent | Action | Tier | Decision | Policy | Controls | Input SHA-256 | Output SHA-256 |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |');
  for (const r of report.records) {
    lines.push(
      `| ${r.seq} | ${r.recordedAt} | ${r.agentId} | \`${r.actionName}\` | ${r.riskTier} | ${decisionMark(r)} | ${r.policyId} | ${r.controls.join(', ') || '—'} | \`${short(r.inputSha256)}\` | ${r.outputSha256 ? `\`${short(r.outputSha256)}\`` : '—'} |`,
    );
  }
  return lines.join('\n');
}

/** Render a human-readable Markdown compliance report. */
export function renderMarkdown(report: AttestationReport): string {
  const range =
    report.from || report.to
      ? `${report.from ?? 'beginning'} → ${report.to ?? 'now'}`
      : 'full history';
  return [
    '# Attestor Compliance Attestation',
    '',
    `Generated: ${report.generatedAt}  `,
    `Range: ${range}`,
    '',
    'This report is generated from a hash-chained, append-only evidence log with',
    'signed Merkle checkpoints. By default only SHA-256 digests of inputs and',
    'outputs are retained (privacy by design); raw payloads appear only where a',
    'policy explicitly opted into full capture.',
    '',
    integritySection(report),
    '',
    summarySection(report),
    '',
    controlSection(report),
    '',
    trailSection(report),
    '',
  ].join('\n');
}
