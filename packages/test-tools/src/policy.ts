/**
 * The governance policy for the live-demo tool surface, as a plain data document
 * (no engine dependency here). The CLI compiles it with the gateway's
 * `PolicyV0Engine`. It maps the real tools across the risk tiers so the live
 * proxy demonstrates allow / escalate / deny against actions that really do
 * something.
 */
export const LIVE_TOOLS_POLICY = {
  version: 0,
  description: 'Attestor live-demo policy — governs the real downstream tools.',
  defaultRule: {
    id: 'live.default.unknown',
    riskTier: 'T2',
    decision: 'escalate',
    capture: 'digest',
    controls: ['A.6.2.4', 'A.9.2'],
    reason: 'Unclassified tool call; escalate for human review (conservative default).',
  },
  rules: [
    {
      id: 'live.read_record.t1',
      actionType: 'tool_call',
      namePattern: '^read_record$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4', 'A.6.2.8'],
      reason: 'Read-only access to operator-owned case data.',
    },
    {
      id: 'live.compute_risk_score.t1',
      actionType: 'tool_call',
      namePattern: '^compute_risk_score$',
      riskTier: 'T1',
      decision: 'allow',
      capture: 'digest',
      controls: ['A.6.2.4'],
      reason: 'Read-only derivation over operator-owned data.',
    },
    {
      id: 'live.write_disposition.t2',
      actionType: 'tool_call',
      namePattern: '^write_disposition$',
      riskTier: 'T2',
      decision: 'allow',
      capture: 'full',
      controls: ['A.6.2.8', 'A.9.4'],
      reason: 'State-changing write within operator-owned systems (recorded before execution).',
    },
    {
      id: 'live.export_case_file.t3.escalate',
      actionType: 'tool_call',
      namePattern: '^export_case_file$',
      riskTier: 'T3',
      decision: 'escalate',
      capture: 'full',
      controls: ['A.9.2', 'A.10.4'],
      reason: 'Bulk case export requires human approval before proceeding.',
    },
    {
      id: 'live.purge_records.t3.deny',
      actionType: 'tool_call',
      namePattern: '^purge_records$',
      riskTier: 'T3',
      decision: 'deny',
      capture: 'digest',
      controls: ['A.9.2', 'A.6.2.8'],
      reason: 'Destructive bulk deletion blocked by policy.',
    },
  ],
};
