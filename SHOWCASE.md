# Attestor Showcase — governance you can watch

Purpose-built demos that make Attestor's governance **visible**: a single MCP
agent works a realistic task through the *existing* Attestor gateway and spine,
and you watch **allow / escalate / deny** happen live — then replay the whole
thing from the signed evidence and prove, on screen, that it is tamper-evident.

> Everything here is **simulated**. No real CRM, no real payments, no real
> customer data, no real money. The point is to exercise the governance path,
> not to do work. This is an **additive demo layer** (`packages/showcase` + one
> `attestor` subcommand); it does not modify the spine or the gateway core.

## Scenarios

Pick a scenario with `--scenario <id>` (default `support-desk`):

**`support-desk`** — a customer-support agent working a disputed-charge ticket:

| Tool | Tier | Decision |
|------|------|----------|
| `read_ticket` | T0 | allow |
| `post_reply` | T1 | allow |
| `update_customer_record` | T2 | allow |
| `issue_refund` | T3 | **allow ≤ $500, escalate > $500** (argument-aware) |
| `delete_account` | T3 | **deny** |
| `export_customer_data` | T3 | **deny** |

**`finance`** — a treasury-ops agent running a month-end settlement:

| Tool | Tier | Decision |
|------|------|----------|
| `check_balance` | T0 | allow |
| `categorize_transaction` | T1 | allow |
| `move_funds` | T3 | **allow ≤ $10,000, escalate > $10,000** (argument-aware) |
| `wire_external` | T3 | **deny** |
| `pull_full_ledger` | T3 | **deny** |

**`aml`** — a BSA/AML investigation agent working a transaction-monitoring alert
(examined against the FFIEC BSA/AML manual standard):

| Tool | Tier | Decision |
|------|------|----------|
| `review_alert` | T0 | allow |
| `pull_customer_profile` | T1 | allow |
| `screen_sanctions_pep` | T1 | allow |
| `dismiss_alert` | T2 | allow (auditable disposition + rationale) |
| `report_ctr` | T3 | **none ≤ $10,000, MANDATORY CTR > $10,000** (argument-aware) |
| `file_sar` | T3 | **escalate** — requires BSA officer authorization |
| `notify_customer_of_sar` | T3 | **deny** — illegal "tipping off" |

  The AML run models the real workflow: L1 triage, L2 enhanced due diligence
  (KYC, sanctions/PEP/adverse-media), clearing a transliteration false-positive
  leg with a recorded rationale, the routine **mandatory CTR** (FinCEN Form 112,
  31 CFR 1010.311) for cash over $10,000, the discretionary **SAR** (FinCEN Form
  111) escalating to a BSA officer, and the gateway **blocking an illegal tipping-
  off attempt** with the regulatory rationale on the record. Controls cite the
  actual BSA/AML obligations (SAR, CTR, 5-year recordkeeping). The CTR is the
  *mandatory* threshold (distinct from the discretionary, confidential SAR).

- Each argument-aware threshold (`issue_refund`, `move_funds`, `report_ctr`) is
  enforced by an additive policy engine built on the shared
  `createAmountAwarePolicyEngine` helper, layered on the product's name-pattern
  `PolicyV0Engine` — the same `PolicyEngine` extension point a real OPA/Cedar
  engine would use. The product policy set is untouched, and the scenarios share
  no mutable state. `--replay`, `--prove-tamper`, and `--anchor` are
  scenario-agnostic and work with all of them.
- Every action becomes a **signed, hash-chained evidence record** in the same
  spine as Phase 1, written to an **isolated store** (`.attestor/showcase/`,
  reset at the start of each run) so it never collides with `attestor demo`.

## Live demo — REAL MCP interception (not scripted)

The scenarios above feed *scripted* calls through the gateway. `attestor
live-demo` replaces that scripted boundary with **real MCP traffic**: a real MCP
agent connects to the **Attestor proxy** over real Streamable HTTP; the proxy
fronts **real downstream tools** running as a spawned stdio subprocess (real
file/compute side effects in a sandbox). The agent is handed **only** the proxy
transport — it cannot reach the tools except through Attestor (a true
man-in-the-middle, not a cooperative wrapper).

```bash
attestor live-demo            # real agent → Attestor proxy → real tools
attestor live-demo --anchor   # …then anchor the evidence to a TSA
```

Hot path (a real product decision, in `packages/proxy`):

- **deny / escalate** → record the blocked attempt, **never forward**.
- **allow, T2/T3** → record an `authorized` event **durably before** forwarding
  (if that write fails, the action is **DENIED** — no action without evidence);
  then forward; then record the `result`. Two records separate the
  *authorization* from the *execution* — exactly what an examiner needs.
  (Latency: a T2/T3 action pays one durable evidence write before it runs.)
- **allow, T0/T1** → forward, then record (reads don't pay the write up front).
- Downstream timeout/unreachable is bounded, recorded, and returned as a clean
  MCP error — it never hangs and never corrupts the chain.

The run prints the agent transcript (allow / escalate / deny), the real
evidence summary, and **proof the boundary is real**: the allowed `write_disposition`
file exists, while the case records are intact because `purge_records` was
denied. The evidence passes the **same `verify` / inclusion / `--anchor`** path
as the showcase. It reuses the gateway's decision logic and the spine verbatim;
the spine and gateway core are unchanged.

## Run it

```bash
npm run build                         # first time (or after changes)
attestor showcase                     # support-desk (default)
attestor showcase --scenario finance  # the finance agent
```

You'll see each action's **tier, decision, and evidence record id** as it
happens (finance shown):

```
   3. move_funds               T3  ✅ ALLOW     → evidence #3 (90376a853cbc…)
      Agent moves $5,000 internally (within the auto-approval limit)
      ↳ Transfer of $5000 is within the $10000 auto-approval limit.
   4. move_funds               T3  ⚠️  ESCALATE  → evidence #4 (91e08cee782b…)
      Agent attempts a $25,000 internal move (over the limit → escalates)
      ↳ Transfer of $25000 exceeds the $10000 auto-approval limit; escalating for human approval.
   5. wire_external            T3  ⛔ DENY      → evidence #5 (d0b7572ae257…)
```

Denied and escalated calls are **never forwarded** to the tool server — they are
blocked at the gateway and recorded with no downstream output.

## Replay — reconstruct the account from the evidence alone

```bash
attestor showcase --replay
```

This reads **only the signed evidence store** (never the scenario script),
verifies the chain, and prints the ordered account: what the agent did, how each
action was classified and decided, the input digest, and the record hash.
Records whose policy opted into `capture: full` (the refunds and the export)
also show their retained payload; everything else is digest-only by design.

## Prove it is tamper-evident — built in

The fastest way: one flag runs the scenario and then the full
tamper→detect→restore cycle on screen, with no hand-typed commands.

```bash
attestor showcase --scenario finance --prove-tamper
```

```
— Built-in tamper proof (live, no hand-typed commands) —

  1) verify on fresh evidence      : ✅ VERIFIED — 6 records, 2 signed checkpoints, chain intact.
  2) tamper: flipped exactly 1 byte of evidence #3 (move_funds) — input_sha256 5616b312… → 4616b312…
  3) verify after tamper           : ❌ FAILED — 1 issue(s) detected:
        • [record_hash_mismatch] at 3: record content does not match its stored hash
  4) restore: reverted the byte of evidence #3 (XOR is its own inverse)
  5) verify after restore          : ✅ VERIFIED — 6 records, 2 signed checkpoints, chain intact.

Tamper proof complete: detection works, and the restored log verifies again.
```

It tampers the **middle** evidence record, and every verify line is the **real
`spine.verify()`** — the same code path as `attestor verify`. The flip and
restore handle the append-only trigger exactly as the manual sequence below.

## Prove it is tamper-evident — by hand

The same thing, step by step, if you'd rather drive it yourself. Flip **one
byte** of one evidence record directly in storage (out of band) and `attestor
verify` detects it; restore the byte and it passes again. These commands run
against the **showcase store**:

```bash
export ATTESTOR_SQLITE_PATH=.attestor/showcase/evidence.sqlite
export ATTESTOR_KEY_FILE=.attestor/showcase/signing-key.json

# 1) Baseline — the log verifies.
attestor verify
#   ✅ Evidence log VERIFIED — 6 records, 2 signed checkpoints, chain intact.

# 2) Tamper: flip one byte of record #4's input digest, directly in the DB.
#    We drop the append-only trigger first to simulate an attacker with full
#    disk/DB access — the same technique the spine's own tamper test uses.
#    (The spine recreates this trigger every time it opens, so each out-of-band
#    write must drop it first.) The XOR flips the low bit of one hex nibble.
node -e '
  const D=require("better-sqlite3");const db=new D(process.env.ATTESTOR_SQLITE_PATH);
  db.exec("DROP TRIGGER IF EXISTS evidence_record_no_update");
  const r=db.prepare("SELECT input_sha256 FROM evidence_record WHERE seq=4").get();
  const c=r.input_sha256, flipped=(parseInt(c[0],16)^1).toString(16)+c.slice(1);
  db.prepare("UPDATE evidence_record SET input_sha256=? WHERE seq=4").run(flipped);
  db.close(); console.log("flipped 1 byte of record #4");
'

# 3) Verify now FAILS and points at the exact record (exit code 1).
attestor verify
#   ❌ Evidence log FAILED verification — 1 issue(s) detected:
#      • [record_hash_mismatch] at 4: record content does not match its stored hash

# 4) Restore: the XOR is its own inverse — run the identical flip again.
node -e '
  const D=require("better-sqlite3");const db=new D(process.env.ATTESTOR_SQLITE_PATH);
  db.exec("DROP TRIGGER IF EXISTS evidence_record_no_update");
  const r=db.prepare("SELECT input_sha256 FROM evidence_record WHERE seq=4").get();
  const c=r.input_sha256, restored=(parseInt(c[0],16)^1).toString(16)+c.slice(1);
  db.prepare("UPDATE evidence_record SET input_sha256=? WHERE seq=4").run(restored);
  db.close(); console.log("restored record #4");
'

# 5) Verify passes again.
attestor verify
#   ✅ Evidence log VERIFIED — 6 records, 2 signed checkpoints, chain intact.
```

Why detection is inevitable: each record's `recordHash` is a SHA-256 over all of
its fields, every record commits to its predecessor's hash, and signed Merkle
checkpoints commit to the whole prefix. Changing a single byte breaks the
record's own hash (and, depending on the field, the chain link and checkpoint
root) — exactly what `verify` re-derives independently.

## Prove it to a third party — external anchoring (RFC 3161)

Everything above proves the log is *internally* consistent — but that still
requires trusting whoever holds the spine. The `@attestor/anchor` package closes
that gap: after a checkpoint is signed, its Merkle root is submitted to an
**independent RFC 3161 Trusted Timestamp Authority** (freetsa.org), and the
returned timestamp token is stored as an *anchor receipt*. Now the root's
existence at a point in time is attested by a third party the operator does not
control.

```bash
attestor showcase --scenario finance --anchor
```

This runs the scenario, anchors the latest checkpoint root to the TSA, exports a
**portable bundle** (`.attestor/showcase/bundle.json` — records + signed roots +
anchor tokens + TSA trust anchors), and runs the independent three-part
verification on that bundle:

```
(1) Internal chain integrity (re-derived, no operator trust):
    ✅ VERIFIED — 6 records, 1 signed checkpoints, chain intact.
(2) External RFC 3161 anchors (attested by an independent TSA):
    ✅ checkpoint #1 (tree size 6) anchored at 2026-06-13T12:34:56.000Z by freetsa.org
(3) Merkle inclusion in an anchored root:
    ✅ record 4 is provably included in anchored checkpoint 1 (tree size 6)

Independent verdict: ✅ the evidence is authentic and externally anchored
```

Anyone can re-run that verification on the exported bundle **without the live
database and without trusting you**:

```bash
attestor verify-anchored --bundle ./bundle.json --seq 4
```

Design notes:

- **Asynchronous & non-blocking.** The checkpoint is created and signed locally;
  the TSA call happens *after*, off the spine's path. It never blocks `append`
  or `checkpoint`.
- **Never loses a checkpoint.** If the TSA is unreachable, the checkpoint is
  preserved as a `pending`/`failed` anchor receipt (a flagged gap) and retried
  later — the local signed checkpoint is untouched. Run `--anchor` without
  network egress and you'll see it degrade gracefully and queue the gap.
- **No hand-rolled crypto.** RFC 3161 request/response and the CMS token are
  handled by `pkijs`/`asn1js`; the signature check uses Node WebCrypto. Chain
  integrity and Merkle inclusion reuse the spine's exported functions verbatim.
- **Live TSA.** The genuine freetsa.org anchor needs outbound network egress; in
  a restricted environment the offline tests cover the full path with a
  self-signed test TSA, and the live integration test runs with
  `ATTESTOR_LIVE_TSA=1`.

## Where the code lives

```
packages/showcase/                       # the additive demo layer (own package)
  src/amount-policy.ts                   # shared argument-aware threshold helper
  src/tamper.ts                          # one-byte flip/restore for --prove-tamper
  src/harness.ts                         # wires agent ⇄ gateway ⇄ tools, isolated store
  src/replay.ts                          # projects evidence records into a replay
  src/scenarios/types.ts                 # the Scenario interface
  src/scenarios/index.ts                 # scenario registry (id → scenario)
  src/scenarios/support-desk.ts          # support-desk scenario (tools/policy/steps)
  src/scenarios/finance.ts               # finance scenario (tools/policy/steps)
  src/scenarios/aml.ts                   # AML/BSA investigation scenario (tools/policy/steps)
  src/tools.ts, src/policy.ts, src/scenario.ts   # support-desk tools/policy/steps
packages/anchor/                         # external RFC 3161 anchoring (own package)
  src/rfc3161.ts                         # build/verify timestamp tokens (pkijs/asn1js)
  src/tsa-client.ts                      # TSA HTTP client (freetsa.org), pluggable transport
  src/anchor-store.ts                    # durable sidecar receipts (pending/anchored/failed)
  src/anchor-service.ts                  # async, graceful anchoring + retry of gaps
  src/bundle.ts                          # portable bundle export/read
  src/verify-bundle.ts                   # three-part verification (reuses spine verify+merkle)
packages/cli/src/commands/showcase.ts    # the `attestor showcase` driver (prints live)
packages/cli/src/commands/verify-anchored.ts   # the `attestor verify-anchored` command
packages/proxy/                          # REAL MCP interception (own package)
  src/proxy-core.ts                      # hot path: classify → record(-before-forward) → forward
  src/server.ts                          # the proxy as a real MCP server
  src/http.ts                            # serve the proxy over real Streamable HTTP
packages/test-tools/                     # real downstream MCP tools (sandboxed side effects)
packages/test-agent/                     # a minimal real MCP-native agent
packages/cli/src/commands/live-demo.ts   # the `attestor live-demo` driver
```

The spine (`packages/spine`) and the gateway core (`packages/gateway/src`) are
**not modified** by this showcase. The built-in tamper proof mutates storage in
`src/tamper.ts` but all detection is the existing `spine.verify()`.
