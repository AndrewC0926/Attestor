# Attestor Showcase — the support-desk agent

A purpose-built demo that makes Attestor's governance **visible**: a single MCP
agent (`support-desk-agent`) handles a realistic support ticket through the
*existing* Attestor gateway and spine, and you watch **allow / escalate / deny**
happen live — then replay the whole thing from the signed evidence and prove it
is tamper-evident.

> Everything here is **simulated**. No real CRM, no real payments, no real
> customer data. The point is to exercise the governance path, not to do work.
> This is an **additive demo layer** (`packages/showcase` + one `attestor`
> subcommand); it does not modify the spine or the gateway core.

## What it demonstrates

- One agent, **6 tools mapped across the risk tiers**:

  | Tool | Tier | Decision |
  |------|------|----------|
  | `read_ticket` | T0 | allow |
  | `post_reply` | T1 | allow |
  | `update_customer_record` | T2 | allow |
  | `issue_refund` | T3 | **allow ≤ $500, escalate > $500** (argument-aware) |
  | `delete_account` | T3 | **deny** |
  | `export_customer_data` | T3 | **deny** |

- The `issue_refund` threshold is enforced by an additive
  `SupportDeskPolicyEngine` that layers an *argument-aware* rule on top of the
  product's name-pattern `PolicyV0Engine` — the same `PolicyEngine` extension
  point a real OPA/Cedar engine would use. The product policy set is untouched.

- Every action becomes a **signed, hash-chained evidence record** in the same
  spine as Phase 1, written to an **isolated store** (`.attestor/showcase/`) so
  it never collides with `attestor demo`.

## Run it

```bash
npm run build          # first time (or after changes)
attestor showcase
```

You'll see each action's **tier, decision, and evidence record id** as it
happens:

```
   1. read_ticket            T0  ✅ ALLOW     → evidence #1 (70e3e5f693ec…)
   2. update_customer_record T2  ✅ ALLOW     → evidence #2 (32cd5c8e6041…)
   3. post_reply             T1  ✅ ALLOW     → evidence #3 (045976e5cc8d…)
   4. issue_refund           T3  ✅ ALLOW     → evidence #4 (99ac17b7e730…)   $200 — within limit
   5. issue_refund           T3  ⚠️  ESCALATE  → evidence #5 (e0157a1670b7…)   $750 — over limit
   6. export_customer_data   T3  ⛔ DENY      → evidence #6 (e063ddc2aa5d…)
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

## Prove it is tamper-evident

The showcase reuses the Phase 1 integrity guarantee. Flip **one byte** of one
evidence record directly in storage (out of band) and `attestor verify` detects
it; restore the byte and it passes again. These commands are run against the
**showcase store**:

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

## Where the code lives

```
packages/showcase/                # the additive demo layer (own package)
  src/tools.ts                    # 6 simulated support-desk MCP tools
  src/policy.ts                   # SupportDeskPolicyEngine (argument-aware refund rule)
  src/scenario.ts                 # the scripted ticket (data only)
  src/harness.ts                  # wires agent ⇄ gateway ⇄ tools, isolated store
  src/replay.ts                   # projects evidence records into a replay
packages/cli/src/commands/showcase.ts   # the `attestor showcase` driver (prints live)
```

The spine (`packages/spine`) and the gateway core (`packages/gateway/src`) are
**not modified** by this showcase.
