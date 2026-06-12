# Attestor

**A risk-tiered audit gateway and tamper-evident evidence system of record for AI agents.**

Attestor is a consent-based, customer-operated audit logging gateway — the
AI-agent equivalent of a SIEM audit log or a flight data recorder. You deploy it
in your own infrastructure, between your agents (MCP clients) and your tools (MCP
servers), and it records every tool call as a signed, Merkle-chained evidence
record mapped to a policy decision and an ISO/IEC 42001 control reference.

It observes only traffic you own. By default it stores **only SHA-256 digests**
of inputs and outputs — never raw payloads — unless a policy explicitly opts in.

> **Phase 1 scope.** This repository is the runtime that *accumulates* audit
> evidence: an MCP gateway, an append-only evidence spine, hardcoded policy v0,
> and a CLI to verify and attest. The SaaS control plane and a pluggable policy
> engine (OPA/Cedar) are Phase 2. See [SHORTCOMINGS.md](./SHORTCOMINGS.md) for an
> honest list of what Phase 1 does **not** do.

---

## What you get

- **MCP audit gateway** — speaks MCP on both sides (an MCP server to the agent,
  an MCP client to your tools). Forwards `tools/list` unchanged and intercepts
  every `tools/call`. Supports **stdio** (Claude Desktop/Code) and **Streamable
  HTTP** (networked agents in a VPC).
- **Evidence spine** — append-only, hash-chained evidence records with signed
  Merkle checkpoints (RFC 6962 model). Immutability is enforced at the **database
  layer** (triggers + privilege revocation), not just in application code.
- **Policy v0** — declarative, risk-tiered classification of tool calls (T0–T3)
  with `allow` / `deny` / `escalate` decisions and ISO 42001 control mappings.
  **Fail-open on T0/T1, fail-closed on T2/T3** when the store is unreachable.
- **CLI** — `verify` (prove integrity), `attest` (compile a compliance report in
  Markdown + JSON), and `demo` (end-to-end scenario).

## Architecture

```
   agent (MCP client)                      your tools (MCP servers)
         │  tools/call                              ▲
         ▼                                          │ forward (allow only)
  ┌─────────────────────── Attestor gateway ───────────────────────┐
  │  classify risk tier → evaluate policy v0 → enforce decision     │
  │  hash input/output (digest by default) → record signed evidence │
  └───────────────────────────────┬─────────────────────────────────┘
                                  │ append (the ONLY write path)
                                  ▼
                    Evidence spine (Postgres / SQLite)
              append-only · hash-chained · signed Merkle checkpoints
```

Denied or escalated calls are **never forwarded downstream**.

---

## Quick start (Docker, ~5 minutes)

Requires Docker with Compose.

```bash
docker compose up --build
```

This starts Postgres and the gateway serving MCP over Streamable HTTP on
`http://localhost:8080`, fronting a bundled sample tool server. Point it at your
own MCP server by editing the `ATTESTOR_DOWNSTREAM_*` variables in
`docker-compose.yml` (set `ATTESTOR_DOWNSTREAM_URL` for an HTTP MCP server, or
`ATTESTOR_DOWNSTREAM_CMD` / `ATTESTOR_DOWNSTREAM_ARGS` for a stdio one).

## Quick start (local, ~10 minutes)

Requires Node.js ≥ 20.

```bash
npm install
npm run build
npm test            # 87 tests; spine coverage gate ≥ 90%

# Run the end-to-end demo: 10 actions through the gateway, incl. a denied T3.
node packages/cli/dist/index.js demo
```

The demo prints the action trail, writes an attestation report to
`.attestor/demo/attestation.md`, and proves chain integrity. Then verify it
yourself and watch tampering get caught:

```bash
export ATTESTOR_SQLITE_PATH=.attestor/demo/evidence.sqlite
export ATTESTOR_KEY_FILE=.attestor/demo/signing-key.json

node packages/cli/dist/index.js verify          # ✅ VERIFIED
node packages/cli/dist/index.js attest --out report   # writes report.md + report.json
```

See [docs/DEMO.md](./docs/DEMO.md) for the tamper-detection walkthrough and how
to connect Claude Desktop/Code to the gateway.

---

## Using the CLI

```
attestor verify [--seq <n>]      Prove the log is intact (--seq: one record, O(log n))
attestor attest [--from <iso>] [--to <iso>] [--out <prefix>]
                                 Compile a compliance report (Markdown + JSON)
attestor demo                    Run the end-to-end demo scenario
```

Exit codes are CI-friendly: `verify` and `attest` return non-zero if the log
fails integrity verification.

## Configuration (environment)

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATTESTOR_DATABASE_URL` | _(unset)_ | Postgres connection string. If unset, SQLite is used. |
| `ATTESTOR_SQLITE_PATH` | `.attestor/evidence.sqlite` | SQLite evidence file. |
| `ATTESTOR_KEY_FILE` | `.attestor/signing-key.json` | Ed25519 signing key (generated on first use). |
| `ATTESTOR_POLICY_FILE` | `policies/v0.yaml` | Policy set. |
| `ATTESTOR_CONTROLS_FILE` | `data/iso42001-controls.json` | Control mapping table. |
| `ATTESTOR_AGENT_ID` | `agent` | Identity attributed to the agent in evidence. |
| `ATTESTOR_DOWNSTREAM_URL` / `ATTESTOR_DOWNSTREAM_CMD` (+`_ARGS`) | _(required for the server)_ | The downstream MCP server to front. |
| `ATTESTOR_HTTP_PORT` / `ATTESTOR_STDIO` | `8080` / _(http)_ | Transport selection. |
| `ATTESTOR_SIGNING_KEY` | _(unset)_ | Supply the private key inline instead of a file (e.g. mounted secret). |

## How integrity works

Each evidence record contains the SHA-256 hash of the previous record, forming a
hash chain. Periodic **checkpoints** sign a Merkle root over all records to date
with the spine's Ed25519 key. Verification independently re-derives every record
hash, every chain link, and every checkpoint root, then checks each signature:

- Altering any field of any record breaks its own hash **and** the next record's
  link.
- Deleting or reordering records breaks the chain and the sequence.
- A historical signed checkpoint pins the Merkle root, so a wholesale rewrite
  cannot forge the past without the signing key.

The evidence table is physically append-only: `BEFORE UPDATE OR DELETE` triggers
abort any mutation through the application path. For production Postgres, see
[`deploy/postgres-grants.sql`](./deploy/postgres-grants.sql) to run the gateway
under a role that cannot `UPDATE`/`DELETE` at all.

## Repository layout

```
packages/types     Shared, dependency-free contracts (EvidenceRecord, RiskTier, …)
packages/spine     Append-only store, hash chain, Ed25519, Merkle, verify  (the sacred core)
packages/gateway   MCP proxy, risk classifier, policy v0 engine, fail-open/closed core
packages/cli       attestor verify | attest | demo
policies/v0.yaml   Declarative policy set v0
data/              ISO/IEC 42001 control mapping table
deploy/            Production Postgres hardening
```

## Development

```bash
npm run build       # tsc project references
npm run lint        # eslint (no console / no any on non-CLI code)
npm test            # vitest; spine coverage gate ≥ 90%
npm run coverage    # coverage report
```

## License

Business Source License 1.1 (`LicenseRef-BSL-1.1`). Source-available; not an OSI
open-source license. Intended for design partners and internal evaluation.
