# Attestor demo walkthrough

This walkthrough takes ~10 minutes and shows the full Phase 1 story: an agent
acting through the gateway, an attestation report, single-record proofs, and
cryptographic tamper detection. It also shows how to put the real Claude
Desktop/Code in front of the gateway.

## 0. Build

```bash
npm install
npm run build
```

## 1. Run the scripted end-to-end scenario

```bash
node packages/cli/dist/index.js demo
```

A scripted agent performs **10 tool calls** through the gateway over in-process
MCP, spanning every risk tier:

| # | Tool | Tier | Outcome |
| --- | --- | --- | --- |
| 1 | `service.status` | T0 | allowed |
| 2–3 | `fs.read`, `db.query` | T1 | allowed |
| 4–6 | `config.update`, `file.write`, `report.create` | T2 | allowed |
| 7 | `cache.read` | T1 | allowed |
| 8 | `email.send` | T3 | **escalate** (blocked, needs approval) |
| 9 | `payments.transfer` | T3 | **deny** (blocked by policy) |
| 10 | `db.delete` | T3 | **deny** (blocked by policy) |

The denied and escalated calls are **never forwarded** to the downstream tools.
The run writes `.attestor/demo/attestation.md` (and `.json`) and prints the
signed Merkle root and integrity status.

## 2. Read the attestation report

```bash
sed -n '1,40p' .attestor/demo/attestation.md
```

You get chain-integrity status with the latest signed root, totals by tier and
decision, ISO 42001 control coverage, and the full ordered incident trail with
input/output digests.

## 3. Verify integrity yourself

Point the CLI at the demo store and signing key:

```bash
export ATTESTOR_SQLITE_PATH=.attestor/demo/evidence.sqlite
export ATTESTOR_KEY_FILE=.attestor/demo/signing-key.json

node packages/cli/dist/index.js verify
# ✅ Evidence log VERIFIED — 10 records, 3 signed checkpoints, chain intact.

node packages/cli/dist/index.js verify --seq 9   # prove the denied transfer, O(log n)
# ✅ Record #9 is included in the signed log (proof verified).
```

## 4. Prove tamper detection

The evidence table is append-only: a normal `UPDATE` is rejected by a database
trigger.

```bash
node -e "const D=require('better-sqlite3');const db=new D(process.env.ATTESTOR_SQLITE_PATH);
try{db.prepare(\"UPDATE evidence_record SET decision='allow' WHERE seq=9\").run()}
catch(e){console.log('blocked:', e.message)}"
# blocked: evidence_record is append-only
```

Now model a privileged attacker who drops the trigger and rewrites the denied
`payments.transfer` (seq 9) to look `allow`ed:

```bash
node -e "const D=require('better-sqlite3');const db=new D(process.env.ATTESTOR_SQLITE_PATH);
db.exec('DROP TRIGGER evidence_record_no_update');
db.prepare(\"UPDATE evidence_record SET decision='allow' WHERE seq=9\").run();
console.log('covertly changed deny -> allow')"

node packages/cli/dist/index.js verify
# ❌ Evidence log FAILED verification — 1 issue(s) detected:
#    • [record_hash_mismatch] at 9: record content does not match its stored hash
```

The cryptographic chain catches what the application-layer guard could not. Re-run
`demo` to reset the store.

## 5. Put Claude Desktop/Code in front of the gateway (stdio)

The gateway is a standard MCP server. To audit your own agent, run the gateway
over stdio, fronting your real MCP tool server, and register it with the client.

Example `claude_desktop_config.json` entry (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "attestor": {
      "command": "node",
      "args": ["/absolute/path/to/packages/gateway/dist/bin/gateway.js"],
      "env": {
        "ATTESTOR_STDIO": "1",
        "ATTESTOR_AGENT_ID": "claude-desktop",
        "ATTESTOR_SQLITE_PATH": "/absolute/path/to/.attestor/evidence.sqlite",
        "ATTESTOR_KEY_FILE": "/absolute/path/to/.attestor/signing-key.json",
        "ATTESTOR_DOWNSTREAM_CMD": "node",
        "ATTESTOR_DOWNSTREAM_ARGS": "/absolute/path/to/your-mcp-server.js"
      }
    }
  }
}
```

Claude now sees your tools *through* Attestor: every call it makes is classified,
enforced, and recorded. Denied/escalated calls return a structured tool error to
Claude and never reach your tools. Run `attestor verify` / `attestor attest`
against the same `ATTESTOR_SQLITE_PATH` at any time to prove and report on what
the agent did.

> For a networked agent instead of stdio, run the gateway over HTTP
> (`docker compose up --build`, or unset `ATTESTOR_STDIO` and set
> `ATTESTOR_HTTP_PORT`) and connect your client to `http://host:8080`.
