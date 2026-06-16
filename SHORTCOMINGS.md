# SHORTCOMINGS — what Attestor Phase 1 does NOT do

This document exists so that sales claims stay aligned with reality. Phase 1 is a
real, working evidence pipeline, but it is deliberately scoped. Everything below
is a known, intentional limitation — not a bug.

## Scope boundaries

- **No control plane.** This is the self-hosted gateway only. There is no SaaS
  control plane, no fleet management, no multi-tenant aggregation, and no hosted
  dashboard. (Phase 2.)
- **No UI.** The only interfaces are the CLI and the Markdown/JSON reports. There
  is no web dashboard by design — the first interface is the evidence.
- **Policy is hardcoded v0.** Policies are declarative YAML evaluated by a thin
  rule engine behind the `PolicyEngine` interface. There is no OPA/Cedar
  integration, no policy authoring UI, and no per-tenant policy versioning yet.
  The interface is built so a real engine slots in without gateway changes.

## Instrumentation coverage

- **Tool calls only.** The gateway audits MCP `tools/call`. `model_call` and
  `agent_message` exist in the type system and policy schema but are not yet
  instrumented end-to-end. Resources, prompts, and sampling are passed through
  conceptually but only tool calls are classified and recorded.
- **Risk classification is name-pattern based.** Tier assignment matches tool
  names against regexes in `policies/v0.yaml`. It does not inspect arguments
  semantically (e.g. a transfer amount threshold), and a mis-named or unmatched
  tool falls to the conservative default (T2 / escalate). Argument-aware policy
  is future work.
- **Agent identity is configured, not authenticated.** The agent id attributed
  to evidence comes from gateway configuration, not from a verified credential.
  Strong per-agent authentication (mTLS / token binding) is not in Phase 1.

## Evidence store

- **Postgres backend is integration-tested, not unit-covered.** The ≥90% spine
  coverage gate runs against the SQLite backend and the backend-agnostic
  integrity logic. The Postgres store is exercised via Docker and the demo path.
- **Append-only is enforced by triggers; least-privilege is opt-in.** The
  `BEFORE UPDATE OR DELETE` triggers bind every role, including the owner, and
  are the enforced guarantee. The Docker demo connects as the database owner for
  simplicity; running under a non-owner role that physically cannot
  `UPDATE`/`DELETE` requires applying `deploy/postgres-grants.sql` (documented,
  not automated in Phase 1).
- **Signing key custody: pluggable, HSM-ready.** Signing goes through a `Signer`
  seam (`packages/spine/src/signer.ts`). The default `LocalKeySigner` is the
  unchanged Ed25519 local-key path (file mode 0600, or `ATTESTOR_SIGNING_KEY`).
  `Pkcs11Signer` keeps the Ed25519 private key inside an HSM (PKCS#11; the key
  never leaves the token) and is verifier-compatible — no signature-format
  change. **Key rotation** is supported: each checkpoint records an optional
  `keyId` and embeds its own public key, so new checkpoints sign with the
  current key while historical checkpoints stay verifiable against the key that
  signed them (the `keyId` is metadata, never part of the signed bytes).
  - *Cloud KMS (AWS/GCP) follow-up:* those KMSes do not offer Ed25519 (only
    ECDSA/RSA), so a cloud-KMS signer would require an additive `algorithm`
    field and an algorithm-aware verifier — a deliberate change to the verify
    path, deferred until a customer needs it. PKCS#11 HSMs were implemented
    first precisely because they preserve the format and the verifier.
  - *Forward-security path:* Ed25519 is not forward-secure on its own, but
    rewriting PAST evidence is already prevented by the external RFC 3161
    anchoring (a compromised key cannot forge a past TSA timestamp over an old
    Merkle root). Rotation bounds the blast radius going forward; independent
    co-signing/witnessing of checkpoints is the documented next step.
- **No consistency proofs.** Verification uses record-chain re-derivation plus
  inclusion proofs and signed checkpoint roots. RFC 6962 *consistency* proofs
  between checkpoints are not implemented; a full verify is O(n).

## Operational

- **Buffer durability is process-local.** The fail-open offline buffer is a local
  JSONL file flushed on reconnect. It survives process restarts but not loss of
  the local disk, and it is not itself hash-chained until flushed into the spine.
- **No high-availability story.** Single gateway process per transport; appends
  to Postgres are serialized with an advisory lock. Horizontal scaling and
  failover are not addressed.
- **HTTP transport is stateless and unauthenticated.** The Streamable HTTP
  endpoint has no auth in front of it; deploy it inside your trust boundary or
  behind your own gateway/mTLS. There is no rate limiting.

## Compliance mapping

- **Control mappings are a curated subset.** `data/iso42001-controls.json` maps a
  handful of ISO/IEC 42001:2023 Annex A controls with paraphrased titles. It is
  not a complete or certified control catalog, and NIST AI RMF / EU AI Act /
  AIUC-1 mappings are stubbed for future addition (the data file is structured to
  allow them without code changes). The authoritative wording is in the standard.
- **Reports are evidence summaries, not certifications.** `attestor attest`
  compiles what happened and proves the log is intact. It does not assert
  conformance with any framework; that judgment belongs to your assessor.

## Known limitations (Phase 1)

- Audit scope is limited to the MCP channel. The gateway records actions 
  an agent takes through MCP servers it is configured to forward. Agent 
  behavior through other channels is out of scope for Phase 1 and is 
  planned for later phases.

- Evidence records store cryptographic digests of inputs and outputs by 
  default, not full content. Full-content retention is opt-in per policy. 
  This is a deliberate privacy-preserving default so the audit layer does 
  not retain customer payloads unless explicitly configured to.

- Phase 1 records a single agent's action sequence cleanly. Workflows 
  where agents invoke other agents are not fully modeled yet; nested 
  attribution across multiple agents is planned for a later phase.
