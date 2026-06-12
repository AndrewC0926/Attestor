-- Optional least-privilege hardening for production Postgres deployments.
--
-- Append-only is ALREADY enforced for every role (including the table owner) by
-- the BEFORE UPDATE OR DELETE triggers the gateway installs at startup. This
-- script is defense in depth: it provisions a runtime role that physically
-- cannot UPDATE or DELETE evidence, so even a compromised application credential
-- cannot rewrite history.
--
-- Usage:
--   1. Let the gateway connect once as the owner to create the tables/triggers
--      (it does this automatically on first start).
--   2. Run this script as the owner.
--   3. Re-point the gateway at the database using the attestor_app credentials.

-- Runtime role with no UPDATE/DELETE on evidence.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'attestor_app') THEN
    CREATE ROLE attestor_app LOGIN PASSWORD 'change-me-in-production';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE attestor TO attestor_app;
GRANT USAGE ON SCHEMA public TO attestor_app;

-- The only mutations the runtime role may perform: append and read.
GRANT SELECT, INSERT ON evidence_record TO attestor_app;
GRANT SELECT, INSERT ON evidence_checkpoint TO attestor_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO attestor_app;

REVOKE UPDATE, DELETE, TRUNCATE ON evidence_record FROM attestor_app;
REVOKE UPDATE, DELETE, TRUNCATE ON evidence_checkpoint FROM attestor_app;
