-- Ported from the SQLite series' 0003_add_upstream_credential.sql (renumbered — see
-- 0001_init.sql's header on the unified version sequence).
--
-- Storage decision, carried across the port unchanged: plaintext in the database, injected as a
-- literal Authorization header value on outbound upstream requests. NOT encrypted-at-rest by
-- this column's own definition. Note that enterprise #5 (secret backends) later made the VALUE
-- of this column optionally a reference (`enc:v1:...` / `vault://...#...`) resolved at call time
-- — that is an application-layer concern (archon/secrets/), not a schema one, so this column
-- stays a plain TEXT either way.
--
-- The original migration's rationale for plaintext (this app has no KMS story; session_secret
-- and admin_password_hash are already plaintext rows; anyone who can read the config store can
-- already forge an admin session) still applies verbatim on Postgres. What CHANGES with this
-- cutover is the operator-facing mitigation: "protect the data volume" becomes "protect the
-- Postgres instance" — network-reachable rather than a file on a mounted volume, which is a
-- genuinely different (larger) exposure surface. Called out in docs/postgres.md's security
-- section rather than left implicit.

ALTER TABLE servers ADD COLUMN IF NOT EXISTS upstream_auth_header TEXT;
