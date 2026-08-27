-- 0001_audit_init.sql — the audit log schema, for a SEPARATE audit database (issue #108).
--
-- When ACROPOLIS_AUDIT_DATABASE_URL is set, the high-churn traffic log (audit_events) lives in
-- its OWN Postgres database, separate from the config database (servers, keys, policies,
-- settings). This is the opt-in restoration of the pre-cutover split, where gateway.db and
-- audit.db were separate SQLite files (see 0001_init.sql's header, which documents why the
-- Postgres cutover collapsed them and what that cost).
--
-- This is a FRESH forward-only sequence for the audit database, bookkept in its own
-- schema_migrations table (identical shape to the config database's). It contains exactly the
-- audit-relevant DDL from the config sequence, folded into one file:
--   - 0001_init.sql:  audit_events table + idx_audit_ts / idx_audit_server_ts / idx_audit_decision
--   - 0003:           idx_audit_api_key
--   - 0004:           origin column (in-UI tool-tester rows, origin='test')
--   - 0007:           dlp_detector / dlp_action / dlp_match_count
--
-- When the audit store is NOT split, the config database's own 0001/0003/0004/0007 create all
-- of this as before; this file is never applied there. When it IS split, the config database's
-- copy of audit_events is created by 0001 and then sits inert and unused — every audit read
-- and write routes through AuditRepo, which targets the audit pool (see db/repo.py).

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts TEXT NOT NULL,
    server_slug TEXT,
    api_key_id INTEGER,
    client_ip TEXT,
    endpoint TEXT,
    rpc_method TEXT,
    tool TEXT,
    decision TEXT NOT NULL,
    rule TEXT,
    matched TEXT,
    reason TEXT,
    args_summary TEXT,
    bridged BOOLEAN NOT NULL DEFAULT FALSE,
    status_code INTEGER,
    latency_ms INTEGER,
    origin TEXT,
    dlp_detector TEXT,
    dlp_action TEXT,
    dlp_match_count INTEGER,
    CONSTRAINT audit_events_decision
        CHECK (decision IN ('ALLOWED', 'BLOCKED', 'PASSTHROUGH', 'ERROR'))
);

-- BIGINT (not INTEGER) for audit_events.id specifically: this is the one genuinely high-churn
-- table in the schema, and SQLite's INTEGER PRIMARY KEY was always a 64-bit rowid. Mapping it
-- to a 32-bit Postgres INTEGER would have silently introduced a ~2.1-billion-row ceiling.

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_server_ts ON audit_events(server_slug, ts);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision, ts);
CREATE INDEX IF NOT EXISTS idx_audit_api_key ON audit_events(api_key_id, ts);
