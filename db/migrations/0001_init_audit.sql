-- audit.db schema (high-churn event log, separate file from gateway.db)

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
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
    bridged INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER,
    latency_ms INTEGER,
    CHECK (decision IN ('ALLOWED', 'BLOCKED', 'PASSTHROUGH', 'ERROR'))
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_server_ts ON audit_events(server_slug, ts);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision, ts);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
