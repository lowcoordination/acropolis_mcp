-- 0001_init.sql — Postgres-native initial schema (enterprise #7, issue #8).
--
-- HARD CUTOVER NOTE. Before this migration existed, Acropolis ran on SQLite across TWO files:
-- gateway.db (config: servers, policies, keys, settings) and audit.db (the high-churn traffic
-- log). Those files had their own migration series (0001_init.sql + 0001_init_audit.sql, each
-- with independent schema_migrations bookkeeping). This migration replaces BOTH with one
-- Postgres database.
--
-- Decision: ONE database, ONE schema ("public"), two table GROUPS — not two Postgres schemas.
-- Reasoning:
--   1. The original split was a SQLite file-level concern (one writer per file; keeping the
--      high-churn traffic log out of the config file's write path). Postgres has row-level
--      locking and MVCC — the contention argument that motivated two files does not survive
--      the port, so preserving it would be cargo-culting a workaround for a constraint that no
--      longer exists.
--   2. Two schemas would need either two connection pools with different search_paths or
--      schema-qualified names everywhere, for zero isolation benefit — both groups live in the
--      same database, same backup, same transaction domain either way.
--   3. It makes cross-group queries POSSIBLE for the first time. AuditRepo.query's own docstring
--      documents the old limitation verbatim: "audit_events lives in audit.db, a SEPARATE SQLite
--      file/connection from gateway.db where servers/projects live — there is no SQL JOIN across
--      them", which forced project-scoped audit queries to resolve a slug set in Python first and
--      pass it as an IN-list. That workaround is now optional rather than mandatory.
--   4. Retention (stoa/retention.py) prunes audit_events only; a shared database does not change
--      what that job touches. The "admin_events must survive the retention job" invariant
--      (0006's header comment) was always enforced by WHICH TABLE a row lands in, never by which
--      file — so it is unaffected.
-- Tradeoff accepted: an operator can no longer back up or discard the traffic log independently
-- of config by moving one file. pg_dump --exclude-table=audit_events covers the same need; see
-- docs/backup-and-upgrades.md.
--
-- Type mapping applied throughout this port:
--   INTEGER PRIMARY KEY (AUTOINCREMENT) -> INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY
--   INTEGER (boolean-ish, 0/1)          -> BOOLEAN
--   TEXT holding JSON                   -> JSONB (native, queryable, validated on write)
--   TEXT holding an ISO8601 timestamp   -> TEXT, DELIBERATELY UNCHANGED (see below)
--   REAL                                -> DOUBLE PRECISION
--
-- Timestamps stay TEXT rather than becoming TIMESTAMPTZ. This is deliberate and load-bearing,
-- not laziness: every timestamp in this app is produced by db/database.py's utcnow()
-- (datetime.now(timezone.utc).isoformat()), compared as a STRING in half a dozen places
-- (AuditRepo.query's ts >= / ts <=, UsageRepo.total_since's period_start >= since_iso,
-- _hour_bucket's ISO round-trip), returned as a string through the API, and parsed by the
-- frontend with new Date(...). Converting to TIMESTAMPTZ would change the wire format of every
-- API response that carries a timestamp (asyncpg returns datetime objects, not strings),
-- silently breaking the frontend and every test that asserts on an ISO string. That is a
-- separate, user-visible change with its own testing burden — out of scope for a storage-engine
-- cutover whose whole premise is that behaviour stays identical. Recorded here so the next
-- person sees a decision rather than an oversight.

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    in_aggregate BOOLEAN NOT NULL DEFAULT TRUE,
    upstream_protocol TEXT,
    health_status TEXT NOT NULL DEFAULT 'unknown',
    last_seen_at TEXT,
    discover_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    -- Ported from 0002_tighten_slug_check.sql, which rebuilt the table to fix a GLOB pattern
    -- that only constrained the FIRST character. Postgres has a real regex operator, so the
    -- intent ("lowercase alphanumerics and hyphens, at least one character") is expressible
    -- directly and unambiguously rather than as a double-GLOB negation. Folded into the
    -- CREATE TABLE rather than kept as a separate rebuild migration: 0002 existed ONLY because
    -- SQLite has no ALTER TABLE ... ADD CONSTRAINT and a CHECK change required the
    -- new-table/copy/drop/rename dance. On a fresh Postgres schema there is no shipped 0001 to
    -- avoid editing — this IS the first migration — so the correct constraint goes in directly.
    CONSTRAINT servers_slug_format CHECK (slug ~ '^[a-z0-9-]+$'),
    CONSTRAINT servers_health_status CHECK (health_status IN ('unknown', 'healthy', 'unhealthy'))
);

CREATE TABLE IF NOT EXISTS server_policies (
    server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'passthrough',
    rate_limit TEXT,
    updated_at TEXT NOT NULL,
    CONSTRAINT server_policies_mode CHECK (mode IN ('passthrough', 'allowlist', 'denylist'))
);

CREATE TABLE IF NOT EXISTS tool_policies (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    action TEXT NOT NULL,
    rate_limit TEXT,
    PRIMARY KEY (server_id, tool_name),
    CONSTRAINT tool_policies_action CHECK (action IN ('allow', 'deny'))
);

CREATE TABLE IF NOT EXISTS param_rules (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    param_name TEXT NOT NULL,
    max_length INTEGER,
    max_value DOUBLE PRECISION,
    min_value DOUBLE PRECISION,
    denied BOOLEAN NOT NULL DEFAULT FALSE,
    -- block_patterns is a JSON array of regex strings (json.dumps'd list in the SQLite schema).
    -- JSONB here: the repo layer already round-trips it through json.dumps/json.loads, and
    -- asyncpg needs an explicit codec either way — see db/database.py's _init_connection.
    block_patterns JSONB,
    UNIQUE (server_id, tool_name, param_name)
);

CREATE TABLE IF NOT EXISTS tools_cache (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    definition_json JSONB NOT NULL,
    ttl_ms INTEGER,
    cache_scope TEXT,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (server_id, tool_name)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- JSON array of server slugs this key is scoped to, or NULL for "all servers".
    server_scopes JSONB,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Ported from 0001_init_audit.sql. Now a table in the SAME database as everything above rather
-- than a separate audit.db file — see this file's header for the one-database decision.
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
    CONSTRAINT audit_events_decision
        CHECK (decision IN ('ALLOWED', 'BLOCKED', 'PASSTHROUGH', 'ERROR'))
);

-- BIGINT (not INTEGER) for audit_events.id specifically: this is the one genuinely
-- high-churn table in the schema, it is the whole reason the traffic log used to live in its
-- own file, and SQLite's INTEGER PRIMARY KEY was always a 64-bit rowid. Mapping it to a 32-bit
-- Postgres INTEGER would have silently introduced a ~2.1-billion-row ceiling that the SQLite
-- schema never had. Every other id stays INTEGER — those tables are operator-scale (servers,
-- keys, users, projects), and usage_rollups is bounded by hour-buckets, not call volume.

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_server_ts ON audit_events(server_slug, ts);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision, ts);

-- Single schema_migrations table for the whole database, replacing the two independent ones the
-- two SQLite files each carried. Version numbering is therefore unified: the old gateway series
-- and audit series both had an 0001, and both had an 0008 (0008_gateway_dlp_config.sql /
-- 0008_audit_dlp.sql) — a collision that only worked because they were bookkept in separate
-- files. This port renumbers into one forward-only sequence; see db/database.py's MIGRATIONS
-- list for the canonical order.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
