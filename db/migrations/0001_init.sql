-- gateway.db schema (config: servers, policies, keys, settings)

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    in_aggregate INTEGER NOT NULL DEFAULT 1,
    upstream_protocol TEXT,
    health_status TEXT NOT NULL DEFAULT 'unknown',
    last_seen_at TEXT,
    discover_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (slug GLOB '[a-z0-9-]*' AND slug != ''),
    CHECK (health_status IN ('unknown', 'healthy', 'unhealthy'))
);

CREATE TABLE IF NOT EXISTS server_policies (
    server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'passthrough',
    rate_limit TEXT,
    updated_at TEXT NOT NULL,
    CHECK (mode IN ('passthrough', 'allowlist', 'denylist'))
);

CREATE TABLE IF NOT EXISTS tool_policies (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    action TEXT NOT NULL,
    rate_limit TEXT,
    PRIMARY KEY (server_id, tool_name),
    CHECK (action IN ('allow', 'deny'))
);

CREATE TABLE IF NOT EXISTS param_rules (
    id INTEGER PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    param_name TEXT NOT NULL,
    max_length INTEGER,
    max_value REAL,
    min_value REAL,
    denied INTEGER NOT NULL DEFAULT 0,
    block_patterns TEXT,
    UNIQUE (server_id, tool_name, param_name)
);

CREATE TABLE IF NOT EXISTS tools_cache (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    ttl_ms INTEGER,
    cache_scope TEXT,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (server_id, tool_name)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    server_scopes TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
