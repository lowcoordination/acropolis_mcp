-- 0010_usage_rollups.sql: quotas + usage attribution (enterprise #11, issue #12).
--
-- Deliberately in gateway.db, NOT audit.db: `AuditRetentionJob` (stoa/retention.py) prunes
-- audit_events on a rolling window (default 30 days) — a usage rollup that lived there would
-- silently lose history exactly when an operator most wants to look back over a full billing
-- period. Same reasoning that put admin_events in gateway.db (0006_admin_events.sql): a
-- high-value aggregate must survive the traffic-log retention job, because it answers a
-- different question ("how much has this key spent this period") than the traffic log does
-- ("what exactly happened at 14:32:07").
--
-- Bucket granularity: ONE hour, UTC. Day/month views are computed by summing hourly buckets
-- over a query range — never stored redundantly at coarser granularity — so there is exactly
-- one place counts are written and no risk of an hourly and a monthly copy drifting apart.
-- period_kind is stored alongside period_start as a documentation/query-convenience column
-- (it is always 'hour' today) rather than implying multiple stored granularities exist.
--
-- project_id is nullable and unused today — a deliberate placeholder for enterprise #5
-- (multi-tenancy, next in the roadmap after this item) per 02-quotas-and-usage.md's own
-- "Interactions" section: adding project scoping later should not require ANOTHER migration
-- against this table, just backfilling and starting to filter/group by it.
--
-- server_id (not server_slug) is the FK target, matching how server_policies/tool_policies
-- key off server_id rather than the human-facing slug — consistent with the rest of this
-- schema, and immune to a slug being renamed later (ServerRepo has no rename path today, but
-- server_id is still the more correct key to have chosen).
--
-- api_key_id/server_id/tool are NOT NULL with sentinel values (0 / 0 / '' respectively) for
-- "no key" (open auth_mode), "no server" (never actually used, reserved), and "no specific
-- tool" (non-tools/call traffic), rather than nullable FKs. This is deliberate, not an
-- oversight: SQLite's UNIQUE constraint treats NULL as never-equal-to-itself, so two rows that
-- are logically "the same bucket" would both insert successfully and ON CONFLICT would never
-- fire — confirmed directly against a throwaway table before writing this migration. Sentinels
-- keep the UNIQUE constraint meaningful and the upsert atomic; 0 is never a real api_keys.id or
-- servers.id (SQLite AUTOINCREMENT starts at 1), so it can't collide with a real row.
CREATE TABLE IF NOT EXISTS usage_rollups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    period_start TEXT NOT NULL,   -- ISO8601 UTC, truncated to the hour, e.g. "2026-08-09T14:00:00+00:00"
    period_kind  TEXT NOT NULL DEFAULT 'hour',
    api_key_id   INTEGER NOT NULL DEFAULT 0,  -- 0 = no key (open auth_mode) — see note above
    server_id    INTEGER NOT NULL DEFAULT 0,  -- 0 = no server — reserved, not used by tools/call rows
    tool         TEXT NOT NULL DEFAULT '',    -- '' = no specific tool (non-tools/call traffic)
    project_id   INTEGER,         -- reserved for enterprise #5 (multi-tenancy) — unused today
    calls        INTEGER NOT NULL DEFAULT 0,
    CHECK (period_kind IN ('hour')),
    UNIQUE (period_start, api_key_id, server_id, tool)
);

-- The hot read path is "give me this key's total calls since the period boundary" (quota
-- enforcement, on every tools/call) — api_key_id first, period_start second, matches that
-- access pattern. The query endpoint's by-server/by-tool breakdowns reuse the same index as a
-- prefix scan (api_key_id, period_start) plus a filter, rather than needing a second index.
CREATE INDEX IF NOT EXISTS idx_usage_rollups_key_period ON usage_rollups(api_key_id, period_start);
CREATE INDEX IF NOT EXISTS idx_usage_rollups_server_period ON usage_rollups(server_id, period_start);

-- Quota config lives ON the key (per-key, not per-server): the billing/budget question this
-- feature answers is "what did this consumer spend," and api_keys is the consumer identity on
-- the data plane (02-quotas-and-usage.md design decision 3). Both nullable; NULL = unlimited,
-- which is the default — a key with no quota configured must behave byte-identically to today
-- (see tests/integration/test_quotas.py's regression test), same off-by-default discipline as
-- server_policies.rate_limit and enterprise #10's dlp_detectors.
ALTER TABLE api_keys ADD COLUMN quota_calls INTEGER;
ALTER TABLE api_keys ADD COLUMN quota_period TEXT;
