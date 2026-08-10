-- Ported from the SQLite series' 0010_usage_rollups.sql (renumbered).
--
-- Quotas + usage attribution: durable call-count rollups, one row per (UTC hour bucket,
-- api_key_id, server_id, tool).
--
-- Deliberately a SEPARATE TABLE from audit_events (the original phrased this as "in gateway.db,
-- NOT audit.db"): stoa/retention.py's AuditRetentionJob prunes audit_events on a rolling window
-- (default 30 days), and a usage rollup subject to that job would silently lose history exactly
-- when an operator most wants to look back over a full billing period. Same reasoning that keeps
-- admin_events separate — a high-value aggregate must survive the traffic-log retention job
-- because it answers a different question ("how much has this key spent this period") than the
-- traffic log does ("what exactly happened at 14:32:07").
--
-- Bucket granularity: ONE hour, UTC. Day/month views are computed by summing hourly buckets over
-- a query range — never stored redundantly at coarser granularity — so there is exactly one place
-- counts are written and no risk of an hourly and a monthly copy drifting apart. period_kind is
-- a documentation/query-convenience column (always 'hour' today).
--
-- server_id (not server_slug) is the join key, matching how server_policies/tool_policies key off
-- server_id. NOT declared as a real FK — the sentinel value 0 used for "no server" below would
-- violate one, since no server row with id 0 can exist. A row referencing a deleted server's
-- former id is left in place rather than cascaded away, which is correct for a historical usage
-- record: a server being deleted from the fleet shouldn't retroactively erase what it cost.
--
-- SENTINELS, RE-VERIFIED FOR POSTGRES: api_key_id/server_id/tool are NOT NULL with sentinel
-- values (0 / 0 / '') for "no key" (open auth_mode), "no server", and "no specific tool"
-- (non-tools/call traffic), rather than nullable columns. The SQLite original's stated reason was
-- that "SQLite's UNIQUE constraint treats NULL as never-equal-to-itself, so two rows that are
-- logically the same bucket would both insert successfully and ON CONFLICT would never fire."
-- That is NOT a SQLite quirk — it is standard SQL NULL semantics, and Postgres behaves the same
-- way by default (UNIQUE NULLS DISTINCT). Confirmed directly against this database before
-- writing this migration rather than assumed from the original's comment. So the sentinel design
-- is carried across unchanged and for the same reason. (Postgres 15+ does offer UNIQUE NULLS NOT
-- DISTINCT, which would permit real NULLs here — deliberately not adopted: it would change the
-- meaning of every existing sentinel row and require a data migration, for no behavioural gain.)
--
-- Sentinel 0 remains collision-proof: GENERATED ALWAYS AS IDENTITY starts at 1, exactly as
-- SQLite's AUTOINCREMENT did, so 0 is never a real api_keys.id or servers.id.
CREATE TABLE IF NOT EXISTS usage_rollups (
    id           INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    period_start TEXT NOT NULL,   -- ISO8601 UTC, truncated to the hour, e.g. "2026-08-09T14:00:00+00:00"
    period_kind  TEXT NOT NULL DEFAULT 'hour',
    api_key_id   INTEGER NOT NULL DEFAULT 0,  -- 0 = no key (open auth_mode)
    server_id    INTEGER NOT NULL DEFAULT 0,  -- 0 = no server context
    tool         TEXT NOT NULL DEFAULT '',    -- '' = non-tools/call traffic (no specific tool)
    project_id   INTEGER,         -- backfilled by 0010_projects.sql
    calls        INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT usage_rollups_period_kind CHECK (period_kind IN ('hour')),
    UNIQUE (period_start, api_key_id, server_id, tool)
);

-- The hot read path is "give me this key's total calls since the period boundary" (quota
-- enforcement, on every tools/call) — api_key_id first, period_start second, matching that access
-- pattern. The query endpoint's by-server/by-tool breakdowns reuse the same index as a prefix
-- scan plus a filter, rather than needing a second index.
CREATE INDEX IF NOT EXISTS idx_usage_rollups_key_period ON usage_rollups(api_key_id, period_start);
CREATE INDEX IF NOT EXISTS idx_usage_rollups_server_period ON usage_rollups(server_id, period_start);

-- Quota config lives ON the key (per-key, not per-server): the billing/budget question this
-- feature answers is "what did this consumer spend," and api_keys is the consumer identity on the
-- data plane. Both nullable; NULL = unlimited, which is the default — a key with no quota
-- configured must behave byte-identically to a pre-feature key.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS quota_calls INTEGER;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS quota_period TEXT;
