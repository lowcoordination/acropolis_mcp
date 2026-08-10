-- Ported from the SQLite series' 0006_admin_events.sql (renumbered).
--
-- Control-plane audit log: administrative actions on the control plane (server CRUD, policy
-- changes, key mint/revoke, settings changes, config imports). The OPPOSITE of audit_events'
-- high-volume, lower-value traffic log — these are low-volume, high-value events that must
-- survive long-term.
--
-- The original migration's placement rationale was "gateway.db, not audit.db". Post-cutover
-- there is one database, so the rationale restates as: this is a SEPARATE TABLE from
-- audit_events, and stoa/retention.py's AuditRetentionJob only ever DELETEs from audit_events.
-- The invariant that mattered ("the 30-day retention job must never destroy these rows") was
-- always enforced by table identity, not file identity — so it survives the port untouched.
--
-- before/after are JSONB here (they were TEXT holding JSON in SQLite). AdminEventRecord exposes
-- them as Optional[str] to callers and parses on demand via parse_before/parse_after, so the
-- repo layer serializes on write and stringifies on read to keep that public shape identical.

CREATE TABLE IF NOT EXISTS admin_events (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          TEXT NOT NULL,
    actor       TEXT,              -- 'admin-session' | 'admin-token' | 'cli' | a real user id
    action      TEXT NOT NULL,     -- server.create | server.update | policy.update | key.create | ...
    target_type TEXT,              -- 'server' | 'key' | 'settings' | 'config' | 'project'
    target_id   TEXT,              -- slug, key id, or NULL
    before      JSONB,             -- allowlisted fields only, NULL on create
    after       JSONB,             -- allowlisted fields only, NULL on delete
    client_ip   TEXT,
    summary     TEXT NOT NULL      -- human-readable, e.g. "mode: allowlist -> passthrough"
);

CREATE INDEX IF NOT EXISTS idx_admin_events_ts ON admin_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_admin_events_action ON admin_events(action);
