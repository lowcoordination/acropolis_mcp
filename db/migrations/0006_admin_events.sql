-- 0006_admin_events.sql: control-plane audit log (Enterprise #3).
--
-- Records administrative actions on the control plane (server CRUD, policy changes, key
-- mint/revoke, settings changes, config imports). This is the OPPOSITE of audit.db's
-- high-volume, lower-value traffic log — these are low-volume, high-value events that must
-- survive long-term.
--
-- Deliberately placed in gateway.db (not audit.db):
--   1. gateway.db is documented as the config store — a restore brings its change history.
--   2. audit.db's 30-day AuditRetentionJob would silently destroy exactly this record.
--   3. The schemas genuinely diverge (action/target_type/before/after vs tool/rpc_method/decision).
--
-- actor is nullable and carries a SOURCE string ('admin-session' | 'admin-token' | 'cli')
-- until 01-identity-and-sso backfills a real user id. Designed so no second migration needed.

CREATE TABLE IF NOT EXISTS admin_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT,              -- NULL until identity milestone; 'admin-session' | 'admin-token' | 'cli' meanwhile
    action      TEXT NOT NULL,     -- server.create | server.update | server.delete | policy.update
                                   -- key.create | key.disable | key.delete | settings.update | config.import
    target_type TEXT,              -- 'server' | 'key' | 'settings' | 'config'
    target_id   TEXT,              -- slug, key id, or NULL
    before      TEXT,              -- JSON, allowlisted fields only, NULL on create
    after       TEXT,              -- JSON, allowlisted fields only, NULL on delete
    client_ip   TEXT,
    summary     TEXT NOT NULL      -- human-readable, e.g. "mode: allowlist -> passthrough"
);

CREATE INDEX IF NOT EXISTS idx_admin_events_ts ON admin_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_admin_events_action ON admin_events(action);
