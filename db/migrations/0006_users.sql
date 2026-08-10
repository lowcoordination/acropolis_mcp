-- Ported from the SQLite series' 0007_users.sql (renumbered).
--
-- Local user model + substrate for RBAC. The original migration's non-negotiables all still
-- apply and are preserved verbatim in behaviour:
--   1. Seed a `users` row from settings.admin_password_hash IN THIS SAME migration, same hash
--      format, verbatim copy, so an operator's existing password keeps working untouched.
--   2. Do NOT delete settings.admin_password_hash here — it stays as a fallback read path
--      (archon/admin_auth.py's legacy-check branch) and is the thing this migration reads FROM.
--   3. role is TEXT, not an enum — room to add roles later without a schema migration; validity
--      is enforced in archon/rbac.py, which is also where "unrecognized role -> no access"
--      (fail-closed) has to live anyway. Note this is a REAL constraint-design decision, not a
--      SQLite limitation: Postgres HAS native ENUM types, and using one here would have been the
--      idiomatic-looking port. Deliberately not done — a Postgres ENUM makes adding a role a
--      schema migration (ALTER TYPE ... ADD VALUE), which is exactly the coupling the original
--      decision existed to avoid. Porting the storage engine must not quietly reverse a design
--      call that was made on its own merits.
--   4. oidc_subject (IdP `sub`) is the OIDC identity key, never email — emails change, `sub`
--      doesn't, and matching on email is a known account-takeover vector.
--
-- session_version is the PER-USER revocation counter (archon/sessions.py has a separate GLOBAL
-- one in a settings row) so disabling/demoting/logging-out one person doesn't invalidate
-- everyone else's session.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT,
    password_hash   TEXT,                           -- NULL for OIDC-only users
    role            TEXT NOT NULL DEFAULT 'admin',  -- viewer | operator | admin (validated in app)
    auth_source     TEXT NOT NULL DEFAULT 'local',  -- 'local' | 'oidc'
    oidc_subject    TEXT UNIQUE,                    -- IdP 'sub', stable across email changes
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    session_version INTEGER NOT NULL DEFAULT 0,     -- per-user revocation counter
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(oidc_subject);

-- Seed the existing single admin, preserving their working password verbatim. A fresh
-- (pre-setup) database has no admin_password_hash row, so this SELECT returns zero rows and the
-- INSERT is a no-op — `users` stays empty, which is exactly the "partial/fresh install" state
-- archon/admin_auth.py's fallback path is designed to keep working under.
--
-- created_at: the SQLite original used strftime('%Y-%m-%dT%H:%M:%fZ', 'now') specifically to get
-- a 'Z' suffix, because a bare datetime('now') produced a timezone-LESS string that JS's
-- new Date(...) parses as LOCAL time, mis-rendering this row against every other timestamp in
-- the UI (all written by db/database.py's utcnow()). The Postgres equivalent must preserve that
-- property. to_char(now() AT TIME ZONE 'utc', ...) with an explicit literal Z does so, and is
-- immune to the server's timezone setting because of the explicit AT TIME ZONE 'utc'.
INSERT INTO users (username, password_hash, role, auth_source, created_at)
  SELECT 'admin', value, 'admin', 'local',
         to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  FROM settings WHERE key = 'admin_password_hash'
  ON CONFLICT (username) DO NOTHING;
