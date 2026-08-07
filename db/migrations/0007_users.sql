-- 0007_users.sql: local user model + substrate for RBAC (Enterprise #2/#3).
--
-- This is the highest-risk migration in the enterprise roadmap: the instance already has a
-- single admin authenticated via settings.admin_password_hash, and after this migration
-- archon/admin_auth.py resolves identity through the `users` table instead. If the existing
-- hash isn't carried across correctly, the operator is locked out of their own gateway with
-- no recovery flow (see docs/backup-and-upgrades.md — migrations are forward-only, there is
-- no `down`).
--
-- Non-negotiables (see enterprise_roadmap_08_06_26/01-identity-and-sso.md):
--   1. Seed a `users` row from settings.admin_password_hash IN THIS SAME migration, same hash
--      format, verbatim copy, so the operator's existing password keeps working untouched.
--   2. Do NOT delete settings.admin_password_hash here — it stays as a fallback read path
--      (archon/admin_auth.py's legacy-check branch) for at least one release, and is the
--      thing this migration reads FROM, so deleting it in the same statement would be
--      self-defeating regardless.
--   3. role is a TEXT column, not an enum — 02-rbac.md wants room to add roles later without
--      a schema migration; validity is enforced at the application layer (archon/rbac.py),
--      which is also where "unrecognized role -> no access" (fail-closed) has to live anyway.
--   4. oidc_subject (IdP `sub`) is the OIDC identity key, never email — emails change, `sub`
--      doesn't, and matching on email is a known account-takeover vector when an IdP allows
--      email reuse across accounts.
--
-- session_version here is the PER-USER revocation counter — archon/sessions.py already has a
-- GLOBAL one (logout-all bumps a single settings row); this is the same mechanism scoped to one
-- user; so disabling/demoting/logging-out one person doesn't invalidate everyone else's session.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT,
    password_hash   TEXT,                          -- NULL for OIDC-only users
    role            TEXT NOT NULL DEFAULT 'admin',  -- viewer | operator | admin (validated in app)
    auth_source     TEXT NOT NULL DEFAULT 'local',  -- 'local' | 'oidc'
    oidc_subject    TEXT UNIQUE,                    -- IdP 'sub', stable across email changes
    enabled         INTEGER NOT NULL DEFAULT 1,
    session_version INTEGER NOT NULL DEFAULT 0,     -- per-user revocation counter (F18, scoped)
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(oidc_subject);

-- Seed the existing single admin, preserving their working password verbatim. A fresh
-- (pre-setup) database has no admin_password_hash row yet, so this SELECT returns zero rows
-- and the INSERT is a no-op — `users` stays empty, which is exactly the "partial/fresh install"
-- state archon/admin_auth.py's fallback path is designed to keep working under.
--
-- Self-review fix: created_at uses strftime with a 'Z' suffix rather than bare datetime('now')
-- ('YYYY-MM-DD HH:MM:SS', no timezone marker). Every OTHER created_at in this app is written by
-- db/database.py's utcnow() (Python's datetime.now(timezone.utc).isoformat(), e.g.
-- "2026-08-07T20:47:58+00:00") and the frontend renders these with `new Date(...)` — a
-- timezone-less string is parsed as LOCAL time by JS, silently mis-rendering the migration-
-- seeded admin's created_at relative to every other timestamp in the UI. strftime's 'Z' suffix
-- makes this string parse as UTC too, consistent with the rest of the app.
INSERT INTO users (username, password_hash, role, auth_source, created_at)
  SELECT 'admin', value, 'admin', 'local', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM settings WHERE key = 'admin_password_hash';
