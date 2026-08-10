-- Ported from the SQLite series' 0011_projects.sql (renumbered).
--
-- Multi-tenancy / project scoping. "Projects," not "tenants" — one scoping level, no isolation
-- guarantees (no separate crypto domains, no per-project noisy-neighbor QoS). Servers and API
-- keys belong to exactly one project; audit rows and usage rollups are scoped transitively
-- through the server/key they reference. See docs/projects.md for the full design writeup and the
-- explicit "not isolation" statement.
--
-- TWO INDEPENDENT ROLE SYSTEMS (see archon/rbac.py and archon/project_rbac.py):
--   - users.role (unchanged by this migration) is the GLOBAL role — instance-wide authority:
--     creating/deleting projects, managing users/settings, config import/export, GitOps. A global
--     'admin' is an implicit superset admin of EVERY project — no membership row required.
--   - project_members.role (this table) is the PROJECT role — viewer < poweruser < admin, held
--     independently per (user_id, project_id). Structurally identical to the global ROLE_RANK
--     hierarchy, but a completely separate rank space.
--
-- Backfill: every existing server and key lands in a new 'default' project, and EVERY EXISTING
-- USER becomes an 'admin' MEMBER of it — deliberate, not generous. Pre-this-feature, every
-- authenticated user's global role WAS their full authority over every server. Backfilling anyone
-- as less than project-admin would silently take away capability on upgrade.
CREATE TABLE IF NOT EXISTS projects (
    id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    -- Same regex treatment as servers.slug in 0001 — the SQLite original's
    -- GLOB '[a-z0-9-]*' AND slug != '' had the same first-character-only weakness 0002 fixed for
    -- servers, and it was never separately tightened there. Ported to the correct, fully-anchored
    -- constraint directly: this is a fresh schema, so there is no "already shipped, must not edit"
    -- consideration, and porting the weaker pattern faithfully would be preserving a latent bug.
    CONSTRAINT projects_slug_format CHECK (slug ~ '^[a-z0-9-]+$')
);

-- No surrogate id/created_at: the composite key IS the identity of a membership, and "when did
-- this membership start" has no product use today (admin_events already records the
-- project.member_add/member_remove/member_role_change actions with a timestamp on the change).
CREATE TABLE IF NOT EXISTS project_members (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,  -- viewer | poweruser | admin (validated in app, same as users.role)
    PRIMARY KEY (user_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);

-- project_id is nullable at the column level but is made fully populated by the backfill below
-- and treated as effectively-required by the application from here forward — ServerRepo.create /
-- ApiKeyRepo.create both resolve an explicit project_id. A NULL here (unreachable through the
-- app, but not physically impossible — e.g. a hand-edited row) is handled fail-closed by the
-- project scoping filter: a server/key with no project matches no project's queries, the same
-- "unrecognized state -> no access" discipline as an unrecognized project_members.role.
--
-- Note the SQLite original justified the nullability partly as a limitation ("SQLite can't add a
-- NOT NULL column without a default to a non-empty table in one statement anyway"). Postgres
-- CAN do that. Kept nullable regardless, because the fail-closed application semantics above are
-- the real reason to allow it — the SQLite limitation was a coincidental second reason, and
-- removing it doesn't change the design call.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id);

CREATE INDEX IF NOT EXISTS idx_servers_project ON servers(project_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_project ON api_keys(project_id);

-- Backfill: create 'default', assign every existing server/key to it, make every existing user an
-- admin member of it. Same to_char(... 'utc' ...) UTC-with-Z timestamp shape as 0006_users.sql —
-- see that file's comment on why a timezone-less string would mis-render in the UI.
INSERT INTO projects (slug, name, created_at)
  SELECT 'default', 'Default', to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ON CONFLICT (slug) DO NOTHING;

UPDATE servers SET project_id = (SELECT id FROM projects WHERE slug = 'default')
  WHERE project_id IS NULL;

UPDATE api_keys SET project_id = (SELECT id FROM projects WHERE slug = 'default')
  WHERE project_id IS NULL;

-- Every existing user (any global role, including viewer/operator) becomes an ADMIN member of
-- 'default'. A fresh (pre-setup, zero-row users table) database has no rows to backfill here,
-- matching every other migration's "no-op on a fresh install" shape.
INSERT INTO project_members (user_id, project_id, role)
  SELECT u.id, (SELECT id FROM projects WHERE slug = 'default'), 'admin'
  FROM users u
  ON CONFLICT (user_id, project_id) DO NOTHING;

-- usage_rollups.project_id already exists as a nullable placeholder column (0009_usage_rollups.sql)
-- — backfill it here now that 'default' exists for real, so pre-existing usage history is
-- attributed rather than left NULL forever. Rows with the server_id sentinel 0 (no server context)
-- are left NULL — there is no project to attribute them to.
UPDATE usage_rollups SET project_id = s.project_id
  FROM servers s
  WHERE s.id = usage_rollups.server_id
    AND usage_rollups.project_id IS NULL
    AND usage_rollups.server_id != 0;
