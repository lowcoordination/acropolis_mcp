-- 0011_projects.sql: multi-tenancy / project scoping (enterprise #4, issue #5).
--
-- "Projects," not "tenants" — one scoping level, no isolation guarantees (no separate crypto
-- domains, no per-project noisy-neighbor QoS). Servers and API keys belong to exactly one
-- project; audit rows and usage rollups are scoped transitively through the server/key they
-- reference. See docs/projects.md for the full design writeup and the explicit "not isolation"
-- statement.
--
-- TWO INDEPENDENT ROLE SYSTEMS (see archon/rbac.py's module docstring for the global side,
-- archon/project_rbac.py for this side):
--   - users.role (existing, unchanged by this migration) is the GLOBAL role — instance-wide
--     authority: creating/deleting projects, managing users/settings, config import/export,
--     GitOps. A global 'admin' is an implicit superset admin of EVERY project (see
--     archon/project_rbac.py's require_project_role) — no membership row required.
--   - project_members.role (new, this table) is the PROJECT role — viewer < poweruser < admin,
--     held independently per (user_id, project_id). Structurally identical to the global
--     ROLE_RANK hierarchy, but a completely separate rank space: a user can be project-admin in
--     A, project-viewer in B, and have no membership (= no access) in C, independent of their
--     global role.
--
-- Backfill (design decision 5 in 03-multi-tenancy.md): every existing server and key lands in
-- a new 'default' project, and EVERY EXISTING USER becomes an 'admin' MEMBER of it — not
-- viewer, not poweruser. This is deliberate, not generous: pre-this-feature, every authenticated
-- user's global role WAS their full authority over every server (RBAC's ROLE_RANK only gated
-- what operation they could do, never WHICH server). Backfilling anyone as less than
-- project-admin in 'default' would silently take away capability on upgrade — the opposite of
-- the byte-identical-on-upgrade guarantee every prior enterprise migration (0007_users chief
-- among them) has held to. A single-project instance must behave identically to pre-feature
-- master; the full existing test suite run against this migrated schema is the proof (see
-- tests/integration/test_projects_migration.py).
CREATE TABLE IF NOT EXISTS projects (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (slug GLOB '[a-z0-9-]*' AND slug != '')
);

-- No surrogate id/created_at: the composite key IS the identity of a membership, and "when did
-- this membership start" has no product use today (admin_events already records the
-- project.member_add/member_remove/member_role_change actions with a timestamp on the change
-- itself, which is the more useful question anyway).
CREATE TABLE IF NOT EXISTS project_members (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,  -- viewer | poweruser | admin (validated in app, same as users.role)
    PRIMARY KEY (user_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);

-- project_id is nullable on servers/api_keys at the ALTER TABLE level (SQLite can't add a NOT
-- NULL column without a default to a non-empty table in one statement anyway) but is made
-- fully populated by the backfill below and is treated as effectively-required by the
-- application from this migration forward — ServerRepo.create/ApiKeyRepo.create both require an
-- explicit project_id argument after this migration. A NULL here (unreachable through the app,
-- but not physically impossible — e.g. a hand-edited DB) is handled fail-closed by the project
-- scoping filter: a server/key with no project matches no project's queries, the same
-- "unrecognized state -> no access" discipline as an unrecognized project_members.role.
ALTER TABLE servers ADD COLUMN project_id INTEGER REFERENCES projects(id);
ALTER TABLE api_keys ADD COLUMN project_id INTEGER REFERENCES projects(id);

CREATE INDEX IF NOT EXISTS idx_servers_project ON servers(project_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_project ON api_keys(project_id);

-- Backfill: create 'default', assign every existing server/key to it, make every existing user
-- an admin member of it.
INSERT INTO projects (slug, name, created_at)
  SELECT 'default', 'Default', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE NOT EXISTS (SELECT 1 FROM projects WHERE slug = 'default');

UPDATE servers SET project_id = (SELECT id FROM projects WHERE slug = 'default')
  WHERE project_id IS NULL;

UPDATE api_keys SET project_id = (SELECT id FROM projects WHERE slug = 'default')
  WHERE project_id IS NULL;

-- Every existing user (any global role, including viewer/operator) becomes an ADMIN member of
-- 'default' — see the header comment above for why 'admin' specifically. A fresh (pre-setup,
-- zero-row users table) database has no rows to backfill here, matching every other migration's
-- "no-op on a fresh install" shape.
INSERT INTO project_members (user_id, project_id, role)
  SELECT u.id, (SELECT id FROM projects WHERE slug = 'default'), 'admin'
  FROM users u
  WHERE NOT EXISTS (
    SELECT 1 FROM project_members pm
    WHERE pm.user_id = u.id AND pm.project_id = (SELECT id FROM projects WHERE slug = 'default')
  );

-- usage_rollups.project_id already exists as a nullable placeholder column (0010_usage_rollups.sql,
-- enterprise #11) — backfill it here now that 'default' exists for real, so pre-existing usage
-- history is attributed rather than left NULL forever. NULL rows (server_id sentinel 0 / no
-- server context) are left NULL — there is no project to attribute them to.
UPDATE usage_rollups SET project_id = (
    SELECT s.project_id FROM servers s WHERE s.id = usage_rollups.server_id
  )
  WHERE project_id IS NULL AND server_id != 0
    AND EXISTS (SELECT 1 FROM servers s WHERE s.id = usage_rollups.server_id);
