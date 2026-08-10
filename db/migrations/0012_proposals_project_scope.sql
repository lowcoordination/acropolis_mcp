-- Approvals: project-scope proposals (remediation, review 2026-08-10 — the /code-review +
-- /security-scan pass over enterprise Epic 2 found /proposals* gated on GLOBAL admin
-- (require_role("admin")) while the thing being proposed, a server policy change, is
-- project-owned. Two consequences fixed here: (1) any global admin could preview a live
-- recomputed diff of every project's pending changes, a visibility surface multi-tenancy
-- otherwise closes; (2) a project-admin-who-is-global-viewer could PROPOSE a change
-- (require_project_role gates PUT /servers/{slug}/policy) but never APPROVE one in their own
-- project without a global admin — a four-eyes deadlock the codebase already avoids for
-- /keys (see archon/api.py's project-admin-but-global-viewer handling on list_keys).
--
-- project_id is populated for 'server_policy' proposals (backfilled below from the target
-- server's project) and left NULL for 'config_import' proposals — a config import can touch
-- servers across every project in one file, so it stays instance-wide and global-admin-gated,
-- same as before this migration. This asymmetry is enforced in code (archon/api.py's project
-- resolver for the /proposals routes must require global admin when project_id IS NULL,
-- never silently downgrade), not just left implicit in the schema.
--
-- Nullable at the column level for the same reason 0010_projects.sql's server/key project_id
-- columns are: NULL is a real, meaningful state here (every config_import proposal), not just
-- an unreachable edge case to guard against.
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id);

-- Backfill: resolve every existing 'server_policy' proposal's target_id (a server slug) to that
-- server's current project_id. A proposal whose target server has since been deleted (target_id
-- no longer matches any server) is left with project_id NULL rather than erroring the
-- migration — ApprovalService.preview()/approve() already handle a vanished target server as a
-- stale/not-found case at read time (see archon/approvals.py), so a NULL project_id here just
-- means the route-layer project check falls back to requiring global admin for that one
-- orphaned row, which is the safe default for a target that no longer resolves to anything.
-- 'config_import' proposals are untouched — they keep the column's NULL default, matching the
-- "instance-wide, not project-owned" status they've always had.
UPDATE proposals
SET project_id = servers.project_id
FROM servers
WHERE proposals.target_type = 'server_policy'
  AND proposals.target_id = servers.slug
  AND proposals.project_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_proposals_project ON proposals(project_id);
