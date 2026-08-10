# Projects (multi-tenancy)

Acropolis supports scoping servers, API keys, audit history, and usage rollups into **projects**
— named groups within a single instance. Read the "What this is not" section before you plan a
deployment around it: this is visibility scoping, not tenant isolation.

## Option A vs. Option B: do you need this at all?

Two ways to run several teams/environments through Acropolis:

- **Option A — one Acropolis instance per team.** Zero code, deployment pattern only: stand up a
  separate container/pod per team, each with its own data directory, admin, and servers. This
  gives you real isolation (separate SQLite files, separate process, a compromise of one
  instance's admin credentials doesn't touch another's) and is still the right answer for small
  deployments or when teams genuinely should not share fate with each other's config or audit
  log.
- **Option B — one instance, multiple projects (this feature).** Selected for Acropolis when a
  single control plane, single set of instance-wide settings (auth mode, webhook config, GitOps
  source), and cross-project visibility for instance admins is worth more than the isolation
  Option A gives you for free. This is the shape documented below.

If you don't need multiple projects, everything works exactly as before: a fresh instance (or
one upgraded from a pre-projects release) has exactly one project, `default`, and every route
behaves byte-identically to a build that never had this feature.

## What this is not

**"Projects," not "tenants."** This is one scoping level with no isolation guarantees:

- No separate crypto domains — a secret provider (local/encrypted/OpenBao) is configured once,
  instance-wide, and serves every project.
- No per-project settings overrides — `auth_mode`, webhook configuration, GitOps source, audit
  retention, and every other instance-wide setting apply identically across all projects.
- No noisy-neighbor QoS — rate limits and quotas are per-server/per-key, same as before; a
  heavily-used project can affect shared resources (the process, the SQLite write lock) the same
  way any heavy project-less usage always could.
- No data-plane network isolation — every project's servers are proxied through the same
  Acropolis process and the same outbound HTTP client.

If you need real isolation between tenants — separate blast radius for a credential leak,
separate crypto domains, separate resource guarantees — run separate instances (Option A above),
not separate projects.

## The two role systems, and the one place they touch

This is the part to get right before configuring anything. There are **two independent role
systems**:

- **Global role** (`users.role`, unchanged from enterprise #2/#3's identity/RBAC work) —
  instance-level authority: creating/deleting projects, managing users, global settings, config
  import/export, GitOps reconcile. Three tiers: `viewer < operator < admin`.
- **Project role** (`project_members.role`, new) — authority over ONE project's resources
  (servers, their policies, API keys minted in that project, that project's audit/usage view).
  Held independently per `(user, project)` pair. Three tiers, structurally identical to the
  global hierarchy but a SEPARATE rank space: `viewer < poweruser < admin`. ("Poweruser" is this
  system's name for the tier "operator" plays globally.)

A user's authority in project A has **nothing to do with** their authority in project B, or with
their global role — with exactly one exception:

> **A user whose GLOBAL role is `admin` is implicitly `admin` in every project, with no
> membership row required.** This is what lets one instance administrator actually administer
> the whole instance without being manually added to every project as it's created. It is a
> superset relationship, not a parallel path — a global admin's project authority is never
> capped by a stale/lesser membership row that might also exist for them.

Every other combination is real:

| Global role | Project role in A | Effective authority in A |
|---|---|---|
| `admin` | (any, or none) | full admin — the superset always wins |
| `viewer` | `admin` in A | full admin in A — low global role does not cap a high project role |
| `operator` | `viewer` in A | capped at viewer in A — high global role does NOT leak extra project authority |
| `viewer` | none in B | **no access** to B at all — fail-closed, not "viewer by default" |

No membership row (and not a global admin) means **no access**, full stop. An unrecognized
`project_members.role` value (a hand-edited database, a future migration this binary doesn't
know about) resolves to no access everywhere for that membership — the same
`ROLE_RANK.get(role) -> None -> denied` pattern the global RBAC system already established.

## What's project-scoped vs. instance-wide

Every route in the control plane was explicitly audited and assigned one of two gates:

**Project-scoped** (`require_project_role`, resolved from the resource):
- Servers: list/get/create/update/delete/probe, tools, test-call
- Server policy: get/set
- API keys: list/create/patch/quota/delete
- Audit and usage views, when a `project_id` filter is supplied (both stay instance-wide by
  default when no filter is given — see below)

**Instance-wide** (`require_role`, global, unchanged):
- Settings, config export/import, GitOps drift/reconcile
- User management (creating users, changing global roles, enabling/disabling accounts)
- `/me`, `/admin-events`, `/tracing/status`
- Project CRUD itself (creating/deleting a project is instance-level authority — a project admin
  does not get to create sibling projects)

`/stats`, `/audit`, `/audit/export.csv`, and `/usage` are a deliberate middle case: they stay
**global-viewer-gated and instance-wide by default** (matching their pre-feature behavior
exactly — a global viewer could already see this data for every server), and accept an
**optional `project_id` query parameter** to scope the view for the frontend's project switcher.
This is not a security boundary change — a global viewer already saw this information
unfiltered; the filter is a convenience, not a new restriction.

Project **membership management** (`PUT`/`DELETE /api/v1/projects/{id}/members`) is gated
project-admin-or-global-admin — this is the one place a project admin who is not a global admin
gets real write authority beyond their own project's resources.

## Deliberate behavior change: aggregate `tools/list` is now per-project

Before this feature, the aggregate `/mcp` endpoint's `tools/list` and `server/discover` merged
**every** enabled, `in_aggregate` server on the instance, regardless of which key called it. That
is no longer true: a key's aggregate view is scoped to its own project's servers only. A key
with no project (unreachable through the app, but see "fail-closed" below) or a caller under
`auth_mode: open` (no key at all) still gets the pre-feature instance-wide view — there's no
notion of "a project" to scope to without a key.

If you relied on the aggregate endpoint spanning every server regardless of project, either keep
everything in the `default` project (the byte-identical-on-upgrade path — see below) or mint
keys per-project deliberately now that projects exist.

## Keys are project-bound, transitively

Every API key belongs to exactly one project (`api_keys.project_id`). This is a **separate**
check from `server_scopes` (the existing, data-plane-only slug allowlist on a key) — the two
compose:

1. `server_scopes` (if set) must permit the target server's slug.
2. The key's project must match the target server's project.

Both checks must pass. A key minted in project A can never reach a server in project B, even if
`server_scopes` was (mis)configured to name that server by slug — this is enforced in
`argus/pipeline.py` before the request is ever dispatched to the upstream, and the refusal is
audited like any other blocked call.

## Upgrading from a pre-projects release

The migration (`db/migrations/0011_projects.sql`) is fully automatic and preserves existing
behavior exactly:

1. A `default` project is created.
2. Every existing server and API key is assigned to `default`.
3. **Every existing user becomes an `admin` member of `default`** — not viewer, not poweruser.
   This is deliberate: before this feature, your global role WAS your full authority over every
   server (RBAC had no per-server dimension). Backfilling anyone as less than project-admin would
   be a silent capability regression on upgrade, which conflicts with the byte-identical-on-
   upgrade guarantee every migration in this project holds to.

A single-project (`default`-only) instance behaves identically to a pre-feature build — this is
proven by running the **entire pre-existing test suite unmodified** against the migrated schema,
not just a handful of spot checks.

Note: a user created **after** the migration has run (e.g. the first-run setup wizard's admin
on a brand-new instance) gets **no** automatic membership row — that would be a permissive
default for a genuinely new user, which fail-closed design explicitly rejects. A fresh instance's
setup-wizard admin administers `default` via the global-admin superset, exactly like any other
global admin administers any project with zero membership rows.

## Config export/import and GitOps

Config export carries each server's `project_slug` (not `project_id` — ids aren't portable
across instances, slugs are the identity the rest of config-io already uses). Re-importing
preserves project assignment: an entry with no `project_slug` in the file (an export from a
pre-projects build, or a hand-written file) is treated as "leave assignment alone" on update and
lands in the `default` project on create — it never un-assigns an existing server.

**Config export/import and GitOps reconcile/drift stay instance-wide and global-admin-only,
unaffected by any project role.** A project admin — even a project admin of every project on the
instance — does not get GitOps or config-import authority merely by being a project admin. This
mirrors the existing rule that GitOps reconcile is "config import by another name," and that
import has always been a global-admin-only, instance-wide action.

## Data model

- `projects` (id, slug, name, created_at)
- `project_members` (user_id, project_id, role) — composite primary key, one row per membership
- `servers.project_id`, `api_keys.project_id` — the resource's owning project
- `usage_rollups.project_id` — populated at write time and backfilled by the migration; audit
  events (`audit.db`, a separate SQLite file from `gateway.db` where projects live) are scoped by
  resolving the calling project's server slugs and filtering on `server_slug IN (...)`, since
  there is no cross-database JOIN available.
