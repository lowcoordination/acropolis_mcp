# Authentication and Authorization

Acropolis has two independent auth systems:

- **Data-plane auth** (`/mcp/*`) — API keys, unchanged by anything in this document.
- **Control-plane auth** (`/api/v1/*`) — who can administer the gateway, covered here.

Conflating the two is a design error this document is careful to avoid: an operator's role
(viewer/operator/admin) has **no bearing** on what an API key can call, and an API key has no
bearing on control-plane access. See [Data-plane auth is unaffected](#data-plane-auth-is-unaffected)
below.

## Identity: local users and OIDC

Every control-plane action is attributed to a **user** — a row in the `users` table, either:

- **Local**: a username + password, hashed with PBKDF2-HMAC-SHA256 (600k iterations), the same
  scheme the single-admin password always used.
- **OIDC**: authenticated against an external identity provider (Okta, Entra, Google, Keycloak,
  Authentik, or any standards-compliant OIDC provider). No password is stored for these users.

A user can be local-only, OIDC-only, or (if an admin sets a password on an OIDC user) both.

### The single-admin upgrade path

If you're upgrading from a version of Acropolis that predates this milestone, your existing
admin password **keeps working with zero action on your part**. The migration
(`db/migrations/0007_users.sql`) creates a `users` row seeded from your existing
`settings.admin_password_hash`, using the exact same hash — not a re-hash, not a reset, a
byte-for-byte copy of what was already there.

The legacy `admin_password_hash` setting itself is **not deleted**. It stays as a fallback read
path — a partially-applied upgrade (or any environment where `users` is unexpectedly empty)
degrades to "the old single-admin flow still works," never to a lockout. Migrations in this
project are forward-only by design (see [Backups and Upgrades](backup-and-upgrades.md)), so this
was treated as the single highest-risk change in the whole identity/RBAC milestone and tested
accordingly — see `tests/integration/test_users_migration.py`.

### Break-glass: `admin_token`

The `ACROPOLIS_ADMIN_TOKEN` environment variable remains a full break-glass path, independent of
the `users` table entirely. It authenticates as a synthetic admin identity regardless of whether
any local user exists, is enabled, or has the right role — including if the `users` table itself
is somehow wrong. Keep it set (and rotated, and out of version control) as your recovery path if
something ever goes sideways with the user/role data.

```bash
curl -H "Authorization: Bearer $ACROPOLIS_ADMIN_TOKEN" http://localhost:8000/api/v1/servers
```

Actions taken via `admin_token` are recorded in the control-plane audit log under the actor
`admin-token`.

## OIDC setup

OIDC uses **Authorization Code + PKCE** — the browser never handles an IdP token directly; it's
exchanged for Acropolis's own session cookie server-side. This keeps session revocation
(`session_version`) working uniformly whether a user authenticated locally or via SSO.

Configure it via the `settings` table (no dedicated settings-API route ships in this milestone —
see [Known limitations](#known-limitations) below):

| Setting | Purpose |
|---|---|
| `oidc_enabled` | `"true"` to turn OIDC on |
| `oidc_issuer` | The IdP's issuer URL (its `/.well-known/openid-configuration` is derived from this) |
| `oidc_client_id` / `oidc_client_secret` | Registered with your IdP |
| `oidc_redirect_uri` | Must exactly match what's registered at the IdP — Acropolis never accepts a redirect target from the request itself |
| `oidc_scopes` | Defaults to `openid email profile` |
| `oidc_allowed_domains` | Comma-separated email domains permitted to self-provision (JIT) |
| `oidc_allowed_groups` | Comma-separated IdP group names permitted to self-provision |
| `oidc_group_claim` | Which ID-token claim carries group membership (defaults to `groups`) |
| `oidc_default_role` | Role for a JIT-provisioned user with no group-based role match (defaults to `viewer`) |
| `oidc_jit_provisioning` | `"false"` to require an admin to pre-create every user (no self-service accounts at all) |

**Identity is keyed on the IdP's `sub` claim, never email.** Emails change, and matching on them
is a known account-takeover vector when an IdP allows email reuse across accounts — two users
who happen to share an email but have different `sub` values are, correctly, two separate
Acropolis accounts.

### JIT provisioning and the allowlist

On a **first** successful login from an unrecognized `sub`, Acropolis can auto-create a local
user (JIT — just-in-time provisioning). This is gated:

- If `oidc_jit_provisioning` is `false`, an unrecognized subject is rejected outright — every
  user must be pre-created by an admin.
- If both `oidc_allowed_domains` and `oidc_allowed_groups` are empty, JIT provisioning accepts
  **any** successfully authenticated subject. This is the admin's explicit choice by leaving
  both blank — not a silent default — and is only appropriate for a tightly-scoped, trusted IdP
  tenant.
- Otherwise, the subject's email domain or group membership must match one of the configured
  allowlists, or provisioning is denied with a 403.

A group named exactly `viewer`, `operator`, or `admin` in the group claim maps directly to that
role on JIT-provisioned accounts (highest-ranking match wins); otherwise the new user gets
`oidc_default_role`. **The allowlist and role mapping are only evaluated at provisioning time** —
an existing OIDC user's role is not automatically re-derived from IdP group membership on every
subsequent login. If someone's access needs to be revoked, disable their account via the Users
page or `PATCH /api/v1/users/{id}/enabled` (see [Roles](#roles) below); this takes effect on
their very next request, not on their next login.

### Scope: OIDC only

This milestone deliberately does **not** implement SAML, SCIM, or LDAP. OIDC covers the large
majority of modern identity providers. SCIM in particular is a large independent integration
surface (automated user lifecycle sync) and, if ever wanted, should be its own project.

## Roles

Three roles, stored as a plain string (not a database enum) so a future role can be added
without a schema migration:

| Role | Can | Cannot |
|---|---|---|
| **viewer** | Dashboard, server list, tool list, audit log, config export | Any mutation |
| **operator** | Everything viewer can, plus policy edits, re-probe, tools refresh, the in-UI tool tester | Minting/revoking API keys, settings, config import, user management |
| **admin** | Everything | — |

Roles are **hierarchical** (`viewer < operator < admin`) — enforcement compares rank, not
equality, so "admin can do everything operator can" is structural rather than something every
route has to individually get right.

### Enforcement is per-route, server-side

Every control-plane route is individually annotated with its minimum required role
(`archon/rbac.py`'s `require_role(minimum)`, wired into `archon/api.py`) — there is no blanket
gate. This is deliberately explicit and greppable (`grep require_role archon/api.py` enumerates
every protected route and its floor) rather than checking role inside handler bodies, which is
invisible in the route signature and easy to forget on a new route.

**An unrecognized role string is denied everywhere, never granted a permissive default.** If the
`users` table ever contains a role that isn't `viewer`/`operator`/`admin` — a typo, a hand-edited
row, a future version's role this binary doesn't know about — that user gets 403 on every route,
including the lowest-privilege ones. This is the same failure-mode discipline as this project's
own history with unvalidated mode/state strings silently falling through to a permissive
default; it's treated as a hard requirement here.

Authenticated-but-unauthorized returns **403**, not 404 (the resource exists) and not 401 (the
caller is authenticated).

The frontend hides UI it knows a role can't use — but this is a courtesy, not the enforcement
boundary. Every mutating request is checked server-side regardless of what the UI shows or
hides; bypassing the UI entirely (e.g. with `curl`) is not a way around role enforcement.

### Why config import is admin-only despite editing policies

An operator can edit any single server's policy directly. But `POST /api/v1/config/import` is
admin-only, even though it also edits policies. The reasoning: one import can rewrite the entire
instance's configuration in a single request — every server, every policy, settings — which is a
fundamentally different blast radius than one operator tuning one server's allowlist. The
viewer/operator/admin separation exists specifically to contain that kind of blast radius, and
treating "editing a policy" as one undifferentiated capability would erase the distinction the
roles are meant to draw. The same reasoning extends to `POST /api/v1/config/reconcile` (GitOps
reconcile) — it's config import by another name, sourced from git instead of an uploaded file.

### Why operators can't mint API keys

API key `server_scopes` is a *data-plane* restriction, orthogonal to control-plane roles — but
there's one real interaction: if an operator could mint a key, they could use it against the
data plane and act entirely outside the boundary their control-plane role is supposed to
enforce. Key management (`/api/v1/keys/*`) is admin-only specifically to close that path, not
merely because keys feel sensitive in the abstract.

## Managing users

Admins can manage users from the **Users** page in the UI, or directly via the API:

- `GET /api/v1/users` — list
- `POST /api/v1/users` — create (local, with a temporary password)
- `PATCH /api/v1/users/{id}/role` — change role
- `PATCH /api/v1/users/{id}/enabled` — enable/disable

A role change or an enable/disable both take effect **immediately** — on the target user's very
next request, not after their session naturally expires (sessions are otherwise valid for up to
7 days). This is done by bumping a per-user revocation counter independent of the global one, so
disabling or demoting one user never logs out anyone else.

An admin cannot disable their own account (a footgun guard, not a security boundary — it can
still be done via a second admin account or the `admin_token` break-glass path).

Every role change and enable/disable change writes a control-plane audit event (see
[Audit and Compliance](audit-and-compliance.md)) — privilege changes are exactly what that log
exists to make reviewable.

## Data-plane auth is unaffected

None of the above changes how `/mcp/*` is authenticated. `auth_mode` (`open`/`keyed`) and API
key `server_scopes` remain the entire data-plane authorization story. A control-plane session
cookie grants **zero** access to `/mcp/*` — there is no code path that even attempts to read one
there. This was a deliberate design boundary from the start of this milestone (conflating the
two would break every existing MCP client integration) and is regression-tested explicitly in
`tests/integration/test_identity.py`.

## Known limitations

- **No settings-API/UI for OIDC configuration.** The OIDC settings above are set via the
  `settings` table directly (a small script, or a future admin API) — there's no `PUT /settings`
  support for them yet and no OIDC config panel in the Settings page. The handshake itself is
  fully built and tested; the admin-facing configuration surface is a reasonable follow-up.
- **ID-token signature verification is not performed** — safe under this flow's specific threat
  model (the token arrives over a direct, back-channel exchange gated by `client_secret` and
  PKCE, never through the browser), but full JWKS-based signature verification would be a
  reasonable hardening addition if this ever needs to defend against a compromised/malicious
  token endpoint specifically. `aud`/`iss` claims are validated.
- **Live-tested only against a mocked IdP** (see `tests/integration/test_oidc.py`), not a real
  Keycloak/Authentik/Okta instance — no local IdP container was available in the environment
  this was built in. The handshake logic (state/nonce/PKCE/allowlist/JIT/sub-keying) is proven;
  interop quirks with a specific real-world provider are not.
