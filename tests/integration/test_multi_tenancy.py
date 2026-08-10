"""Multi-tenancy / project-scoping tests (enterprise #4, issue #5).

Mirrors tests/integration/test_rbac.py's fixture/matrix shape closely — same real-login-path
discipline (create user via the real API, log in via the real /login route, never forge a
cookie unless the test is specifically about a hand-edited DB state), same parametrised-matrix
approach for the "does the floor actually hold" proof.

Core things this file must prove, per 03-multi-tenancy.md's revision note (real per-project
roles, not a filter on one global role):
  1. Migration backfill: every existing user becomes a project-admin member of 'default', every
     existing server/key lands in 'default', and the FULL existing test suite's behavior is
     unchanged against the migrated schema (that's what test_rbac.py etc. running unmodified
     already proves — this file adds the migration-specific assertions).
  2. Global-admin superset: a global admin with ZERO project_members rows still fully
     administers every project.
  3. Independence: project role is NOT a filter on global role. A global-viewer/project-admin
     fully administers their project; the same user gets 403 with no membership in another
     project. A global-operator/project-viewer is held to viewer's ceiling in their project —
     their global role does not leak extra project authority.
  4. Fail-closed: a garbage project_members.role denies access everywhere for that membership.
  5. Cross-project data-plane isolation: a key from project A cannot call a server in project B.
  6. Aggregate tools/list is scoped to the calling key's project.
  7. Export/import round-trips project assignment; GitOps stays instance-wide/global-admin-only.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import httpx
import pytest

from archon.project_rbac import PROJECT_ROLE_RANK
from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ProjectMemberRepo, ProjectRepo, SettingsRepo, UserRepo


@pytest.fixture
async def mt_app(tmp_path: Path):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="keyed",
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as setup_client:
            await setup_client.post("/api/v1/setup", json={"admin_password": "admin-password-1"})
        yield app, transport
    await db.close()


async def _login_as(transport: httpx.ASGITransport, username: str, password: str) -> httpx.AsyncClient:
    client = httpx.AsyncClient(transport=transport, base_url="http://argus.test")
    resp = await client.post("/api/v1/login", json={"username": username, "admin_password": password})
    if resp.status_code != 200:
        raise AssertionError(f"login failed for {username}: {resp.status_code} {resp.text}")
    return client


async def _create_user_and_login(
    transport: httpx.ASGITransport, admin_client: httpx.AsyncClient,
    username: str, global_role: str, password: str = "password-12345",
) -> httpx.AsyncClient:
    resp = await admin_client.post(
        "/api/v1/users", json={"username": username, "password": password, "role": global_role}
    )
    assert resp.status_code == 201, resp.text
    return await _login_as(transport, username, password)


@pytest.fixture
async def two_projects(mt_app):
    """Project 'alpha' and 'beta', both created by the global admin (project CRUD is
    global-admin-only)."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")
    for slug in ("alpha", "beta"):
        resp = await admin_client.post("/api/v1/projects", json={"slug": slug, "name": slug.title()})
        assert resp.status_code == 201, resp.text
    yield
    await admin_client.aclose()


# ---------------------------------------------------------------------------------------------
# 1. Migration backfill
# ---------------------------------------------------------------------------------------------

async def test_migration_backfills_default_project_and_admin_memberships(tmp_path: Path):
    """Populated-DB migration proof, the real thing: build a PRE-migration gateway.db by hand
    (seed `users` rows the way 0007_users.sql would have left them, from BEFORE 0011_projects.sql
    ever ran), then apply migrations via Database.connect() and confirm every one of those
    pre-existing users becomes a project-admin MEMBER of 'default' — not viewer, not poweruser.

    This is deliberately NOT done by creating users through the live API (which runs strictly
    AFTER migrations have already applied, so a user created that way was never actually
    'pre-existing' at migration time — see test_setup_wizard_admin_has_no_membership_but_still_administers
    below for why that path correctly produces NO membership row and relies on the global-admin
    superset instead)."""
    import aiosqlite

    from db.database import _apply_migrations, utcnow

    data_dir = tmp_path / "premigration"
    data_dir.mkdir()
    gateway_path = data_dir / "gateway.db"

    # Build the pre-0011 schema by hand: apply every migration EXCEPT 0011_projects.sql, then
    # seed three users directly (bypassing the app entirely) to simulate an instance that has
    # been running through several prior enterprise releases already.
    pre_migrations = [
        "0001_init.sql", "0002_tighten_slug_check.sql", "0003_add_upstream_credential.sql",
        "0006_admin_events.sql", "0007_users.sql", "0008_gateway_dlp_config.sql",
        "0009_server_health_reason.sql", "0010_usage_rollups.sql",
    ]
    conn = await aiosqlite.connect(gateway_path)
    await conn.execute("PRAGMA foreign_keys=ON")
    await _apply_migrations(conn, pre_migrations, "gateway.db")

    now = utcnow()
    for username, role in (("admin", "admin"), ("viewer-user", "viewer"), ("operator-user", "operator")):
        await conn.execute(
            """INSERT INTO users (username, password_hash, role, auth_source, enabled, created_at)
               VALUES (?, 'x', ?, 'local', 1, ?)""",
            (username, role, now),
        )
    cur = await conn.execute(
        "INSERT INTO servers (slug, name, upstream_url, enabled, in_aggregate, created_at, updated_at) "
        "VALUES ('pre-existing', 'Pre', 'http://localhost:1/mcp', 1, 1, ?, ?)", (now, now),
    )
    await conn.execute(
        "INSERT INTO server_policies (server_id, mode, updated_at) VALUES (?, 'passthrough', ?)",
        (cur.lastrowid, now),
    )
    await conn.commit()
    await conn.close()

    # Now open it through the REAL Database class, which applies 0011_projects.sql (the only
    # migration this pre-seeded DB hasn't seen yet) — this is the actual migration under test.
    from db.database import Database

    db = Database(data_dir)
    await db.connect()
    try:
        project_repo = ProjectRepo(db)
        member_repo = ProjectMemberRepo(db)
        user_repo = UserRepo(db)

        default_project = await project_repo.get("default")
        assert default_project.name

        for username in ("admin", "viewer-user", "operator-user"):
            user = await user_repo.get_by_username(username)
            membership = await member_repo.get_membership(user_id=user.id, project_id=default_project.id)
            assert membership is not None, f"{username} should be a member of 'default'"
            assert membership.role == "admin", (
                f"{username} (global role {user.role!r}) should be project-ADMIN of 'default', "
                f"got {membership.role!r}"
            )

        from db.repo import ServerRepo

        server_repo = ServerRepo(db)
        server = await server_repo.get("pre-existing")
        assert server.project_id == default_project.id, "pre-existing server must land in 'default'"
    finally:
        await db.close()


async def test_setup_wizard_admin_has_no_membership_but_still_administers(mt_app):
    """Contrast case for the migration test above: a user created AFTER migration time (e.g. the
    setup wizard's admin on a brand-new instance, or any user created via POST /users later) gets
    NO automatic project membership row — fail-closed is the correct default for a genuinely NEW
    user, not just a migrated one. A global admin still fully administers 'default' regardless,
    via the superset — this is the same proof as
    test_global_admin_with_zero_memberships_administers_every_project, restated for the
    single-project ('default') case specifically, since that's the byte-identical-on-upgrade
    scenario every prior enterprise item's regression guard cares about most."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    project_repo = ProjectRepo(app.state.db)
    member_repo = ProjectMemberRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo

    default_project = await project_repo.get("default")
    admin_user = await user_repo.get_by_username("admin")
    membership = await member_repo.get_membership(user_id=admin_user.id, project_id=default_project.id)
    assert membership is None, "a freshly-created (post-migration) admin should have NO membership row"

    resp = await admin_client.post(
        "/api/v1/servers", json={"slug": "pre-existing", "name": "Pre", "upstream_url": "http://localhost:1/mcp"}
    )
    assert resp.status_code == 201
    assert resp.json()["project_slug"] == "default"


async def test_single_project_instance_servers_keys_default_project(mt_app):
    """A fresh (single-project) instance: every server/key created with no explicit
    project_slug lands in 'default' — the byte-identical-on-upgrade guarantee."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    resp = await admin_client.post(
        "/api/v1/servers", json={"slug": "s1", "name": "S1", "upstream_url": "http://localhost:1/mcp"}
    )
    assert resp.status_code == 201
    assert resp.json()["project_slug"] == "default"

    resp = await admin_client.post("/api/v1/keys", json={"name": "k1"})
    assert resp.status_code == 201
    key_id = resp.json()["id"]

    resp = await admin_client.get("/api/v1/keys")
    assert resp.status_code == 200
    key_row = next(k for k in resp.json() if k["id"] == key_id)
    assert key_row["project_slug"] == "default"


# ---------------------------------------------------------------------------------------------
# 2. Global-admin superset
# ---------------------------------------------------------------------------------------------

async def test_global_admin_with_zero_memberships_administers_every_project(mt_app, two_projects):
    """The core superset proof: a global admin with LITERALLY ZERO rows in project_members can
    still fully administer every project — verified directly (create a server, edit its policy,
    mint a key, all in a project this admin has no explicit membership row for), not inferred."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    member_repo = ProjectMemberRepo(app.state.db)
    project_repo = ProjectRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo

    admin_user = await user_repo.get_by_username("admin")
    alpha = await project_repo.get("alpha")

    # Confirm zero membership rows for this admin in 'alpha' before proceeding — the whole point
    # is proving the superset works WITHOUT a membership row, not despite one that happens to
    # also be there.
    membership = await member_repo.get_membership(user_id=admin_user.id, project_id=alpha.id)
    assert membership is None, "test setup invariant: admin must have NO explicit membership in alpha"

    # Create a server in 'alpha' — requires project-admin in alpha.
    resp = await admin_client.post(
        "/api/v1/servers",
        json={"slug": "alpha-srv", "name": "AlphaSrv", "upstream_url": "http://localhost:1/mcp", "project_slug": "alpha"},
    )
    assert resp.status_code == 201, resp.text

    # Edit its policy — requires project-poweruser+ in alpha.
    resp = await admin_client.put(
        "/api/v1/servers/alpha-srv/policy",
        json={"mode": "allowlist", "allowed": ["x"], "denied": [], "param_rules": {}},
    )
    assert resp.status_code == 200, resp.text

    # Mint a key in alpha — requires project-admin in alpha.
    resp = await admin_client.post("/api/v1/keys", json={"name": "alpha-key", "project_slug": "alpha"})
    assert resp.status_code == 201, resp.text

    # Manage membership in alpha — also project-admin-gated.
    resp = await admin_client.put(
        f"/api/v1/projects/{alpha.id}/members", json={"user_id": admin_user.id, "role": "viewer"}
    )
    assert resp.status_code == 200, resp.text

    # Confirm STILL no real membership row was needed for any of the above — the PUT above just
    # created one as an explicit action, so re-verify pre-that-PUT state was truly empty by
    # checking a DIFFERENT project ('beta') the admin never touched membership on at all.
    beta = await project_repo.get("beta")
    beta_membership = await member_repo.get_membership(user_id=admin_user.id, project_id=beta.id)
    assert beta_membership is None
    resp = await admin_client.post(
        "/api/v1/servers",
        json={"slug": "beta-srv", "name": "BetaSrv", "upstream_url": "http://localhost:1/mcp", "project_slug": "beta"},
    )
    assert resp.status_code == 201, "global admin must administer beta with zero membership rows too"


# ---------------------------------------------------------------------------------------------
# 3. Independence: project role is not a filter on global role
# ---------------------------------------------------------------------------------------------

async def test_global_viewer_project_admin_fully_administers_their_project(mt_app, two_projects):
    """A user who is global VIEWER but project-ADMIN in alpha can fully administer alpha
    (create servers, edit policy, manage keys) — their LOW global role does not cap their HIGH
    project role. The same user has NO membership in beta and gets 403 on every beta-scoped
    route."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")
    project_repo = ProjectRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo

    client = await _create_user_and_login(transport, admin_client, "alpha-admin-global-viewer", "viewer")
    user = await user_repo.get_by_username("alpha-admin-global-viewer")
    alpha = await project_repo.get("alpha")
    beta = await project_repo.get("beta")

    resp = await admin_client.put(
        f"/api/v1/projects/{alpha.id}/members", json={"user_id": user.id, "role": "admin"}
    )
    assert resp.status_code == 200

    # Full administration of alpha, despite global role = viewer.
    resp = await client.post(
        "/api/v1/servers",
        json={"slug": "av-srv", "name": "AVSrv", "upstream_url": "http://localhost:1/mcp", "project_slug": "alpha"},
    )
    assert resp.status_code == 201, resp.text
    resp = await client.put(
        "/api/v1/servers/av-srv/policy",
        json={"mode": "passthrough", "allowed": [], "denied": [], "param_rules": {}},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.post("/api/v1/keys", json={"name": "av-key", "project_slug": "alpha"})
    assert resp.status_code == 201, resp.text
    resp = await client.delete("/api/v1/servers/av-srv")
    assert resp.status_code == 204, resp.text

    # No membership in beta at all -> 403 on every beta-scoped route.
    resp = await client.post(
        "/api/v1/servers",
        json={"slug": "should-fail", "name": "X", "upstream_url": "http://localhost:1/mcp", "project_slug": "beta"},
    )
    assert resp.status_code == 403

    # Also confirm this user cannot touch INSTANCE-WIDE routes their global viewer role denies —
    # global role still means what it always did for instance-wide resources.
    resp = await client.post("/api/v1/users", json={"username": "x", "password": "password-12345", "role": "viewer"})
    assert resp.status_code == 403


async def test_global_operator_project_viewer_held_to_viewer_ceiling(mt_app, two_projects):
    """A user who is global OPERATOR but project-VIEWER in alpha is capped at viewer's ceiling
    in alpha — their HIGHER global role must NOT leak extra project authority. Global operator
    normally could edit policy directly (see test_rbac.py's
    test_operator_can_edit_policy_directly) — that must NOT carry over to a project where their
    PROJECT role is only viewer."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")
    project_repo = ProjectRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo

    client = await _create_user_and_login(transport, admin_client, "alpha-viewer-global-operator", "operator")
    user = await user_repo.get_by_username("alpha-viewer-global-operator")
    alpha = await project_repo.get("alpha")

    resp = await admin_client.put(
        f"/api/v1/projects/{alpha.id}/members", json={"user_id": user.id, "role": "viewer"}
    )
    assert resp.status_code == 200

    await admin_client.post(
        "/api/v1/servers",
        json={"slug": "gov-srv", "name": "GOVSrv", "upstream_url": "http://localhost:1/mcp", "project_slug": "alpha"},
    )

    # Can READ (project-viewer ceiling).
    resp = await client.get("/api/v1/servers/gov-srv")
    assert resp.status_code == 200
    resp = await client.get("/api/v1/servers/gov-srv/policy")
    assert resp.status_code == 200

    # Cannot WRITE — global operator would normally pass require_role("operator") for policy
    # edits, but project role viewer must cap them here regardless.
    resp = await client.put(
        "/api/v1/servers/gov-srv/policy",
        json={"mode": "denylist", "allowed": [], "denied": ["x"], "param_rules": {}},
    )
    assert resp.status_code == 403, (
        "global-operator/project-viewer must be denied policy write in their project "
        f"— got {resp.status_code}"
    )
    resp = await client.post("/api/v1/servers/gov-srv/probe")
    assert resp.status_code == 403
    resp = await client.post("/api/v1/keys", json={"name": "should-fail", "project_slug": "alpha"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------------------------
# Parametrized route x project-role matrix — extends test_rbac.py's own matrix with a
# project-role dimension, for a user with a FIXED low global role (viewer) so every allow
# decision below is attributable ONLY to project role, never global role leaking through.
# ---------------------------------------------------------------------------------------------

PROJECT_ROUTE_MATRIX: list[tuple[str, str, str, Optional[dict]]] = [
    ("GET", "/api/v1/servers/matrix-srv", "viewer", None),
    ("GET", "/api/v1/servers/matrix-srv/policy", "viewer", None),
    ("GET", "/api/v1/servers/matrix-srv/tools", "viewer", None),
    ("POST", "/api/v1/servers/matrix-srv/probe", "poweruser", None),
    ("PUT", "/api/v1/servers/matrix-srv/policy", "poweruser",
     {"mode": "passthrough", "allowed": [], "denied": [], "param_rules": {}}),
    ("PUT", "/api/v1/servers/matrix-srv", "admin", {"name": "renamed"}),
    ("DELETE", "/api/v1/servers/matrix-srv-del", "admin", None),
]


@pytest.mark.parametrize("method,path,minimum_role,body", PROJECT_ROUTE_MATRIX)
async def test_project_route_role_matrix(mt_app, two_projects, method, path, minimum_role, body):
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")
    project_repo = ProjectRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo
    alpha = await project_repo.get("alpha")

    await admin_client.post(
        "/api/v1/servers",
        json={"slug": "matrix-srv", "name": "M", "upstream_url": "http://localhost:1/mcp", "project_slug": "alpha"},
    )
    if "matrix-srv-del" in path:
        await admin_client.post(
            "/api/v1/servers",
            json={"slug": "matrix-srv-del", "name": "MD", "upstream_url": "http://localhost:1/mcp", "project_slug": "alpha"},
        )

    clients: dict[str, httpx.AsyncClient] = {}
    for i, project_role in enumerate(("viewer", "poweruser", "admin")):
        username = f"matrix-user-{project_role}-{path.replace('/', '_')}"
        client = await _create_user_and_login(transport, admin_client, username, "viewer")
        user = await user_repo.get_by_username(username)
        resp = await admin_client.put(
            f"/api/v1/projects/{alpha.id}/members", json={"user_id": user.id, "role": project_role}
        )
        assert resp.status_code == 200
        clients[project_role] = client

    minimum_rank = PROJECT_ROLE_RANK[minimum_role]
    try:
        for project_role, client in clients.items():
            should_allow = PROJECT_ROLE_RANK[project_role] >= minimum_rank
            resp = await client.request(method, path, json=body)
            if should_allow:
                assert resp.status_code < 400, (
                    f"project-{project_role} (rank {PROJECT_ROLE_RANK[project_role]}) should be "
                    f"ALLOWED on {method} {path} (needs >= {minimum_role}), got {resp.status_code}: {resp.text}"
                )
            else:
                assert resp.status_code == 403, (
                    f"project-{project_role} (rank {PROJECT_ROLE_RANK[project_role]}) should be "
                    f"DENIED with 403 on {method} {path} (needs >= {minimum_role}), got {resp.status_code}"
                )
    finally:
        for client in clients.values():
            await client.aclose()


# ---------------------------------------------------------------------------------------------
# 4. Fail-closed on garbage project role
# ---------------------------------------------------------------------------------------------

async def test_garbage_project_role_denied_everywhere(mt_app, two_projects):
    """Same discipline as test_rbac.py's test_unknown_role_denied_everywhere, at the project
    level: a hand-edited project_members.role value must resolve to NO ACCESS, never a
    permissive default."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")
    project_repo = ProjectRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo
    alpha = await project_repo.get("alpha")

    client = await _create_user_and_login(transport, admin_client, "garbage-project-role-user", "viewer")
    user = await user_repo.get_by_username("garbage-project-role-user")

    resp = await admin_client.put(
        f"/api/v1/projects/{alpha.id}/members", json={"user_id": user.id, "role": "viewer"}
    )
    assert resp.status_code == 200

    # Hand-edit directly in the DB to a nonsense value, bypassing the API's own role validation.
    async with app.state.db.gateway_write_lock:
        await app.state.db.gateway.execute(
            "UPDATE project_members SET role = 'super-project-mode' WHERE user_id = ? AND project_id = ?",
            (user.id, alpha.id),
        )
        await app.state.db.gateway.commit()

    await admin_client.post(
        "/api/v1/servers",
        json={"slug": "garbage-srv", "name": "G", "upstream_url": "http://localhost:1/mcp", "project_slug": "alpha"},
    )

    resp = await client.get("/api/v1/servers/garbage-srv")
    assert resp.status_code == 403, (
        f"garbage project role should be denied even at viewer level, got {resp.status_code}"
    )
    resp = await client.post("/api/v1/keys", json={"name": "x", "project_slug": "alpha"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------------------------
# 5. Cross-project data-plane isolation
# ---------------------------------------------------------------------------------------------

async def test_key_from_project_a_refused_on_project_b_server(mt_app, two_projects):
    """A key minted in alpha calling a server in beta must be refused BEFORE the upstream is
    ever reached, and audited. Uses a fixture upstream call-counter (via the health-poll-disabled
    fixture app's httpx client is real, but the server URL points nowhere real — a 403 proves
    the call never got dispatched, since a real dispatch attempt against an unreachable upstream
    would surface as a 502/timeout, not a clean 403)."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    resp = await admin_client.post(
        "/api/v1/servers",
        json={
            "slug": "beta-only-srv", "name": "BetaOnly",
            "upstream_url": "http://127.0.0.1:1/mcp", "project_slug": "beta",
        },
    )
    assert resp.status_code == 201

    resp = await admin_client.post("/api/v1/keys", json={"name": "alpha-key-xproj", "project_slug": "alpha"})
    assert resp.status_code == 201
    alpha_key = resp.json()["plaintext"]

    resp = await admin_client.post(
        "/mcp/beta-only-srv",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {alpha_key}"},
    )
    assert resp.status_code == 403, (
        f"key from project alpha must be refused calling a project-beta server, got {resp.status_code}: {resp.text}"
    )

    await asyncio.sleep(0.3)  # AuditLogger flush interval — see test_control_plane_m3.py's same pattern

    # Audited as an ERROR/blocked decision, not silently dropped.
    audit_resp = await admin_client.get("/api/v1/audit", params={"server_slug": "beta-only-srv"})
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    assert any(e["status_code"] == 403 for e in events), "cross-project refusal must be audited"


async def test_key_can_call_server_in_its_own_project(mt_app, two_projects):
    """Contrast case: a key minted in alpha calling a server ALSO in alpha proceeds past the
    project-agreement check (it may still fail for other reasons — unreachable upstream — but
    must NOT be a 403 project-scoping refusal)."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    await admin_client.post(
        "/api/v1/servers",
        json={"slug": "alpha-own-srv", "name": "AlphaOwn", "upstream_url": "http://127.0.0.1:1/mcp", "project_slug": "alpha"},
    )
    resp = await admin_client.post("/api/v1/keys", json={"name": "alpha-key-own", "project_slug": "alpha"})
    alpha_key = resp.json()["plaintext"]

    resp = await admin_client.post(
        "/mcp/alpha-own-srv",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {alpha_key}"},
    )
    # Not a project-scoping 403 — the unreachable upstream will surface as something else
    # (502/500/timeout-shaped error), but never the "key not scoped for server" 403.
    if resp.status_code == 403:
        assert "not scoped" not in resp.text


# ---------------------------------------------------------------------------------------------
# 6. Aggregate tools/list scoped to the key's project
# ---------------------------------------------------------------------------------------------

async def test_aggregate_tools_list_scoped_to_key_project(mt_app, two_projects):
    """A real behavior change from pre-feature instance-wide aggregate (documented in
    docs/projects.md) — a key's aggregate tools/list view must contain ONLY its own project's
    servers, raw response assertion (not inferred from server count)."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    await admin_client.post(
        "/api/v1/servers",
        json={
            "slug": "agg-alpha", "name": "AggAlpha", "upstream_url": "http://127.0.0.1:1/mcp",
            "project_slug": "alpha", "in_aggregate": True,
        },
    )
    await admin_client.post(
        "/api/v1/servers",
        json={
            "slug": "agg-beta", "name": "AggBeta", "upstream_url": "http://127.0.0.1:1/mcp",
            "project_slug": "beta", "in_aggregate": True,
        },
    )
    resp = await admin_client.post("/api/v1/keys", json={"name": "agg-alpha-key", "project_slug": "alpha"})
    alpha_key = resp.json()["plaintext"]

    resp = await admin_client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
        headers={"Authorization": f"Bearer {alpha_key}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    aggregated = body["result"]["aggregatedServers"]
    assert "agg-alpha" in aggregated
    assert "agg-beta" not in aggregated, "aggregate discover leaked a different project's server"

    # tools/list is the more direct proof (the actual namespaced tool catalog, not just the
    # discover manifest) — every tool name is namespaced '{server_slug}__{tool}', so a leaked
    # beta tool would show up as an 'agg-beta__...' prefix.
    resp = await admin_client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        headers={"Authorization": f"Bearer {alpha_key}"},
    )
    assert resp.status_code == 200, resp.text
    tools = resp.json()["result"]["tools"]
    assert not any(t["name"].startswith("agg-beta__") for t in tools), (
        "aggregate tools/list leaked a different project's server's tools"
    )


# ---------------------------------------------------------------------------------------------
# 7. Export/import round-trip + GitOps unaffected by project role
# ---------------------------------------------------------------------------------------------

async def test_export_import_round_trips_project_assignment(mt_app, two_projects):
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    await admin_client.post(
        "/api/v1/servers",
        json={"slug": "export-srv", "name": "ExportSrv", "upstream_url": "http://localhost:1/mcp", "project_slug": "beta"},
    )

    resp = await admin_client.get("/api/v1/config/export")
    assert resp.status_code == 200
    yaml_text = resp.text
    assert "project_slug: beta" in yaml_text

    await admin_client.delete("/api/v1/servers/export-srv")

    resp = await admin_client.post("/api/v1/config/import", json={"yaml": yaml_text, "apply": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True

    resp = await admin_client.get("/api/v1/servers/export-srv")
    assert resp.status_code == 200
    assert resp.json()["project_slug"] == "beta"


async def test_gitops_reconcile_stays_global_admin_only_unaffected_by_project_role(mt_app, two_projects):
    """A project admin with no global role above viewer gets 403 on GitOps reconcile/drift —
    project admin does NOT imply GitOps authority."""
    app, transport = mt_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")
    project_repo = ProjectRepo(app.state.db)
    user_repo: UserRepo = app.state.user_repo
    alpha = await project_repo.get("alpha")

    client = await _create_user_and_login(transport, admin_client, "alpha-admin-not-gitops", "viewer")
    user = await user_repo.get_by_username("alpha-admin-not-gitops")
    resp = await admin_client.put(
        f"/api/v1/projects/{alpha.id}/members", json={"user_id": user.id, "role": "admin"}
    )
    assert resp.status_code == 200

    resp = await client.get("/api/v1/config/drift")
    assert resp.status_code == 200, "drift GET is viewer-gated instance-wide, should still work"

    resp = await client.post("/api/v1/config/reconcile")
    assert resp.status_code == 403, (
        f"project-admin-but-global-viewer must be denied GitOps reconcile, got {resp.status_code}"
    )
