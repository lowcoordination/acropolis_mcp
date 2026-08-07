"""RBAC enforcement tests (enterprise #3) — the parametrised route x role matrix that makes the
per-route `require_role` approach provably safe (02-rbac.md's own framing: "fails loudly when a
new route ships without a role annotation"), plus the specific escalation paths the plan calls
out by name (operator minting a key, operator running config import, garbage role fail-closed).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import httpx
import pytest

from archon.settings import Settings
from archon.rbac import ROLE_RANK
from argus.app import create_app
from db.database import Database
from db.repo import SettingsRepo, UserRepo


@pytest.fixture
async def rbac_app(tmp_path: Path):
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
    # Bug fix (coordinator review of PR #16, 2026-08-07): POST /api/v1/login now takes a real
    # `username` field (see archon/schemas.py's LoginRequest and the fix in archon/setup.py) —
    # this goes through the ACTUAL login route for every role, not just "admin". Previously this
    # helper's docstring said only admin could reach /login at all, and non-admin test clients
    # were built by forging a session cookie directly; that was true, and it was the bug.
    client = httpx.AsyncClient(transport=transport, base_url="http://argus.test")
    resp = await client.post("/api/v1/login", json={"username": username, "admin_password": password})
    if resp.status_code != 200:
        raise AssertionError(f"login failed for {username}: {resp.status_code} {resp.text}")
    return client


async def _create_user_and_login(
    app, transport: httpx.ASGITransport, admin_client: httpx.AsyncClient,
    username: str, role: str, password: str = "password-12345",
) -> httpx.AsyncClient:
    """Creates a user via the real admin API, then authenticates as them through the real
    POST /api/v1/login route (not a forged cookie) — this is the actual login path an operator
    or viewer created via the Users page would use, and is the thing that was broken pre-fix."""
    resp = await admin_client.post(
        "/api/v1/users", json={"username": username, "password": password, "role": role}
    )
    assert resp.status_code == 201, resp.text
    return await _login_as(transport, username, password)


async def _forge_session_cookie_client(
    app, transport: httpx.ASGITransport, username: str,
) -> httpx.AsyncClient:
    """For tests that need a valid session for an EXISTING user but don't care about proving
    the login route itself (e.g. constructing a session for a role after a hand-edited DB
    state that couldn't have come from a normal login, like test_unknown_role_denied_everywhere
    below). Real login-path coverage lives in _login_as / _create_user_and_login above and in
    tests/integration/test_identity.py's dedicated login tests."""
    from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, create_session_token

    settings_repo: SettingsRepo = app.state.settings_repo
    user_repo: UserRepo = app.state.user_repo
    user = await user_repo.get_by_username(username)
    session_secret = await settings_repo.get("session_secret")
    global_version_raw = await settings_repo.get("session_version")
    global_version = int(global_version_raw) if global_version_raw is not None else DEFAULT_SESSION_VERSION

    token = create_session_token(
        session_secret, session_version=global_version,
        user_id=user.id, user_session_version=user.session_version,
    )
    return httpx.AsyncClient(
        transport=transport, base_url="http://argus.test",
        cookies={SESSION_COOKIE_NAME: token},
    )


@pytest.fixture
async def role_clients(rbac_app):
    """One authenticated httpx client per role, all against the SAME app/db."""
    app, transport = rbac_app
    admin_client = await _login_as(transport, "admin", "admin-password-1")

    operator_client = await _create_user_and_login(app, transport, admin_client, "op-user", "operator")
    viewer_client = await _create_user_and_login(app, transport, admin_client, "view-user", "viewer")

    yield {"admin": admin_client, "operator": operator_client, "viewer": viewer_client}
    await admin_client.aclose()
    await operator_client.aclose()
    await viewer_client.aclose()


# --- Parametrised route x role matrix ---------------------------------------------------------
#
# Each entry: (method, path, minimum_role). `path` may need a real server slug — the fixture
# creates one server ("srv") up front via the admin client, and routes needing a slug use
# "srv" directly. Routes needing a body use a minimal valid one via `body`.
#
# This list is deliberately hand-maintained (not derived from the app's route table) — that's
# the point: a new route landing WITHOUT a corresponding entry here is exactly the gap this test
# exists to catch on review, even though it can't catch it automatically at import time.
ROUTE_MATRIX: list[tuple[str, str, str, Optional[dict]]] = [
    ("GET", "/api/v1/servers", "viewer", None),
    ("GET", "/api/v1/servers/srv", "viewer", None),
    ("GET", "/api/v1/servers/srv/tools", "viewer", None),
    ("GET", "/api/v1/servers/srv/policy", "viewer", None),
    ("GET", "/api/v1/settings", "viewer", None),
    ("GET", "/api/v1/config/export", "viewer", None),
    ("GET", "/api/v1/stats", "viewer", None),
    ("GET", "/api/v1/audit", "viewer", None),
    ("GET", "/api/v1/audit/export.csv", "viewer", None),
    ("GET", "/api/v1/admin-events", "viewer", None),
    ("GET", "/api/v1/me", "viewer", None),
    ("POST", "/api/v1/servers/srv/probe", "operator", None),
    ("PUT", "/api/v1/servers/srv/policy", "operator",
     {"mode": "passthrough", "allowed": [], "denied": [], "param_rules": {}}),
    ("POST", "/api/v1/servers", "admin",
     {"slug": "new-srv-x", "name": "X", "upstream_url": "http://localhost:1/mcp"}),
    ("PUT", "/api/v1/servers/srv", "admin", {"name": "renamed"}),
    ("DELETE", "/api/v1/servers/srv-to-delete", "admin", None),
    ("GET", "/api/v1/keys", "admin", None),
    ("POST", "/api/v1/keys", "admin", {"name": "k1"}),
    ("PUT", "/api/v1/settings", "admin", {"aggregate_enabled": True}),
    ("POST", "/api/v1/config/import", "admin", {"yaml": "servers: []\n", "apply": False}),
    ("GET", "/api/v1/users", "admin", None),
    ("POST", "/api/v1/users", "admin", {"username": "matrix-probe", "password": "password-12345", "role": "viewer"}),
]


@pytest.mark.parametrize("method,path,minimum_role,body", ROUTE_MATRIX)
async def test_route_role_matrix(rbac_app, role_clients, method, path, minimum_role, body):
    app, transport = rbac_app
    admin_client = role_clients["admin"]

    # Fixtures the matrix needs: a server named "srv", plus one to delete per-parametrization
    # run (DELETE is destructive, so give it its own slug rather than sharing "srv").
    await admin_client.post(
        "/api/v1/servers", json={"slug": "srv", "name": "Srv", "upstream_url": "http://localhost:1/mcp"}
    )
    if path == "/api/v1/servers/srv-to-delete":
        pass
    if "servers/srv-to-delete" in path:
        await admin_client.post(
            "/api/v1/servers",
            json={"slug": "srv-to-delete", "name": "Del", "upstream_url": "http://localhost:1/mcp"},
        )

    minimum_rank = ROLE_RANK[minimum_role]
    for role_name, client in role_clients.items():
        should_allow = ROLE_RANK[role_name] >= minimum_rank
        resp = await client.request(method, path, json=body)
        if should_allow:
            assert resp.status_code < 400 or resp.status_code in (409,), (
                f"{role_name} (rank {ROLE_RANK[role_name]}) should be ALLOWED on "
                f"{method} {path} (needs >= {minimum_role}), got {resp.status_code}: {resp.text}"
            )
        else:
            assert resp.status_code == 403, (
                f"{role_name} (rank {ROLE_RANK[role_name]}) should be DENIED with 403 on "
                f"{method} {path} (needs >= {minimum_role}), got {resp.status_code}: {resp.text}"
            )


async def test_viewer_gets_403_not_404_or_401(role_clients):
    """02-rbac.md is explicit: 403, not 404, not 401 — the resource exists and the caller IS
    authenticated, they simply lack permission."""
    resp = await role_clients["viewer"].post("/api/v1/keys", json={"name": "nope"})
    assert resp.status_code == 403
    assert resp.status_code != 404
    assert resp.status_code != 401


async def test_operator_cannot_mint_api_key(role_clients):
    """The escalation path 02-rbac.md calls out by name: an operator minting a key could use it
    against the DATA plane and act entirely outside their control-plane role."""
    resp = await role_clients["operator"].post("/api/v1/keys", json={"name": "escalation-attempt"})
    assert resp.status_code == 403

    # Confirm no key was actually created despite the attempt.
    listed = await role_clients["admin"].get("/api/v1/keys")
    assert all(k["name"] != "escalation-attempt" for k in listed.json())


async def test_operator_cannot_run_config_import(role_clients):
    """An operator CAN edit a single server's policy directly, but must NOT be able to run a
    config import — one import rewrites the entire instance, a different blast radius."""
    resp = await role_clients["operator"].post(
        "/api/v1/config/import", json={"yaml": "servers: []\n", "apply": True}
    )
    assert resp.status_code == 403


async def test_operator_can_edit_policy_directly(rbac_app, role_clients):
    """The contrast case for the above: operators DO have policy-edit access on a single
    server, just not the bulk config-import path."""
    admin_client = role_clients["admin"]
    await admin_client.post(
        "/api/v1/servers", json={"slug": "policy-target", "name": "PT", "upstream_url": "http://localhost:1/mcp"}
    )
    resp = await role_clients["operator"].put(
        "/api/v1/servers/policy-target/policy",
        json={"mode": "allowlist", "allowed": ["a"], "denied": [], "param_rules": {}},
    )
    assert resp.status_code == 200


async def test_unknown_role_denied_everywhere(rbac_app, role_clients):
    """Fail-closed guard (same bug class as F26): a garbage role string in the users table must
    resolve to NO ACCESS on every route, never a permissive default."""
    app, transport = rbac_app
    admin_client = role_clients["admin"]

    resp = await admin_client.post(
        "/api/v1/users", json={"username": "garbage-role-user", "password": "password-12345", "role": "viewer"}
    )
    assert resp.status_code == 201

    # Hand-edit the role directly in the DB to a nonsense value — bypassing the API's own
    # is_valid_role() validation on write, simulating a hand-edited DB, a future migration this
    # binary doesn't fully understand, or any other path that could produce a bad row.
    user_repo: UserRepo = app.state.user_repo
    user = await user_repo.get_by_username("garbage-role-user")
    async with app.state.db.gateway_write_lock:
        await app.state.db.gateway.execute(
            "UPDATE users SET role = 'super-admin-mode' WHERE id = ?", (user.id,)
        )
        await app.state.db.gateway.commit()

    from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, create_session_token

    settings_repo: SettingsRepo = app.state.settings_repo
    session_secret = await settings_repo.get("session_secret")
    token = create_session_token(
        session_secret, session_version=DEFAULT_SESSION_VERSION,
        user_id=user.id, user_session_version=DEFAULT_SESSION_VERSION,
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://argus.test", cookies={SESSION_COOKIE_NAME: token},
    ) as bad_client:
        # Every rank, including the LOWEST (viewer), must deny this principal.
        resp = await bad_client.get("/api/v1/servers")
        assert resp.status_code == 403, f"garbage role should be denied even at viewer level, got {resp.status_code}"
        resp = await bad_client.post("/api/v1/keys", json={"name": "x"})
        assert resp.status_code == 403


async def test_role_change_writes_admin_event(role_clients):
    admin_client = role_clients["admin"]
    resp = await admin_client.post(
        "/api/v1/users", json={"username": "promotable", "password": "password-12345", "role": "viewer"}
    )
    user_id = resp.json()["id"]

    resp = await admin_client.patch(f"/api/v1/users/{user_id}/role", json={"role": "operator"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "operator"

    events = await admin_client.get("/api/v1/admin-events", params={"action": "user.role_change"})
    assert events.status_code == 200
    matching = [e for e in events.json() if e["target_id"] == str(user_id)]
    assert len(matching) == 1
    assert "viewer -> operator" in matching[0]["summary"]


async def test_role_change_revokes_existing_session_immediately(rbac_app, role_clients):
    """A role change (demotion in particular) must take effect on the NEXT request, not wait
    for the old cookie to expire up to 7 days later."""
    app, transport = rbac_app
    admin_client = role_clients["admin"]

    resp = await admin_client.post(
        "/api/v1/users", json={"username": "demote-me", "password": "password-12345", "role": "admin"}
    )
    user_id = resp.json()["id"]

    from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, create_session_token

    user_repo: UserRepo = app.state.user_repo
    settings_repo: SettingsRepo = app.state.settings_repo
    user = await user_repo.get_by_id(user_id)
    session_secret = await settings_repo.get("session_secret")
    token = create_session_token(
        session_secret, session_version=DEFAULT_SESSION_VERSION,
        user_id=user.id, user_session_version=user.session_version,
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://argus.test", cookies={SESSION_COOKIE_NAME: token},
    ) as demoted_client:
        # Works fine before the demotion.
        assert (await demoted_client.get("/api/v1/keys")).status_code == 200

        await admin_client.patch(f"/api/v1/users/{user_id}/role", json={"role": "viewer"})

        # Same cookie, unchanged bytes — must now be rejected outright (session_version bumped),
        # not merely downgraded in effective permissions on the same still-valid token.
        resp = await demoted_client.get("/api/v1/keys")
        assert resp.status_code == 401


async def test_disabling_user_revokes_session_immediately(rbac_app, role_clients):
    app, transport = rbac_app
    admin_client = role_clients["admin"]

    resp = await admin_client.post(
        "/api/v1/users", json={"username": "disable-me", "password": "password-12345", "role": "viewer"}
    )
    user_id = resp.json()["id"]

    from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, create_session_token

    user_repo: UserRepo = app.state.user_repo
    settings_repo: SettingsRepo = app.state.settings_repo
    user = await user_repo.get_by_id(user_id)
    session_secret = await settings_repo.get("session_secret")
    token = create_session_token(
        session_secret, session_version=DEFAULT_SESSION_VERSION,
        user_id=user.id, user_session_version=user.session_version,
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://argus.test", cookies={SESSION_COOKIE_NAME: token},
    ) as disabled_client:
        assert (await disabled_client.get("/api/v1/servers")).status_code == 200

        resp = await admin_client.patch(f"/api/v1/users/{user_id}/enabled", json={"enabled": False})
        assert resp.status_code == 200

        resp = await disabled_client.get("/api/v1/servers")
        assert resp.status_code == 401


async def test_admin_cannot_disable_own_account(role_clients):
    admin_client = role_clients["admin"]
    me = await admin_client.get("/api/v1/me")
    user_id = me.json()["user_id"]
    resp = await admin_client.patch(f"/api/v1/users/{user_id}/enabled", json={"enabled": False})
    assert resp.status_code == 400


async def test_data_plane_unaffected_by_role(rbac_app, role_clients):
    """/mcp/* authorisation is API-key scoping only — completely independent of control-plane
    role. A viewer-role session cookie must have NO bearing on data-plane access (there is no
    session-cookie auth path on /mcp/* at all; only Bearer API keys)."""
    app, transport = rbac_app
    # No API key presented at all — auth_mode is "keyed", so this must be rejected regardless
    # of which (if any) control-plane session cookie rides along, proving session-based RBAC
    # grants nothing on the data plane.
    resp = await role_clients["viewer"].post(
        "/mcp/some-server", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code in (401, 404)
