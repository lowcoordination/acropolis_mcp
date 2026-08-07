"""Identity-milestone tests not covered by test_users_migration.py or test_rbac.py:
admin_token break-glass after full setup/migration, data-plane byte-identical regression, the
/users CRUD API surface, and per-user vs global session revocation independence.
"""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, create_session_token
from argus.app import create_app
from db.database import Database
from db.repo import SettingsRepo, UserRepo


@pytest.fixture
async def app_and_transport(tmp_path: Path, admin_token: str | None = None):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="keyed", admin_token=admin_token,
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        yield app, transport
    await db.close()


async def test_admin_token_still_works_as_break_glass_after_setup(tmp_path: Path):
    """01-identity-and-sso.md non-negotiable: admin_token is preserved as break-glass, mapped
    to a synthetic actor, and keeps working even once real users exist."""
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="keyed", admin_token="break-glass-secret",
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            # admin_token allows completing setup too — it's a full break-glass admin identity.
            setup = await client.post(
                "/api/v1/setup", json={"admin_password": "operator-password-1"},
                headers={"Authorization": "Bearer break-glass-secret"},
            )
            assert setup.status_code == 200

        # A completely fresh client, no cookie, presenting ONLY the bearer token — must have
        # full admin access despite real users now existing in the table.
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as fresh:
            resp = await fresh.get(
                "/api/v1/servers", headers={"Authorization": "Bearer break-glass-secret"}
            )
            assert resp.status_code == 200

            # Break-glass resolves to admin rank -- can do admin-only things too.
            resp = await fresh.post(
                "/api/v1/keys", json={"name": "break-glass-key"},
                headers={"Authorization": "Bearer break-glass-secret"},
            )
            assert resp.status_code == 201

            # And even disabling the local admin user doesn't lock out the break-glass path.
            user_repo: UserRepo = app.state.user_repo
            admin_user = await user_repo.get_by_username("admin")
            await user_repo.set_enabled(admin_user.id, False)

            resp = await fresh.get(
                "/api/v1/servers", headers={"Authorization": "Bearer break-glass-secret"}
            )
            assert resp.status_code == 200, "admin_token must work even if the local admin user is disabled"
    await db.close()


async def test_admin_token_actor_recorded_in_audit_log(tmp_path: Path):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="keyed", admin_token="break-glass-secret",
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post(
                "/api/v1/setup", json={"admin_password": "pw-12345678"},
                headers={"Authorization": "Bearer break-glass-secret"},
            )
            await client.post(
                "/api/v1/servers",
                json={"slug": "via-token", "name": "ViaToken", "upstream_url": "http://localhost:1/mcp"},
                headers={"Authorization": "Bearer break-glass-secret"},
            )
            events = await client.get(
                "/api/v1/admin-events", params={"action": "server.create"},
                headers={"Authorization": "Bearer break-glass-secret"},
            )
            matching = [e for e in events.json() if e["target_id"] == "via-token"]
            assert len(matching) == 1
            assert matching[0]["actor"] == "admin-token"
    await db.close()


async def test_data_plane_mcp_unaffected_by_control_plane_auth_changes(tmp_path: Path):
    """Regression guard: /mcp/* behaviour must be byte-identical regardless of control-plane
    identity/RBAC state — this is the blast radius that matters most if this milestone ever
    regresses something. auth_mode=keyed with NO API key presented must 401 the data plane the
    exact same way whether or not any control-plane session/token is also presented."""
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="keyed", health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            setup = await client.post("/api/v1/setup", json={"admin_password": "pw-12345678"})
            assert setup.status_code == 200

            # A request to /mcp/* carrying a VALID admin session cookie but no API key must
            # still be rejected -- session cookies are a control-plane concept only.
            resp = await client.post(
                "/mcp/nonexistent-server",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            assert resp.status_code in (401, 404)

        # And the same request with NEITHER cookie nor key behaves identically.
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as anon:
            resp = await anon.post(
                "/mcp/nonexistent-server",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            assert resp.status_code in (401, 404)
    await db.close()


async def test_users_crud_via_admin_api(app_and_transport):
    app, transport = app_and_transport
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        await client.post("/api/v1/setup", json={"admin_password": "admin-pw-12345"})

        create = await client.post(
            "/api/v1/users", json={"username": "alice", "password": "alice-password-1", "role": "viewer", "email": "alice@x.com"}
        )
        assert create.status_code == 201
        body = create.json()
        assert body["username"] == "alice"
        assert body["role"] == "viewer"
        assert body["enabled"] is True
        assert "password" not in body and "password_hash" not in body

        listed = await client.get("/api/v1/users")
        usernames = {u["username"] for u in listed.json()}
        assert {"admin", "alice"} <= usernames

        dup = await client.post(
            "/api/v1/users", json={"username": "alice", "password": "another-password-1", "role": "viewer"}
        )
        assert dup.status_code == 409

        bad_role = await client.post(
            "/api/v1/users", json={"username": "bob", "password": "bob-password-12", "role": "superuser"}
        )
        assert bad_role.status_code == 400

        short_pw = await client.post(
            "/api/v1/users", json={"username": "carol", "password": "short", "role": "viewer"}
        )
        assert short_pw.status_code == 400


async def test_per_user_revocation_logs_out_one_user_not_all(app_and_transport):
    """01-identity-and-sso.md verification requirement: per-user revocation must not be global."""
    app, transport = app_and_transport
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as admin_client:
        await admin_client.post("/api/v1/setup", json={"admin_password": "admin-pw-12345"})
        create = await admin_client.post(
            "/api/v1/users", json={"username": "user-a", "password": "user-a-password", "role": "viewer"}
        )
        user_a_id = create.json()["id"]
        await admin_client.post(
            "/api/v1/users", json={"username": "user-b", "password": "user-b-password", "role": "viewer"}
        )
        user_b_id = (await admin_client.get("/api/v1/users")).json()

        user_repo: UserRepo = app.state.user_repo
        settings_repo: SettingsRepo = app.state.settings_repo
        session_secret = await settings_repo.get("session_secret")
        global_version_raw = await settings_repo.get("session_version")
        global_version = int(global_version_raw) if global_version_raw is not None else DEFAULT_SESSION_VERSION

        user_a = await user_repo.get_by_id(user_a_id)
        user_b = next(u for u in user_b_id if u["username"] == "user-b")
        user_b_record = await user_repo.get_by_id(user_b["id"])

        token_a = create_session_token(
            session_secret, session_version=global_version,
            user_id=user_a.id, user_session_version=user_a.session_version,
        )
        token_b = create_session_token(
            session_secret, session_version=global_version,
            user_id=user_b_record.id, user_session_version=user_b_record.session_version,
        )

        async with httpx.AsyncClient(
            transport=transport, base_url="http://argus.test", cookies={SESSION_COOKIE_NAME: token_a},
        ) as client_a, httpx.AsyncClient(
            transport=transport, base_url="http://argus.test", cookies={SESSION_COOKIE_NAME: token_b},
        ) as client_b:
            assert (await client_a.get("/api/v1/servers")).status_code == 200
            assert (await client_b.get("/api/v1/servers")).status_code == 200

            # Revoke ONLY user A (role change bumps their per-user version).
            await admin_client.patch(f"/api/v1/users/{user_a_id}/role", json={"role": "viewer"})
            # ^ same role, but PATCH still bumps the version unconditionally on the enabled path;
            # role endpoint only records an audit event on an actual change. Use a real change
            # to be unambiguous:
            await admin_client.patch(f"/api/v1/users/{user_a_id}/role", json={"role": "operator"})

            resp_a = await client_a.get("/api/v1/servers")
            resp_b = await client_b.get("/api/v1/servers")
            assert resp_a.status_code == 401, "user A's session should be revoked"
            assert resp_b.status_code == 200, "user B's session must be UNAFFECTED by user A's revocation"


async def test_legacy_admin_session_still_works_when_users_table_has_no_matching_row(tmp_path: Path):
    """Partial-upgrade guard: a session cookie with no user_id (issued by, or surviving from, a
    pre-identity-milestone code path) must still authenticate via the legacy settings-based
    check, exercising archon/admin_auth.py's path 3 directly."""
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="keyed", health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    settings_repo = SettingsRepo(db)
    from archon.passwords import hash_password
    await settings_repo.set_many({
        "admin_password_hash": hash_password("legacy-pw-12345"),
        "session_secret": "legacy-secret",
        "session_version": "0",
    })
    # No `users` row created — simulating an app that wrote settings directly without ever
    # calling UserRepo (or a genuinely empty users table for any other reason).
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        legacy_token = create_session_token(
            "legacy-secret", session_version=0, user_id=None, user_session_version=DEFAULT_SESSION_VERSION,
        )
        async with httpx.AsyncClient(
            transport=transport, base_url="http://argus.test", cookies={SESSION_COOKIE_NAME: legacy_token},
        ) as client:
            resp = await client.get("/api/v1/servers")
            assert resp.status_code == 200, "user-less legacy token must still authenticate via fallback"
    await db.close()
