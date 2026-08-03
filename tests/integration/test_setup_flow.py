"""End-to-end tests for the first-run setup / login / session-cookie flow."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database


@pytest.fixture
async def app_transport(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        yield transport
    await db.close()


@pytest.fixture
async def client(app_transport):
    async with httpx.AsyncClient(transport=app_transport, base_url="http://argus.test") as c:
        yield c


async def test_setup_status_initially_incomplete(client):
    resp = await client.get("/api/v1/setup/status")
    assert resp.status_code == 200
    assert resp.json()["setup_complete"] is False


async def test_before_setup_control_plane_is_open(client):
    # No admin configured yet, no admin_token — the narrow "open until wizard runs" window.
    resp = await client.get("/api/v1/servers")
    assert resp.status_code == 200


async def test_complete_setup_sets_cookie_and_marks_complete(client):
    resp = await client.post("/api/v1/setup", json={"admin_password": "hunter22", "auth_mode": "keyed"})
    assert resp.status_code == 200
    assert resp.json()["setup_complete"] is True
    assert "argus_session" in resp.cookies

    status = await client.get("/api/v1/setup/status")
    assert status.json()["setup_complete"] is True


async def test_setup_rejects_short_password(client):
    resp = await client.post("/api/v1/setup", json={"admin_password": "short"})
    assert resp.status_code == 400


async def test_setup_cannot_run_twice(client):
    await client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    resp = await client.post("/api/v1/setup", json={"admin_password": "different-pass"})
    assert resp.status_code == 409


async def test_after_setup_control_plane_requires_auth(client, app_transport):
    await client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    # A fresh client (no cookie jar carried over) should be rejected now.
    async with httpx.AsyncClient(transport=app_transport, base_url="http://argus.test") as fresh:
        resp = await fresh.get("/api/v1/servers")
        assert resp.status_code == 401


async def test_session_cookie_grants_access_after_setup(client):
    setup_resp = await client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    assert setup_resp.status_code == 200
    # httpx.AsyncClient persists cookies across requests on the same client automatically.
    resp = await client.get("/api/v1/servers")
    assert resp.status_code == 200


async def test_login_with_correct_password_grants_session(client, app_transport):
    await client.post("/api/v1/setup", json={"admin_password": "hunter22"})

    async with httpx.AsyncClient(transport=app_transport, base_url="http://argus.test") as fresh:
        login = await fresh.post("/api/v1/login", json={"admin_password": "hunter22"})
        assert login.status_code == 200
        assert "argus_session" in login.cookies

        resp = await fresh.get("/api/v1/servers")
        assert resp.status_code == 200


async def test_login_with_wrong_password_rejected(client, app_transport):
    await client.post("/api/v1/setup", json={"admin_password": "hunter22"})

    async with httpx.AsyncClient(transport=app_transport, base_url="http://argus.test") as fresh:
        login = await fresh.post("/api/v1/login", json={"admin_password": "wrong-password"})
        assert login.status_code == 401


async def test_login_before_setup_rejected(client):
    resp = await client.post("/api/v1/login", json={"admin_password": "anything"})
    assert resp.status_code == 400


async def test_logout_clears_session(client):
    await client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    assert (await client.get("/api/v1/servers")).status_code == 200

    logout = await client.post("/api/v1/logout")
    assert logout.status_code == 200

    resp = await client.get("/api/v1/servers")
    assert resp.status_code == 401
