"""Proves the data-plane auth_mode setting (from the wizard or the Settings page) is actually
ENFORCED by the pipeline, not just echoed back by the settings API. This is the gap that let a
real bug ship: Pipeline._authenticate read a static env-var Settings object that never saw
what the wizard/Settings page wrote to the DB, so 'keyed' mode silently behaved as 'open'."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


def _tool_call_headers_2026(tool: str) -> dict:
    return {"Content-Type": "application/json", "Accept": "application/json",
            "Mcp-Method": "tools/call", "Mcp-Name": tool}


def _tool_call_body(tool: str, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": tool, "arguments": {"message": "x"}}}


async def test_keyed_auth_mode_set_via_wizard_is_actually_enforced(tmp_path: Path, upstream):
    # Env var default is "keyed" (Settings.auth_mode default) — construct with the ENV default,
    # not an explicit override, mirroring what a real container with no ARGUS_AUTH_MODE set
    # would do, then drive auth_mode entirely through the wizard as a real user would.
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            setup = await client.post(
                "/api/v1/setup", json={"admin_password": "hunter22222", "auth_mode": "keyed"}
            )
            assert setup.status_code == 200

            # No API key presented — must be rejected now that keyed mode is configured.
            resp = await client.post(
                "/mcp/s", json=_tool_call_body("echo"), headers=_tool_call_headers_2026("echo"),
            )
            assert resp.status_code == 401
    await db.close()


async def test_open_auth_mode_set_via_settings_page_actually_disables_auth(tmp_path: Path, upstream):
    # Start from the env-var default of "keyed", then flip to "open" via the Settings API
    # (what the Settings page's save button calls) and confirm the data plane responds to it
    # immediately, without a restart.
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post("/api/v1/setup", json={"admin_password": "hunter22222", "auth_mode": "keyed"})

            # Confirm keyed mode really is enforced first (sanity check before flipping it).
            still_keyed = await client.post(
                "/mcp/s", json=_tool_call_body("echo"), headers=_tool_call_headers_2026("echo"),
            )
            assert still_keyed.status_code == 401

            switch = await client.put("/api/v1/settings", json={"auth_mode": "open"})
            assert switch.status_code == 200
            assert switch.json()["auth_mode"] == "open"

            # Same request, no key, no restart — must now succeed.
            resp = await client.post(
                "/mcp/s", json=_tool_call_body("echo"), headers=_tool_call_headers_2026("echo"),
            )
            assert resp.status_code == 200
    await db.close()


async def test_keyed_mode_still_accepts_a_valid_key(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post("/api/v1/setup", json={"admin_password": "hunter22222", "auth_mode": "keyed"})
            created = await client.post("/api/v1/keys", json={"name": "test-key"})
            plaintext = created.json()["plaintext"]

            resp = await client.post(
                "/mcp/s", json=_tool_call_body("echo"),
                headers={**_tool_call_headers_2026("echo"), "Authorization": f"Bearer {plaintext}"},
            )
            assert resp.status_code == 200
    await db.close()
