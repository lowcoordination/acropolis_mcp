"""Proves the aggregate /mcp endpoint actually enforces auth_mode for EVERY method
(tools/list, server/discover, tools/call) — not just tools/call via incidental re-dispatch.
This closes the gap found during M3 final verification: AggregatePipeline.handle() answered
tools/list and server/discover directly, with no auth check at all, regardless of auth_mode."""
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


@pytest.fixture
async def keyed_client(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)  # default auth_mode=keyed
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post("/api/v1/setup", json={"admin_password": "hunter22222", "auth_mode": "keyed"})
            yield client
    await db.close()


HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


async def test_aggregate_tools_list_requires_auth(keyed_client):
    resp = await keyed_client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, headers=HEADERS,
    )
    assert resp.status_code == 401


async def test_aggregate_server_discover_requires_auth(keyed_client):
    resp = await keyed_client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}, headers=HEADERS,
    )
    assert resp.status_code == 401


async def test_aggregate_tools_call_requires_auth(keyed_client):
    resp = await keyed_client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "s__echo", "arguments": {"message": "x"}}},
        headers=HEADERS,
    )
    assert resp.status_code == 401


async def test_aggregate_tools_list_succeeds_with_valid_key(keyed_client):
    created = await keyed_client.post("/api/v1/keys", json={"name": "k"})
    plaintext = created.json()["plaintext"]

    resp = await keyed_client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={**HEADERS, "Authorization": f"Bearer {plaintext}"},
    )
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert "s__echo" in names


async def test_aggregate_open_mode_requires_no_key(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post("/api/v1/setup", json={"admin_password": "hunter22222", "auth_mode": "open"})
            resp = await client.post(
                "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, headers=HEADERS,
            )
            assert resp.status_code == 200
    await db.close()
