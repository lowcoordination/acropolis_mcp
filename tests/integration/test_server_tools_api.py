"""Integration tests for GET /api/v1/servers/{slug}/tools — real upstream tools annotated
with the server's current policy status."""
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
async def client(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
            yield c
    await db.close()


async def test_get_tools_passthrough_mode_all_allowed(client):
    resp = await client.get("/api/v1/servers/s/tools")
    assert resp.status_code == 200
    tools = resp.json()
    names = {t["name"] for t in tools}
    assert {"echo", "read_file", "write_file", "slow_tool"} <= names
    assert all(t["status"] == "allowed" for t in tools)


async def test_get_tools_reflects_allowlist_policy(client):
    await client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "allowlist", "allowed": ["echo"], "denied": [], "param_rules": {}},
    )
    resp = await client.get("/api/v1/servers/s/tools")
    tools = {t["name"]: t["status"] for t in resp.json()}
    assert tools["echo"] == "allowed"
    assert tools["write_file"] == "denied"


async def test_get_tools_reflects_denylist_policy(client):
    await client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "denylist", "allowed": [], "denied": ["write_file"], "param_rules": {}},
    )
    resp = await client.get("/api/v1/servers/s/tools")
    tools = {t["name"]: t["status"] for t in resp.json()}
    assert tools["write_file"] == "denied"
    assert tools["echo"] == "allowed"


async def test_get_tools_flags_param_rules(client):
    await client.put(
        "/api/v1/servers/s/policy",
        json={
            "mode": "passthrough", "allowed": [], "denied": [],
            "param_rules": {"read_file": {"path": {"block_patterns": [r"/etc/"], "denied": False}}},
        },
    )
    resp = await client.get("/api/v1/servers/s/tools")
    tools = {t["name"]: t for t in resp.json()}
    assert tools["read_file"]["has_param_rules"] is True
    assert tools["echo"]["has_param_rules"] is False


async def test_get_tools_unknown_server_404(client):
    resp = await client.get("/api/v1/servers/nope/tools")
    assert resp.status_code == 404


async def test_get_tools_dead_upstream_returns_empty_not_500(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="dead", name="Dead", upstream_url="http://127.0.0.1:1/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
            resp = await c.get("/api/v1/servers/dead/tools")
            assert resp.status_code == 200
            assert resp.json() == []
    await db.close()
