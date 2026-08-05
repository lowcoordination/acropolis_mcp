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
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
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
    body = resp.json()
    tools = body["tools"]
    names = {t["name"] for t in tools}
    assert {"echo", "read_file", "write_file", "slow_tool"} <= names
    assert all(t["status"] == "allowed" for t in tools)


async def test_get_tools_reflects_allowlist_policy(client):
    await client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "allowlist", "allowed": ["echo"], "denied": [], "param_rules": {}},
    )
    resp = await client.get("/api/v1/servers/s/tools")
    tools = {t["name"]: t["status"] for t in resp.json()["tools"]}
    assert tools["echo"] == "allowed"
    assert tools["write_file"] == "denied"


async def test_get_tools_reflects_denylist_policy(client):
    await client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "denylist", "allowed": [], "denied": ["write_file"], "param_rules": {}},
    )
    resp = await client.get("/api/v1/servers/s/tools")
    tools = {t["name"]: t["status"] for t in resp.json()["tools"]}
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
    tools = {t["name"]: t for t in resp.json()["tools"]}
    assert tools["read_file"]["has_param_rules"] is True
    assert tools["echo"]["has_param_rules"] is False


async def test_get_tools_unknown_server_404(client):
    resp = await client.get("/api/v1/servers/nope/tools")
    assert resp.status_code == 404


async def test_get_tools_dead_upstream_returns_empty_not_500(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
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
            assert resp.json() == {"fetched_at": None, "tools": []}
    await db.close()


async def test_get_tools_fetched_at_updates_after_force_refresh(client, monkeypatch):
    """Roadmap #6: fetched_at should reflect when the tool cache was last populated, and
    force_refresh=true should re-fetch (and thus bump fetched_at) even when the cached rows are
    still within their TTL. Freezes db.database.utcnow (what _store stamps fetched_at with) to
    two distinct instants so the comparison isn't racing the real clock across two fast requests
    that could otherwise land in the same microsecond."""
    import argus.toolslist as toolslist_module

    first_stamp = "2026-01-01T00:00:00+00:00"
    second_stamp = "2026-01-01T00:05:00+00:00"

    monkeypatch.setattr(toolslist_module, "utcnow", lambda: first_stamp)
    first = await client.get("/api/v1/servers/s/tools")
    assert first.json()["fetched_at"] == first_stamp

    monkeypatch.setattr(toolslist_module, "utcnow", lambda: second_stamp)
    second = await client.get("/api/v1/servers/s/tools?force_refresh=true")
    assert second.json()["fetched_at"] == second_stamp


async def test_get_tools_force_refresh_bypasses_cache(client, monkeypatch):
    """force_refresh=true must re-fetch even when the cached rows are still fresh (within TTL).
    Confirmed by counting real bridge_call invocations directly, since the fixture's own
    call_counter only tracks TOOL invocations, not tools/list requests, and calling GET /tools
    never invokes a tool."""
    import argus.toolslist as toolslist_module

    # Count calls into the cache's own _store, which only runs on a genuine upstream fetch,
    # never on a cache hit.
    call_count = {"n": 0}
    original_store = toolslist_module.ToolsCache._store

    async def counting_store(self, *args, **kwargs):
        call_count["n"] += 1
        return await original_store(self, *args, **kwargs)

    monkeypatch.setattr(toolslist_module.ToolsCache, "_store", counting_store)

    first = await client.get("/api/v1/servers/s/tools")
    assert first.status_code == 200
    assert call_count["n"] == 1, "first GET /tools should populate the cache once"

    # A plain GET within the TTL should serve the cache — no new _store call.
    await client.get("/api/v1/servers/s/tools")
    assert call_count["n"] == 1, "a plain GET within TTL must not re-fetch from upstream"

    # force_refresh=true must bypass the cache and re-fetch.
    await client.get("/api/v1/servers/s/tools?force_refresh=true")
    assert call_count["n"] == 2, "force_refresh=true must bypass the cache and re-fetch"
