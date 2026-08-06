"""Integration tests for POST /api/v1/servers/{slug}/test-call (feature #1, the in-UI tool
tester). The core claim under test: a Try-it call runs through the SAME pipeline a real client's
call would (real policy, real rate limiting, real audit logging) while bypassing only the data
plane's API-key check, and never pollutes /stats or the default Audit page view."""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server


async def _test_call(client: httpx.AsyncClient, slug: str, tool: str, arguments: dict) -> httpx.Response:
    return await client.post(f"/api/v1/servers/{slug}/test-call", json={"tool": tool, "arguments": arguments})


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def open_client(tmp_path: Path, upstream):
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


@pytest.fixture
async def keyed_client(tmp_path: Path, upstream):
    """auth_mode left at the Settings object's default ('keyed'), and never overridden via the
    settings table — this is the mode the tester's auth-bypass claim actually needs to prove
    itself against; 'open' mode would pass even with a broken bypass."""
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)
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


async def test_test_call_bypasses_api_key_auth_in_keyed_mode(keyed_client):
    """The whole point of the feature: an admin-authenticated Try-it call must not need a
    minted API key even when the gateway's data plane is in keyed mode. No Authorization
    header is sent here at all — a real /mcp/s call with no header would 401."""
    resp = await _test_call(keyed_client, "s", "echo", {"message": "hi"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOWED"


async def test_test_call_against_denied_tool_returns_blocked(open_client):
    await open_client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "allowlist", "allowed": [], "denied": [], "param_rules": {}},
    )
    resp = await _test_call(open_client, "s", "echo", {"message": "hi"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "BLOCKED"
    assert body["rule"] == "allowlist"


async def test_test_call_writes_audit_row_tagged_origin_test(open_client, tmp_path: Path):
    await _test_call(open_client, "s", "echo", {"message": "hi"})
    await asyncio.sleep(0.3)  # audit flush interval

    resp = await open_client.get("/api/v1/audit", params={"include_test": True})
    events = resp.json()
    test_events = [e for e in events if e.get("tool") == "echo"]
    assert len(test_events) == 1
    assert test_events[0]["origin"] == "test"


async def test_test_call_does_not_move_stats_counters(open_client):
    await open_client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "allowlist", "allowed": [], "denied": [], "param_rules": {}},
    )
    resp = await _test_call(open_client, "s", "echo", {})
    assert resp.json()["decision"] == "BLOCKED"
    await asyncio.sleep(0.3)

    stats = (await open_client.get("/api/v1/stats")).json()
    # This is the assertion that matters — the whole point of the origin column.
    assert stats["blocked_24h"] == 0
    assert stats["requests_24h"] == 0


async def test_test_call_hidden_from_default_audit_view(open_client):
    await _test_call(open_client, "s", "echo", {"message": "hi"})
    await asyncio.sleep(0.3)

    default_view = (await open_client.get("/api/v1/audit")).json()
    assert all(e.get("tool") != "echo" for e in default_view)

    with_test = (await open_client.get("/api/v1/audit", params={"include_test": True})).json()
    assert any(e.get("tool") == "echo" for e in with_test)


async def test_test_call_unknown_server_404(open_client):
    resp = await open_client.post(
        "/api/v1/servers/nope/test-call", json={"tool": "echo", "arguments": {}},
    )
    assert resp.status_code == 404


async def test_test_call_returns_upstream_response_on_allow(open_client):
    resp = await _test_call(open_client, "s", "echo", {"message": "hello"})
    body = resp.json()
    assert body["decision"] == "ALLOWED"
    assert body["upstream_response"] is not None
    assert "result" in body["upstream_response"]


async def test_test_call_agrees_with_a_real_curl_equivalent(open_client):
    """If the tester and a real data-plane call ever disagree, the tester is wrong by
    definition — this is the parity check the plan calls out explicitly."""
    await open_client.put(
        "/api/v1/servers/s/policy",
        json={"mode": "allowlist", "allowed": [], "denied": [], "param_rules": {}},
    )

    tester_resp = await _test_call(open_client, "s", "echo", {"message": "hi"})
    real_resp = await open_client.post(
        "/mcp/s",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "echo", "arguments": {"message": "hi"}}},
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    assert tester_resp.json()["decision"] == "BLOCKED"
    assert real_resp.status_code == 403


async def test_get_tools_includes_input_schema(open_client):
    tools_resp = await open_client.get("/api/v1/servers/s/tools")
    tools = {t["name"]: t for t in tools_resp.json()["tools"]}
    assert tools["echo"]["input_schema"] is not None
    assert "message" in tools["echo"]["input_schema"].get("properties", {})
