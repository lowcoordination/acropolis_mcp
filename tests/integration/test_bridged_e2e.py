"""End-to-end: a 2026-style stateless client (no initialize, Mcp-Method header on every
request) talking through the real Acropolis app to a real 2025-06-18 FastMCP upstream."""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.models import ServerPolicy
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def argus_client(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open")
    db = Database(tmp_path)
    await db.connect()

    server_repo = ServerRepo(db)
    await server_repo.create(slug="test-server", name="Test Server", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client, server_repo, upstream, db

    await db.close()


def _stateless_call(rpc_method: str, params: dict, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": rpc_method, "params": params}


GEN_2026_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


async def test_2026_client_tools_call_bridged_end_to_end(argus_client):
    client, _, upstream, _ = argus_client
    headers = {**GEN_2026_HEADERS, "Mcp-Method": "tools/call", "Mcp-Name": "echo"}
    resp = await client.post(
        "/mcp/test-server",
        json=_stateless_call("tools/call", {"name": "echo", "arguments": {"message": "stateless!"}}),
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["content"][0]["text"] == "stateless!"
    assert upstream.call_counter.get("echo") == 1


async def test_2026_client_never_sends_initialize(argus_client):
    # The whole point of stateless: no initialize round-trip should be required at all.
    # This test simply demonstrates the FIRST request from this client is tools/call.
    client, _, upstream, _ = argus_client
    headers = {**GEN_2026_HEADERS, "Mcp-Method": "tools/call", "Mcp-Name": "echo"}
    resp = await client.post(
        "/mcp/test-server",
        json=_stateless_call("tools/call", {"name": "echo", "arguments": {"message": "first call"}}),
        headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("echo") == 1


async def test_2026_client_blocked_by_policy_before_reaching_upstream(argus_client):
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    headers = {**GEN_2026_HEADERS, "Mcp-Method": "tools/call", "Mcp-Name": "write_file"}
    resp = await client.post(
        "/mcp/test-server",
        json=_stateless_call("tools/call", {"name": "write_file", "arguments": {"path": "/x", "content": "y"}}),
        headers=headers,
    )
    assert resp.status_code == 403
    assert upstream.call_counter.get("write_file") is None


async def test_2026_client_tools_list_is_filtered(argus_client):
    client, server_repo, _, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    headers = {**GEN_2026_HEADERS, "Mcp-Method": "tools/list"}
    resp = await client.post("/mcp/test-server", json=_stateless_call("tools/list", {}), headers=headers)
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert names == {"echo"}


async def test_2025_client_still_works_unbridged(argus_client):
    """Regression check: adding bridging must not change the 2025 passthrough path from M1."""
    client, _, upstream, _ = argus_client
    init_resp = await client.post(
        "/mcp/test-server",
        json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "c", "version": "1"}},
        },
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    assert init_resp.status_code == 200
    session_id = init_resp.headers.get("mcp-session-id")
    headers = {
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": session_id,
    }
    await client.post(
        "/mcp/test-server", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers,
    )
    resp = await client.post(
        "/mcp/test-server",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "echo", "arguments": {"message": "still works"}}},
        headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("echo") == 1


async def test_health_poller_updates_status_via_full_app(argus_client):
    client, server_repo, _, _ = argus_client
    # The poller runs poll_once() immediately on lifespan startup; give it a moment.
    for _ in range(20):
        server = await server_repo.get("test-server")
        if server.health_status != "unknown":
            break
        await asyncio.sleep(0.05)
    assert server.health_status == "healthy"
    assert server.upstream_protocol == "2025-06-18"
