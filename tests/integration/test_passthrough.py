"""
Integration tests: real Argus FastAPI app (via ASGI transport, no sockets) proxying to a real
FastMCP 2025-06-18 upstream (via a real socket, since FastMCP needs an actual server to run).

Covers M1's ship test: a 2025-generation client talking through argus/{slug} to a real
upstream, including allowlist/denylist enforcement and proof that blocked calls never reach
the upstream (via the fixture's call_counter spy).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.models import ParamRule, ServerPolicy
from db.repo import AuditRepo, ServerRepo

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

    # httpx.ASGITransport does not trigger FastAPI lifespan events, so drive the app's
    # lifespan manually — otherwise the audit logger's flush-loop task never starts and
    # every audit.log() call queues forever without being persisted.
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client, server_repo, upstream, db

    await db.close()


def _initialize_body(req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "argus-test-client", "version": "0.0.1"},
        },
    }


def _tool_call_body(tool: str, arguments: dict, req_id: int = 2) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


async def _initialized_session_headers(client: httpx.AsyncClient) -> dict:
    """Real 2025-06-18 clients must initialize() before any other call, and FastMCP mints a
    Mcp-Session-Id that must be echoed on every subsequent request. M1 is pure passthrough,
    so argus does no session handling itself — it just relays whatever the upstream issues."""
    resp = await client.post("/mcp/test-server", json=_initialize_body(), headers=MCP_HEADERS)
    assert resp.status_code == 200, resp.text
    session_id = resp.headers.get("mcp-session-id")
    assert session_id, "FastMCP did not issue a session id on initialize"
    headers = {**MCP_HEADERS, "Mcp-Session-Id": session_id}
    # Required by the streamable-http transport before any other call is accepted.
    init_notif = await client.post(
        "/mcp/test-server",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=headers,
    )
    assert init_notif.status_code in (200, 202), init_notif.text
    return headers


async def test_initialize_passes_through(argus_client):
    client, _, _, _ = argus_client
    resp = await client.post("/mcp/test-server", json=_initialize_body(), headers=MCP_HEADERS)
    assert resp.status_code == 200
    # FastMCP replies SSE on POST — assert we relayed it, not that we understood it (M1 passthrough).
    assert "serverInfo" in resp.text or "result" in resp.text


async def test_tools_call_passthrough_reaches_upstream(argus_client):
    client, _, upstream, _ = argus_client
    headers = await _initialized_session_headers(client)
    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("echo") == 1


async def test_unknown_server_404(argus_client):
    client, _, _, _ = argus_client
    resp = await client.post("/mcp/does-not-exist", json=_tool_call_body("echo", {}), headers=MCP_HEADERS)
    assert resp.status_code == 404


async def test_disabled_server_404(argus_client):
    client, server_repo, _, _ = argus_client
    await server_repo.update("test-server", enabled=False)
    resp = await client.post("/mcp/test-server", json=_tool_call_body("echo", {}), headers=MCP_HEADERS)
    assert resp.status_code == 404


async def test_allowlist_blocks_disallowed_tool_before_reaching_upstream(argus_client):
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("write_file", {"path": "/etc/passwd", "content": "x"}),
        headers=MCP_HEADERS,
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["data"]["rule"] == "allowlist"
    # The whole point: a blocked call must never execute against the real upstream.
    assert upstream.call_counter.get("write_file") is None


async def test_allowlist_permits_allowed_tool(argus_client):
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    headers = await _initialized_session_headers(client)
    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("echo") == 1


async def test_denylist_blocks_denied_tool(argus_client):
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="denylist", denied=["write_file"]))

    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("write_file", {"path": "/x", "content": "y"}),
        headers=MCP_HEADERS,
    )
    assert resp.status_code == 403
    assert upstream.call_counter.get("write_file") is None


async def test_param_rule_blocks_regardless_of_mode(argus_client):
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(
        server.id,
        ServerPolicy(
            mode="passthrough",
            param_rules={"read_file": {"path": ParamRule(block_patterns=[r"/etc/"])}},
        ),
    )

    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("read_file", {"path": "/etc/shadow"}), headers=MCP_HEADERS,
    )
    assert resp.status_code == 403
    assert upstream.call_counter.get("read_file") is None


async def test_blocked_call_is_persisted_to_audit_log(argus_client):
    client, server_repo, _, db = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("write_file", {"path": "/x", "content": "y"}),
        headers=MCP_HEADERS,
    )
    assert resp.status_code == 403

    # Give the audit logger's background flush loop a chance to run (FLUSH_INTERVAL_SECONDS).
    await asyncio.sleep(0.3)

    audit_repo = AuditRepo(db)
    events = await audit_repo.query(server_slug="test-server", decision="BLOCKED")
    assert len(events) == 1
    assert events[0]["tool"] == "write_file"
    assert events[0]["rule"] == "allowlist"


async def test_slow_tool_streams_through(argus_client):
    client, _, upstream, _ = argus_client
    headers = await _initialized_session_headers(client)
    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("slow_tool", {"delay_seconds": 0.2}), headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("slow_tool") == 1


async def test_header_mismatch_rejected(argus_client):
    client, _, upstream, _ = argus_client
    session_headers = await _initialized_session_headers(client)
    headers = {**session_headers, "Mcp-Method": "tools/call", "Mcp-Name": "totally_different_tool"}
    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == -32020
    assert upstream.call_counter.get("echo") is None


async def test_server_rate_limit_enforced(argus_client):
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", rate_limit="2/hour"))
    headers = await _initialized_session_headers(client)

    results = []
    for _ in range(3):
        resp = await client.post(
            "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
        )
        results.append(resp.status_code)

    assert results == [200, 200, 429]
    assert upstream.call_counter.get("echo") == 2  # the 3rd call must never reach the upstream


async def test_header_match_allowed_through(argus_client):
    client, _, upstream, _ = argus_client
    session_headers = await _initialized_session_headers(client)
    headers = {**session_headers, "Mcp-Method": "tools/call", "Mcp-Name": "echo"}
    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("echo") == 1
