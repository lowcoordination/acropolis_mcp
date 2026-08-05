"""
Integration tests: real Acropolis FastAPI app (via ASGI transport, no sockets) proxying to a real
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
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
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
            "clientInfo": {"name": "acropolis-test-client", "version": "0.0.1"},
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
    so acropolis does no session handling itself — it just relays whatever the upstream issues."""
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


async def test_audit_log_records_client_ip(argus_client):
    """F22 regression (review 2026-08-04): client_ip is a parameter on AuditLogger.log() and a
    column in audit_events — grep confirmed no call site anywhere ever passed it, so every
    record had client_ip = NULL. The test fixture's ASGITransport reports a fixed client
    ('127.0.0.1', 123) unless overridden — this asserts the real value actually lands in the
    persisted row, not just that the column exists.

    Deliberately uses a BLOCKED call (never reaches the upstream) rather than a real
    passthrough tools/call: a real call goes through _forward's StreamingResponse against the
    live FastMCP fixture, and a real session handshake + streamed body right before this
    fixture tears down was observed to destabilize the NEXT test's own, unrelated FastMCP
    fixture (RemoteProtocolError) — a pre-existing streaming-teardown fragility in the test
    fixtures, not something this test needs to exercise to prove client_ip is recorded."""
    client, server_repo, _, db = argus_client
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("write_file", {"path": "/x", "content": "y"}),
        headers=MCP_HEADERS,
    )
    assert resp.status_code == 403

    await asyncio.sleep(0.3)

    audit_repo = AuditRepo(db)
    events = await audit_repo.query(server_slug="test-server", decision="BLOCKED")
    assert len(events) >= 1
    assert events[-1]["client_ip"] == "127.0.0.1", (
        f"expected client_ip to be recorded, got {events[-1]['client_ip']!r}"
    )


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


async def test_server_rate_limit_change_takes_effect_without_restart(argus_client):
    """F8 regression (review 2026-08-04): raising a rate limit via a real set_policy() call —
    the same path the /api/v1/servers/{slug}/policy route uses — must take effect on the VERY
    NEXT request. Pre-fix, the bucket was registered once and the `not is_registered(...)`
    guard meant a changed limit was silently ignored until process restart."""
    client, server_repo, upstream, _ = argus_client
    server = await server_repo.get("test-server")
    headers = await _initialized_session_headers(client)

    await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", rate_limit="1/hour"))
    resp1 = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "a"}), headers=headers,
    )
    resp2 = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "b"}), headers=headers,
    )
    assert (resp1.status_code, resp2.status_code) == (200, 429)  # exhausted at limit 1

    # Operator raises the limit through the real policy-write path — not a restart.
    await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", rate_limit="10/hour"))
    resp3 = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "c"}), headers=headers,
    )
    assert resp3.status_code == 200, (
        "raising the rate limit via set_policy() did not take effect on the next request"
    )


async def test_header_match_allowed_through(argus_client):
    client, _, upstream, _ = argus_client
    session_headers = await _initialized_session_headers(client)
    headers = {**session_headers, "Mcp-Method": "tools/call", "Mcp-Name": "echo"}
    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
    )
    assert resp.status_code == 200
    assert upstream.call_counter.get("echo") == 1


async def test_tools_call_fetches_policy_only_once(argus_client, monkeypatch):
    """§26 fix (review 2026-08-04): a single tools/call used to fetch the server's policy
    TWICE — once inside _check_rate_limits (to read policy.rate_limit) and again immediately
    afterward by the caller (to evaluate the tool decision) — two DB reads of the same,
    request-scoped-immutable data per call. Now the caller fetches once and passes it through.

    Patches the ServerRepo CLASS method (not the fixture's own server_repo instance) — the
    running app's Pipeline holds a SEPARATE ServerRepo instance constructed internally by
    create_app(), not the one this test's fixture uses to seed the server, so an instance-level
    monkeypatch on the fixture's object would silently miss every call the app actually makes."""
    client, _, upstream, _ = argus_client
    # Deliberately NOT using the Mcp-Method/Mcp-Name headers here (see
    # test_header_match_allowed_through) — their presence flips detect_client_generation to
    # GEN_2026, routing through _handle_bridged instead of the plain-2025 tools/call branch.
    # This test targets the passthrough branch specifically; the bridged branch has its own
    # equivalent fix and is covered separately.
    headers = await _initialized_session_headers(client)

    call_count = 0
    original_get_policy = ServerRepo.get_policy

    async def counting_get_policy(self, server_id):
        nonlocal call_count
        call_count += 1
        return await original_get_policy(self, server_id)

    monkeypatch.setattr(ServerRepo, "get_policy", counting_get_policy)

    resp = await client.post(
        "/mcp/test-server", json=_tool_call_body("echo", {"message": "hi"}), headers=headers,
    )

    assert resp.status_code == 200
    assert call_count == 1, f"expected exactly 1 get_policy() call per tools/call, got {call_count}"
