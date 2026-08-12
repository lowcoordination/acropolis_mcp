"""Integration tests for ProtocolBridge against a real FastMCP 2025-06-18 upstream —
proves a stateless 2026-style call gets correctly translated and de-enveloped."""
from __future__ import annotations

import json

import httpx
import pytest

from argus.bridge import META_PROTOCOL_VERSION, BridgeError, ProtocolBridge
from argus.upstream import UpstreamHandshakeCache

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def bridge():
    async with httpx.AsyncClient() as client:
        yield ProtocolBridge(client, UpstreamHandshakeCache(client))


async def test_bridge_tools_call_returns_plain_json(bridge, upstream):
    status, body = await bridge.bridge_call(
        server_id=1, upstream_url=f"{upstream.url}/mcp", rpc_method="tools/call",
        rpc_id=42, params={"name": "echo", "arguments": {"message": "bridged!"}},
    )
    assert status == 200
    assert body["id"] == 42
    assert body["result"]["content"][0]["text"] == "bridged!"
    assert upstream.call_counter.get("echo") == 1


async def test_bridge_tools_list(bridge, upstream):
    status, body = await bridge.bridge_call(
        server_id=1, upstream_url=f"{upstream.url}/mcp", rpc_method="tools/list",
        rpc_id=1, params={},
    )
    assert status == 200
    tool_names = {t["name"] for t in body["result"]["tools"]}
    assert "echo" in tool_names
    assert "read_file" in tool_names


async def test_bridge_rejects_initialize_from_2026_client(bridge, upstream):
    with pytest.raises(BridgeError) as exc_info:
        await bridge.bridge_call(
            server_id=1, upstream_url=f"{upstream.url}/mcp", rpc_method="initialize",
            rpc_id=1, params={},
        )
    assert exc_info.value.status_code == 400


async def test_bridge_rejects_subscriptions_listen(bridge, upstream):
    with pytest.raises(BridgeError) as exc_info:
        await bridge.bridge_call(
            server_id=1, upstream_url=f"{upstream.url}/mcp", rpc_method="subscriptions/listen",
            rpc_id=1, params={},
        )
    assert exc_info.value.status_code == 501


async def test_bridge_rejects_unsupported_protocol_version(bridge, upstream):
    with pytest.raises(BridgeError) as exc_info:
        await bridge.bridge_call(
            server_id=1, upstream_url=f"{upstream.url}/mcp", rpc_method="tools/call",
            rpc_id=1, params={"name": "echo", "arguments": {}},
            meta={META_PROTOCOL_VERSION: "1999-01-01"},
        )
    assert exc_info.value.status_code == 400


async def test_bridge_against_dead_upstream_returns_502(bridge):
    with pytest.raises(BridgeError) as exc_info:
        await bridge.bridge_call(
            server_id=1, upstream_url="http://127.0.0.1:1/mcp", rpc_method="tools/call",
            rpc_id=1, params={"name": "echo", "arguments": {}},
        )
    assert exc_info.value.status_code == 502


async def test_bridge_reuses_session_across_calls(bridge, upstream):
    # Two calls to the same server_id should reuse one handshake/session (proven indirectly:
    # if the session were re-established each time and the fixture rejected stale sessions,
    # the second call would fail, since FastMCP's session manager is keyed per transport).
    status1, _ = await bridge.bridge_call(
        server_id=7, upstream_url=f"{upstream.url}/mcp", rpc_method="tools/call",
        rpc_id=1, params={"name": "echo", "arguments": {"message": "one"}},
    )
    status2, _ = await bridge.bridge_call(
        server_id=7, upstream_url=f"{upstream.url}/mcp", rpc_method="tools/call",
        rpc_id=2, params={"name": "echo", "arguments": {"message": "two"}},
    )
    assert status1 == 200
    assert status2 == 200
    assert upstream.call_counter.get("echo") == 2


async def test_bridge_transparently_re_handshakes_on_session_invalid():
    """§26 fix (review 2026-08-04): a 404 on the bridged call (session expired/invalid
    upstream-side) used to invalidate the cached handshake and immediately surface a 502 to the
    CALLER, telling THEM to retry — pushing a transient, gateway-recoverable hiccup out to the
    end client. Scripted via httpx.MockTransport (not a real FastMCP fixture — this needs precise
    control over a 404-then-success sequence, which a real session manager won't reliably
    reproduce): first initialize succeeds, first tools/call 404s, the re-handshake succeeds, the
    retried tools/call succeeds. The caller should see a clean 200, never the 502."""
    import json as _json

    handshake_count = 0
    call_attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal handshake_count, call_attempts
        payload = _json.loads(request.content)
        method = payload.get("method")
        if method == "initialize":
            handshake_count += 1
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0", "id": "acropolis-handshake",
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {}, "serverInfo": {"name": "stub", "version": "0"},
                    },
                },
                headers={"mcp-session-id": f"session-{handshake_count}"},
            )
        if method == "notifications/initialized":
            return httpx.Response(200, json={})
        if method == "tools/call":
            call_attempts += 1
            if call_attempts == 1:
                return httpx.Response(404, text="session not found")
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": payload["id"], "result": {"content": []}},
            )
        raise AssertionError(f"unexpected method: {method}")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        bridge = ProtocolBridge(client, UpstreamHandshakeCache(client))
        status, body = await bridge.bridge_call(
            server_id=99, upstream_url="http://stub.invalid/mcp", rpc_method="tools/call",
            rpc_id=1, params={"name": "echo", "arguments": {}},
        )

    assert status == 200
    assert "error" not in body
    assert handshake_count == 2, "expected exactly one re-handshake after the 404"
    assert call_attempts == 2, "expected exactly one retry of the failed call"


@pytest.mark.parametrize("falsy_id", [0, 0.0, ""])
async def test_bridge_preserves_falsy_but_valid_rpc_ids(falsy_id):
    """Regression for issue #46: `sanitize_rpc_id(rpc_id) or 1` rewrote every FALSY-yet-valid
    JSON-RPC id (0, 0.0, "") to 1 on the way upstream.

    That silently collided distinct concurrent requests: the streamable-http upstream keys its
    per-request response streams by rpc id, and the gateway multiplexes concurrent calls onto
    one upstream session, so a client numbering from 0 sent both id 0 and id 1 upstream as id 1.
    The second displaced the first and the displaced response was never delivered — one request
    in every concurrent burst hung until the read timeout.

    Asserts on the id as it CROSSES THE WIRE, which is where the bug lived; asserting only on
    the returned body would pass even while broken, since bridge_call re-stamps the response
    with the caller's original id regardless."""
    seen_upstream_ids = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method = payload.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0", "id": payload["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {}, "serverInfo": {"name": "stub", "version": "0"},
                    },
                },
                headers={"mcp-session-id": "session-1"},
            )
        if method == "notifications/initialized":
            return httpx.Response(200, json={})
        if method == "tools/call":
            seen_upstream_ids.append(payload["id"])
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": payload["id"], "result": {"content": []}},
            )
        raise AssertionError(f"unexpected method: {method}")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        bridge = ProtocolBridge(client, UpstreamHandshakeCache(client))
        status, body = await bridge.bridge_call(
            server_id=1, upstream_url="http://stub.invalid/mcp", rpc_method="tools/call",
            rpc_id=falsy_id, params={"name": "echo", "arguments": {}},
        )

    assert status == 200
    assert seen_upstream_ids == [falsy_id], (
        f"id {falsy_id!r} must reach the upstream unchanged, not be rewritten to 1"
    )
    assert body["id"] == falsy_id


async def test_bridge_substitutes_an_id_only_when_the_caller_sent_none():
    """The complement of the test above: the fallback must still fire for a genuinely absent
    id, so #46's fix doesn't swing the other way and forward a null id upstream."""
    seen_upstream_ids = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method = payload.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0", "id": payload["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {}, "serverInfo": {"name": "stub", "version": "0"},
                    },
                },
                headers={"mcp-session-id": "session-1"},
            )
        if method == "notifications/initialized":
            return httpx.Response(200, json={})
        if method == "tools/call":
            seen_upstream_ids.append(payload["id"])
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": payload["id"], "result": {"content": []}},
            )
        raise AssertionError(f"unexpected method: {method}")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        bridge = ProtocolBridge(client, UpstreamHandshakeCache(client))
        await bridge.bridge_call(
            server_id=1, upstream_url="http://stub.invalid/mcp", rpc_method="tools/call",
            rpc_id=None, params={"name": "echo", "arguments": {}},
        )

    assert seen_upstream_ids == [1], "an absent id must still get the fallback"
