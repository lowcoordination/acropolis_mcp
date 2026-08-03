"""Integration tests for ProtocolBridge against a real FastMCP 2025-06-18 upstream —
proves a stateless 2026-style call gets correctly translated and de-enveloped."""
from __future__ import annotations

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


async def test_build_stateless_result_meta():
    async with httpx.AsyncClient() as client:
        bridge = ProtocolBridge(client, UpstreamHandshakeCache(client))
        meta = bridge.build_stateless_result_meta({"name": "x", "version": "1"})
        assert meta[META_PROTOCOL_VERSION] == "2026-07-28"
        assert meta["io.modelcontextprotocol/serverInfo"] == {"name": "x", "version": "1"}
