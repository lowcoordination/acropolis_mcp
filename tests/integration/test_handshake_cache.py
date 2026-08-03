from __future__ import annotations

import httpx
import pytest

from argus.upstream import UpstreamHandshakeCache, UpstreamHandshakeError

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


async def test_handshake_against_real_fastmcp_server(upstream):
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        result = await cache.get_or_handshake(server_id=1, upstream_url=f"{upstream.url}/mcp")

        assert result.protocol_version == "2025-06-18"
        assert result.server_info["name"] == "test-fixture"
        assert result.session_id  # FastMCP always issues one


async def test_handshake_is_cached_not_repeated(upstream):
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        first = await cache.get_or_handshake(server_id=1, upstream_url=f"{upstream.url}/mcp")
        second = await cache.get_or_handshake(server_id=1, upstream_url=f"{upstream.url}/mcp")
        assert first.session_id == second.session_id


async def test_handshake_invalidate_forces_rehandshake(upstream):
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        first = await cache.get_or_handshake(server_id=1, upstream_url=f"{upstream.url}/mcp")
        cache.invalidate(1)
        second = await cache.get_or_handshake(server_id=1, upstream_url=f"{upstream.url}/mcp")
        # A fresh handshake against FastMCP mints a new session id.
        assert first.session_id != second.session_id


async def test_handshake_against_dead_upstream_raises():
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        with pytest.raises(UpstreamHandshakeError):
            await cache.get_or_handshake(server_id=1, upstream_url="http://127.0.0.1:1/mcp")


async def test_different_servers_get_independent_sessions(upstream):
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        a = await cache.get_or_handshake(server_id=1, upstream_url=f"{upstream.url}/mcp")
        b = await cache.get_or_handshake(server_id=2, upstream_url=f"{upstream.url}/mcp")
        assert a.session_id != b.session_id
