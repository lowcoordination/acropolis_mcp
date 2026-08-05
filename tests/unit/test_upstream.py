from __future__ import annotations

import json

import httpx
import pytest

import argus.upstream as upstream_module
from argus.upstream import UpstreamHandshakeCache, parse_sse_body


def test_parse_sse_body_single_frame():
    text = 'event: message\r\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\r\n\r\n'
    parsed = parse_sse_body(text)
    assert parsed == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}


def test_parse_sse_body_no_data_lines_returns_none():
    assert parse_sse_body("event: ping\r\n\r\n") is None


def test_parse_sse_body_empty_string_returns_none():
    assert parse_sse_body("") is None


def test_parse_sse_body_skips_non_json_data_lines():
    text = "data: not-json\r\n\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\r\n\r\n"
    parsed = parse_sse_body(text)
    assert parsed == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_parse_sse_body_returns_last_valid_frame():
    text = (
        'data: {"jsonrpc":"2.0","id":1,"result":"first"}\r\n\r\n'
        'data: {"jsonrpc":"2.0","id":2,"result":"second"}\r\n\r\n'
    )
    parsed = parse_sse_body(text)
    assert parsed["id"] == 2


def _handshake_handler(counter: dict) -> callable:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        if payload.get("method") == "initialize":
            counter["count"] = counter.get("count", 0) + 1
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0", "id": "acropolis-handshake",
                    "result": {
                        "protocolVersion": "2025-06-18", "capabilities": {},
                        "serverInfo": {"name": "stub", "version": "0"},
                    },
                },
                headers={"mcp-session-id": f"session-{counter['count']}"},
            )
        return httpx.Response(200, json={})

    return handler


async def test_handshake_cache_reuses_within_ttl():
    counter: dict = {}
    transport = httpx.MockTransport(_handshake_handler(counter))
    async with httpx.AsyncClient(transport=transport) as client:
        cache = UpstreamHandshakeCache(client)
        first = await cache.get_or_handshake(1, "http://stub.invalid/mcp")
        second = await cache.get_or_handshake(1, "http://stub.invalid/mcp")
    assert first.session_id == second.session_id
    assert counter["count"] == 1


async def test_handshake_cache_re_handshakes_after_ttl_expires(monkeypatch):
    """§26 fix (review 2026-08-04): a cached handshake never expired on its own — only an
    explicit invalidate() (on a 401 or a bridged-call 404) ever evicted it. A stale-but-cached
    handshake on the health-poller path could mask a real upstream restart indefinitely. This
    proves a handshake older than the TTL is discarded and re-fetched, without waiting a real
    hour — the module-level TTL constant is monkeypatched down to 0 for the test."""
    monkeypatch.setattr(upstream_module, "_HANDSHAKE_TTL_SECONDS", 0.0)
    counter: dict = {}
    transport = httpx.MockTransport(_handshake_handler(counter))
    async with httpx.AsyncClient(transport=transport) as client:
        cache = UpstreamHandshakeCache(client)
        first = await cache.get_or_handshake(1, "http://stub.invalid/mcp")
        second = await cache.get_or_handshake(1, "http://stub.invalid/mcp")
    assert first.session_id != second.session_id
    assert counter["count"] == 2
