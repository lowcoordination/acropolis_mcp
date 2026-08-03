from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

logger = logging.getLogger("argus.upstream")

MCP_2025_VERSION = "2025-06-18"
MCP_2026_VERSION = "2026-07-28"

CLIENT_INFO = {"name": "argus-gateway", "version": "0.1.0"}

# Deliberately advertise NO sampling/elicitation/roots capabilities when bridging to a
# 2025-generation upstream — those are all "server calls back into the client" patterns,
# and a bridged 2026 client has no channel for the gateway to relay such a callback through
# (MRTR translation is out of scope for M2, see argus/bridge.py). Advertising none of them
# means 2025 upstreams should never attempt to initiate one against us in the first place.
BRIDGE_CLIENT_CAPABILITIES: dict[str, Any] = {}


class UpstreamHandshakeError(Exception):
    pass


@dataclass
class HandshakeResult:
    session_id: Optional[str]
    server_info: Optional[dict]
    capabilities: Optional[dict]
    protocol_version: str


def parse_sse_body(text: str) -> Optional[dict]:
    """Extract the terminal JSON-RPC message from a `text/event-stream` response body.

    FastMCP (2025-06-18) replies to POST with a single SSE frame:
        event: message\r\ndata: {...}\r\n\r\n
    There can in principle be multiple `data:` lines in one frame (continuation) or multiple
    frames; we concatenate all `data:` payloads found and parse the last complete JSON object,
    which is the terminal response for a request/response-shaped call.
    """
    data_lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())

    if not data_lines:
        return None

    # Parse each candidate independently and keep the last one that's valid JSON — pings/
    # keepalives are not JSON and should be skipped rather than aborting the whole parse.
    result = None
    for candidate in data_lines:
        try:
            result = json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return result


class UpstreamHandshakeCache:
    """Per-server cached `initialize` handshake against a 2025-06-18-generation upstream.

    Used by both the health poller (to detect upstream generation) and the 2026->2025 bridge
    (to obtain a session id to attach to bridged requests). A lock per server_id avoids two
    concurrent bridged requests racing to initialize the same upstream twice.
    """

    def __init__(self, client: httpx.AsyncClient):
        self._client = client
        self._cache: dict[int, HandshakeResult] = {}
        self._locks: dict[int, asyncio.Lock] = {}

    def _lock_for(self, server_id: int) -> asyncio.Lock:
        if server_id not in self._locks:
            self._locks[server_id] = asyncio.Lock()
        return self._locks[server_id]

    def invalidate(self, server_id: int) -> None:
        self._cache.pop(server_id, None)

    async def get_or_handshake(self, server_id: int, upstream_url: str) -> HandshakeResult:
        cached = self._cache.get(server_id)
        if cached is not None:
            return cached

        async with self._lock_for(server_id):
            cached = self._cache.get(server_id)
            if cached is not None:
                return cached
            result = await self._handshake(upstream_url)
            self._cache[server_id] = result
            return result

    async def _handshake(self, upstream_url: str) -> HandshakeResult:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        init_body = {
            "jsonrpc": "2.0",
            "id": "argus-handshake",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_2025_VERSION,
                "capabilities": BRIDGE_CLIENT_CAPABILITIES,
                "clientInfo": CLIENT_INFO,
            },
        }
        try:
            resp = await self._client.post(upstream_url, json=init_body, headers=headers)
        except httpx.HTTPError as e:
            raise UpstreamHandshakeError(f"initialize request failed: {e}") from e

        if resp.status_code != 200:
            raise UpstreamHandshakeError(
                f"initialize returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        session_id = resp.headers.get("mcp-session-id")
        parsed = parse_sse_body(resp.text) if "text/event-stream" in resp.headers.get(
            "content-type", ""
        ) else (json.loads(resp.text) if resp.text else None)

        if parsed is None or "result" not in parsed:
            raise UpstreamHandshakeError(f"initialize response did not contain a result: {resp.text[:200]}")

        result = parsed["result"]
        server_info = result.get("serverInfo")
        capabilities = result.get("capabilities")
        protocol_version = result.get("protocolVersion", MCP_2025_VERSION)

        # Required by the streamable-http transport before any other call is accepted.
        notif_headers = dict(headers)
        if session_id:
            notif_headers["Mcp-Session-Id"] = session_id
        try:
            await self._client.post(
                upstream_url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=notif_headers,
            )
        except httpx.HTTPError as e:
            logger.warning("notifications/initialized failed (continuing anyway): %s", e)

        return HandshakeResult(
            session_id=session_id, server_info=server_info,
            capabilities=capabilities, protocol_version=protocol_version,
        )
