from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from argus.jsonrpc import UNSUPPORTED_PROTOCOL_VERSION, rpc_error, sanitize_rpc_id
from argus.upstream import CLIENT_INFO, UpstreamHandshakeCache, UpstreamHandshakeError, parse_sse_body

logger = logging.getLogger("argus.bridge")

# _meta keys defined by the 2026-07-28 spec for stateless per-request version/capability info.
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

SUPPORTED_2026_VERSION = "2026-07-28"

# Methods that only exist as part of the 2025-generation session lifecycle. A 2026 client
# should never send these (stateless clients have no session to establish) — if one does,
# it's a client bug, not something to bridge.
_2025_ONLY_LIFECYCLE_METHODS = frozenset({"initialize", "notifications/initialized"})

# 2026-spec features this bridge does not translate (see plan M2 punt rationale: the whole
# fleet is 2025-generation FastMCP with zero notification traffic today).
_UNSUPPORTED_2026_METHODS = frozenset({"subscriptions/listen"})


class BridgeError(Exception):
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        super().__init__(body)


class ProtocolBridge:
    """Translates a single stateless 2026-07-28-style JSON-RPC request into the equivalent
    2025-06-18 request against a real upstream, and translates the SSE response back into a
    single plain JSON body (2026 stateless clients expect application/json, not event-stream).

    Scope: request/response methods only (tools/call, tools/list, resources/read, prompts/get,
    resources/list, prompts/list). subscriptions/listen and mid-call MRTR are explicitly out of
    scope — see _UNSUPPORTED_2026_METHODS and bridge_call()'s input_required handling.
    """

    def __init__(self, client: httpx.AsyncClient, handshake_cache: UpstreamHandshakeCache):
        self._client = client
        self._handshakes = handshake_cache

    async def bridge_call(
        self, server_id: int, upstream_url: str, rpc_method: str, rpc_id: Any, params: dict,
        meta: Optional[dict] = None,
    ) -> tuple[int, dict]:
        """Returns (http_status, json_rpc_response_body) for a single bridged call."""
        meta = meta or {}

        if rpc_method in _2025_ONLY_LIFECYCLE_METHODS:
            raise BridgeError(
                400,
                rpc_error(rpc_id, f"'{rpc_method}' is a 2025-generation lifecycle method; "
                          "2026 stateless clients must not send it"),
            )

        if rpc_method in _UNSUPPORTED_2026_METHODS:
            raise BridgeError(
                501,
                rpc_error(rpc_id, f"'{rpc_method}' is not supported when bridging to a "
                          "2025-generation upstream (no notification channel to relay it over)"),
            )

        client_version = meta.get(META_PROTOCOL_VERSION)
        if client_version is not None and client_version != SUPPORTED_2026_VERSION:
            raise BridgeError(
                400,
                rpc_error(
                    rpc_id, f"unsupported protocol version {client_version!r}",
                    code=UNSUPPORTED_PROTOCOL_VERSION,
                ),
            )

        try:
            handshake = await self._handshakes.get_or_handshake(server_id, upstream_url)
        except UpstreamHandshakeError as e:
            raise BridgeError(502, rpc_error(rpc_id, f"upstream handshake failed: {e}"))

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": handshake.protocol_version,
        }
        if handshake.session_id:
            headers["Mcp-Session-Id"] = handshake.session_id

        upstream_body = {
            "jsonrpc": "2.0",
            "id": sanitize_rpc_id(rpc_id) or 1,
            "method": rpc_method,
            "params": params,
        }

        try:
            resp = await self._client.post(upstream_url, json=upstream_body, headers=headers)
        except httpx.HTTPError as e:
            raise BridgeError(502, rpc_error(rpc_id, f"upstream request failed: {e}"))

        if resp.status_code == 404:
            # Session likely expired/invalid upstream-side — invalidate and let the caller retry.
            self._handshakes.invalidate(server_id)
            raise BridgeError(502, rpc_error(rpc_id, "upstream session invalid; retry"))

        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            parsed = parse_sse_body(resp.text)
        elif resp.text:
            try:
                parsed = json.loads(resp.text)
            except json.JSONDecodeError:
                parsed = None
        else:
            parsed = None

        if parsed is None:
            raise BridgeError(502, rpc_error(rpc_id, "upstream returned an unparseable response"))

        # Re-stamp the id with the ORIGINAL caller's id (we may have substituted one above).
        parsed["id"] = sanitize_rpc_id(rpc_id)
        return (200 if "error" not in parsed else resp.status_code, parsed)

    def build_stateless_result_meta(self, server_info: Optional[dict]) -> dict:
        """_meta block to attach to a bridged response's result, per SEP-2575: servers SHOULD
        identify themselves in each result's _meta under the new stateless model."""
        meta: dict[str, Any] = {META_PROTOCOL_VERSION: SUPPORTED_2026_VERSION}
        if server_info:
            meta[META_SERVER_INFO] = server_info
        return meta
