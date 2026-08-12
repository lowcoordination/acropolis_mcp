from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from argus.jsonrpc import UNSUPPORTED_PROTOCOL_VERSION, rpc_error, sanitize_rpc_id
from argus.tracing import TracingManager, _DisabledTracingManager
from argus.upstream import CLIENT_INFO, UpstreamHandshakeCache, UpstreamHandshakeError, parse_sse_body

logger = logging.getLogger("argus.bridge")

# _meta keys defined by the 2026-07-28 spec for stateless per-request version/capability info.
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"

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

    def __init__(
        self, client: httpx.AsyncClient, handshake_cache: UpstreamHandshakeCache,
        tracing: Optional[TracingManager] = None,
    ):
        self._client = client
        self._handshakes = handshake_cache
        # Enterprise #9: same "defaults to an inert no-op" shape as Pipeline._tracing — every
        # existing caller/test that constructs a ProtocolBridge without a tracing kwarg gets a
        # manager whose .span() is a pure no-op, so this default is part of the "disabled =
        # byte-identical to today" guarantee.
        self._tracing = tracing or _DisabledTracingManager()

    async def bridge_call(
        self, server_id: int, upstream_url: str, rpc_method: str, rpc_id: Any, params: dict,
        meta: Optional[dict] = None, upstream_auth_header: Optional[str] = None,
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

        # Issue #46: this was `sanitize_rpc_id(rpc_id) or 1`. The `or` was meant to supply a
        # fallback id when the caller sent none, but it fires on every FALSY-yet-valid id too —
        # 0, 0.0 and "" are all legal JSON-RPC ids, and all three got silently rewritten to 1.
        #
        # That is a lost-response bug, not a cosmetic one: the streamable-http upstream keys its
        # per-request response streams by rpc id (mcp/server/streamable_http.py), and the gateway
        # multiplexes concurrent calls onto ONE upstream session. A client numbering its requests
        # from 0 therefore sends both id 0 and id 1 upstream as id 1; the second registration
        # displaces the first, and the displaced request's response is written to a stream nobody
        # is reading. It hangs until the read timeout. Only `None` may take the fallback.
        sanitized_id = sanitize_rpc_id(rpc_id)
        upstream_body = {
            "jsonrpc": "2.0",
            "id": sanitized_id if sanitized_id is not None else 1,
            "method": rpc_method,
            "params": params,
        }

        # §26 fix (review 2026-08-04): a 404 (session expired/invalid upstream-side) used to
        # invalidate the cached handshake and immediately surface a 502 telling the CALLER to
        # retry — pushing a transient, gateway-recoverable hiccup out to the end client instead
        # of just handling it. One re-handshake-and-resend, transparent to the caller, matches
        # what a client-side MCP SDK does on session loss; only give up and surface an error if
        # the retry ALSO fails, so a genuinely dead upstream doesn't retry forever.
        for attempt in range(2):
            with self._tracing.span(
                "bridge.handshake", attributes={"acropolis.bridged": True},
            ) as handshake_span:
                try:
                    handshake = await self._handshakes.get_or_handshake(
                        server_id, upstream_url, upstream_auth_header=upstream_auth_header
                    )
                except UpstreamHandshakeError as e:
                    raise BridgeError(502, rpc_error(rpc_id, f"upstream handshake failed: {e}"))
                handshake_span.set_attribute("acropolis.mcp_protocol_version", handshake.protocol_version)

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": handshake.protocol_version,
            }
            if handshake.session_id:
                headers["Mcp-Session-Id"] = handshake.session_id
            # F23 fix (review 2026-08-04): the bridged path built a fresh header dict with NO
            # Authorization at all — correct in that it never leaked the client's own credential
            # (see argus/headers.py's F5 fix for the passthrough-path equivalent of that leak),
            # but it also meant an upstream requiring its own auth could never be bridged. Inject
            # the per-server configured credential here, same mechanism as the passthrough path.
            if upstream_auth_header:
                headers["Authorization"] = upstream_auth_header

            with self._tracing.span(
                "upstream.forward", attributes={"acropolis.bridged": True},
            ) as forward_span:
                # Enterprise #9: traceparent/tracestate are injected here, from INSIDE the
                # upstream.forward span, so the outbound header correctly parent-chains under
                # THIS span (not the handshake span, not the root request span) — an observer in
                # the collector sees the upstream call as the direct parent of whatever the
                # upstream server does next. inject_headers() returns {} when tracing is
                # inactive, so this is a no-op merge on the disabled path.
                headers.update(self._tracing.inject_headers())
                try:
                    resp = await self._client.post(upstream_url, json=upstream_body, headers=headers)
                except httpx.HTTPError as e:
                    raise BridgeError(502, rpc_error(rpc_id, f"upstream request failed: {e}"))
                forward_span.set_attribute("http.status_code", resp.status_code)

            if resp.status_code == 404:
                self._handshakes.invalidate(server_id)
                if attempt == 0:
                    continue
                raise BridgeError(502, rpc_error(rpc_id, "upstream session invalid; retry"))
            break

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
