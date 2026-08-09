from __future__ import annotations

# Hop-by-hop headers that must never be forwarded by a proxy (RFC 7230 §6.1),
# plus host/content-length/transfer-encoding which the HTTP client recomputes itself.
# The original mcp-guard prototype only stripped 3 of these — extended here.
#
# SECURITY: authorization and cookie are stripped here too, even though neither is hop-by-hop
# by the RFC 7230 definition. Without this, the CALLER's gateway credentials (their Bearer
# acropolis_* API key, or — since the SPA and /mcp/* share an origin — the admin's
# acropolis_session cookie) are forwarded verbatim to whatever upstream MCP server is
# registered. Any registered upstream (third-party, compromised, or attacker-registered) could
# harvest and replay those credentials. If an upstream needs its own auth, that must come from a
# per-server credential the operator configures — never from relaying the client's own headers.
HOP_BY_HOP_HEADERS = frozenset(
    {
        b"host",
        b"content-length",
        b"transfer-encoding",
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"te",
        b"trailer",
        b"trailers",
        b"upgrade",
        b"authorization",
        b"cookie",
    }
)

# Enterprise #9 (OTel tracing): the CLIENT'S OWN inbound traceparent/tracestate are stripped
# here unconditionally, same denylist mechanism as authorization/cookie above — NOT because
# they're sensitive, but because strip_hop_by_hop's output previously fed straight into the
# passthrough forward (argus/pipeline.py's _forward) with no processing at all, so any client
# could already stamp an arbitrary, ungoverned traceparent onto the upstream request today.
# That's an incidental passthrough, exactly what the plan (01-otel-tracing.md design decision 3)
# says this feature must NOT ship as. The correct traceparent is instead re-added deliberately in
# argus/pipeline.py's _forward, sourced from TracingManager.inject_headers() (i.e. derived from
# the gateway's own upstream.forward span, correctly parent-chained under whatever inbound
# traceparent the ROOT span was told to honor) — never a raw copy-through of the client header.
# See tests/integration/test_otel_propagation.py for both directions of this: tracing disabled
# -> no traceparent reaches upstream at all; tracing enabled -> the one that reaches upstream is
# gateway-derived and correctly parent-chained, not the client's verbatim value.
TRACE_CONTEXT_HEADERS = frozenset({b"traceparent", b"tracestate"})


def strip_hop_by_hop(raw_headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    return [
        (k, v) for k, v in raw_headers
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() not in TRACE_CONTEXT_HEADERS
    ]


# F19 fix (review 2026-08-04): the upstream response used to be relayed with headers=dict(
# r.headers) — every header the upstream sent, unfiltered, straight to the browser. Since the
# SPA and /mcp/* share an origin, a malicious or compromised upstream could emit Set-Cookie on
# the ACROPOLIS origin (can't forge a valid signed admin session — see archon/sessions.py's
# HMAC — but can clobber the admin's real cookie as a denial-of-service), or inject
# caching/content-type directives the browser then trusts as if Acropolis itself sent them.
# Relaying upstream transfer-encoding/content-length while Starlette re-frames the streamed
# body is also a request-smuggling hazard behind some reverse proxies. Allowlist instead of
# denylist: only forward headers a legitimate MCP JSON-RPC response actually needs, so a newly
# invented dangerous header doesn't silently start passing through unnoticed.
ALLOWED_RESPONSE_HEADERS = frozenset(
    {
        b"content-type",
        b"cache-control",
        b"mcp-session-id",
        b"mcp-protocol-version",
    }
)


def filter_response_headers(headers) -> dict[str, str]:
    """Allowlists upstream response headers before they're relayed to the browser. `headers`
    accepts anything supporting .items() with str keys (httpx.Headers, dict) — always
    lower-cased for comparison since HTTP header names are case-insensitive."""
    return {k: v for k, v in headers.items() if k.lower().encode() in ALLOWED_RESPONSE_HEADERS}


# MCP spec 2026-07-28: required routing headers on Streamable HTTP POST requests.
MCP_METHOD_HEADER = "Mcp-Method"
MCP_NAME_HEADER = "Mcp-Name"

# Methods for which Mcp-Name is required (carries the tool/resource/prompt name).
METHODS_REQUIRING_NAME = frozenset({"tools/call", "resources/read", "prompts/get"})


def extract_name_from_params(rpc_method: str, params: dict) -> str | None:
    """Pull the resource identifier out of a JSON-RPC body, matching what Mcp-Name should carry."""
    if rpc_method == "tools/call":
        return params.get("name")
    if rpc_method == "resources/read":
        return params.get("uri")
    if rpc_method == "prompts/get":
        return params.get("name")
    return None


def header_matches_body(
    mcp_method_header: str | None,
    mcp_name_header: str | None,
    rpc_method: str,
    body_name: str | None,
) -> bool:
    """
    Verify routing headers agree with the JSON-RPC body they claim to describe.
    Security invariant: headers are a fast-path hint, never a trust source — the body is
    authoritative. This check exists to REJECT mismatches (-32020), never to fast-allow.
    Absent headers (2025-generation clients) are not a mismatch — they simply weren't sent.
    """
    if mcp_method_header is not None and mcp_method_header != rpc_method:
        return False
    if mcp_name_header is not None and mcp_name_header != body_name:
        return False
    return True
