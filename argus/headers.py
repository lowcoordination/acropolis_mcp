from __future__ import annotations

# Hop-by-hop headers that must never be forwarded by a proxy (RFC 7230 §6.1),
# plus host/content-length/transfer-encoding which the HTTP client recomputes itself.
# The original mcp-guard prototype only stripped 3 of these — extended here.
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
    }
)


def strip_hop_by_hop(raw_headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    return [(k, v) for k, v in raw_headers if k.lower() not in HOP_BY_HOP_HEADERS]


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
