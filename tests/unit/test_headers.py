from __future__ import annotations

import httpx

from argus.headers import (
    extract_name_from_params,
    filter_response_headers,
    header_matches_body,
    strip_hop_by_hop,
)


def test_strip_hop_by_hop_removes_all_listed():
    raw = [
        (b"host", b"example.com"),
        (b"content-length", b"10"),
        (b"connection", b"keep-alive"),
        (b"x-custom", b"value"),
    ]
    stripped = strip_hop_by_hop(raw)
    kept_keys = {k for k, _ in stripped}
    assert kept_keys == {b"x-custom"}


def test_strip_hop_by_hop_removes_authorization_and_cookie():
    # Security regression guard (review finding F5, 2026-08-04): authorization and cookie are
    # not RFC 7230 hop-by-hop headers, but they must never reach an upstream MCP server — see
    # the comment on HOP_BY_HOP_HEADERS in argus/headers.py for the credential-leak this closes.
    raw = [
        (b"authorization", b"Bearer acropolis_secret"),
        (b"cookie", b"acropolis_session=abc"),
        (b"x-custom", b"value"),
    ]
    stripped_keys = {k for k, _ in strip_hop_by_hop(raw)}
    assert b"authorization" not in stripped_keys
    assert b"cookie" not in stripped_keys
    assert b"x-custom" in stripped_keys


def test_strip_hop_by_hop_case_insensitive():
    raw = [(b"Host", b"example.com"), (b"Connection", b"close")]
    assert strip_hop_by_hop(raw) == []


def test_strip_hop_by_hop_removes_client_traceparent_and_tracestate():
    # Enterprise #9: the CLIENT's own inbound traceparent/tracestate must never pass straight
    # through to the upstream unmediated — see the TRACE_CONTEXT_HEADERS comment in
    # argus/headers.py for why this is a deliberate policy change, not incidental. The correct,
    # gateway-derived traceparent is re-added explicitly by argus/pipeline.py's _forward, sourced
    # from TracingManager.inject_headers(), never by letting the client's raw header survive
    # this filter.
    raw = [
        (b"traceparent", b"00-11111111111111111111111111111111-2222222222222222-01"),
        (b"tracestate", b"vendor=malicious-value"),
        (b"x-custom", b"value"),
    ]
    stripped_keys = {k for k, _ in strip_hop_by_hop(raw)}
    assert b"traceparent" not in stripped_keys
    assert b"tracestate" not in stripped_keys
    assert b"x-custom" in stripped_keys


def test_strip_hop_by_hop_traceparent_case_insensitive():
    raw = [(b"Traceparent", b"00-x-y-01"), (b"TraceState", b"a=b")]
    assert strip_hop_by_hop(raw) == []


def test_extract_name_tools_call():
    assert extract_name_from_params("tools/call", {"name": "read_file"}) == "read_file"


def test_extract_name_resources_read():
    assert extract_name_from_params("resources/read", {"uri": "file:///x"}) == "file:///x"


def test_extract_name_prompts_get():
    assert extract_name_from_params("prompts/get", {"name": "greeting"}) == "greeting"


def test_extract_name_other_method_returns_none():
    assert extract_name_from_params("initialize", {}) is None


def test_header_matches_body_both_absent_ok():
    assert header_matches_body(None, None, "tools/call", "read_file") is True


def test_header_matches_body_agree():
    assert header_matches_body("tools/call", "read_file", "tools/call", "read_file") is True


def test_header_matches_body_method_mismatch_rejected():
    assert header_matches_body("tools/call", "read_file", "resources/read", "read_file") is False


def test_header_matches_body_name_mismatch_rejected():
    assert header_matches_body("tools/call", "wrong_tool", "tools/call", "read_file") is False


def test_header_matches_body_method_present_name_absent_ok():
    assert header_matches_body("tools/list", None, "tools/list", None) is True


def test_filter_response_headers_drops_malicious_set_cookie():
    # F19 regression (review 2026-08-04): a malicious/compromised upstream emitting Set-Cookie
    # on Acropolis's own origin (the SPA and /mcp/* share an origin) could clobber the admin's
    # real session cookie — a denial-of-service even without forging a valid signature.
    upstream_headers = httpx.Headers({
        "content-type": "application/json",
        "set-cookie": "acropolis_session=attacker-controlled; Max-Age=0",
    })
    filtered = filter_response_headers(upstream_headers)
    assert "set-cookie" not in {k.lower() for k in filtered}
    assert filtered.get("content-type") == "application/json"


def test_filter_response_headers_drops_transfer_encoding_and_content_length():
    # Relaying upstream transfer-encoding/content-length while Starlette re-frames the
    # streamed body is a request-smuggling hazard behind some reverse proxies.
    upstream_headers = httpx.Headers({
        "content-type": "application/json",
        "transfer-encoding": "chunked",
        "content-length": "9999",
    })
    filtered = filter_response_headers(upstream_headers)
    assert "transfer-encoding" not in {k.lower() for k in filtered}
    assert "content-length" not in {k.lower() for k in filtered}


def test_filter_response_headers_keeps_mcp_session_id():
    # Must not be so aggressive it breaks the protocol — mcp-session-id is how a 2025-generation
    # upstream's session is threaded back to the client.
    upstream_headers = httpx.Headers({"mcp-session-id": "abc123", "x-unlisted-header": "drop-me"})
    filtered = filter_response_headers(upstream_headers)
    assert filtered.get("mcp-session-id") == "abc123"
    assert "x-unlisted-header" not in {k.lower() for k in filtered}
