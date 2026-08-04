from __future__ import annotations

from argus.headers import extract_name_from_params, header_matches_body, strip_hop_by_hop


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
