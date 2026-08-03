from __future__ import annotations

from argus.upstream import parse_sse_body


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
