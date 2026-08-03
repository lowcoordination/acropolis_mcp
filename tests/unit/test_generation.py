from __future__ import annotations

from starlette.requests import Request

from argus.generation import ClientGeneration, detect_client_generation


def _fake_request(headers: dict[str, str]) -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {"type": "http", "headers": raw_headers}
    return Request(scope)


def test_mcp_method_header_present_is_2026():
    req = _fake_request({"Mcp-Method": "tools/call"})
    assert detect_client_generation(req) == ClientGeneration.GEN_2026


def test_no_mcp_method_header_is_2025():
    req = _fake_request({"Content-Type": "application/json"})
    assert detect_client_generation(req) == ClientGeneration.GEN_2025
