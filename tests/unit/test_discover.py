from __future__ import annotations

import json

from argus.discover import synthesize_gateway_discover, synthesize_server_discover
from db.models import ServerRecord


def _server(**overrides) -> ServerRecord:
    defaults = dict(
        id=1, slug="s", name="S", upstream_url="http://x/mcp", enabled=True, in_aggregate=True,
        upstream_protocol=None, health_status="unknown", last_seen_at=None, discover_json=None,
        created_at="2026-01-01T00:00:00+00:00", updated_at="2026-01-01T00:00:00+00:00",
    )
    defaults.update(overrides)
    return ServerRecord(**defaults)


def test_synthesize_server_discover_unprobed_server():
    server = _server()
    result = synthesize_server_discover(server)
    assert result["serverInfo"] == {"name": "S"}
    assert result["supportedVersions"] == []


def test_synthesize_server_discover_uses_cached_probe_data():
    discover_json = json.dumps({
        "serverInfo": {"name": "real-upstream", "version": "1.29.0"},
        "capabilities": {"tools": {"listChanged": False}},
    })
    server = _server(upstream_protocol="2025-06-18", discover_json=discover_json)
    result = synthesize_server_discover(server)
    assert result["serverInfo"]["name"] == "real-upstream"
    assert result["supportedVersions"] == ["2025-06-18"]
    assert result["capabilities"] == {"tools": {"listChanged": False}}


def test_synthesize_server_discover_malformed_json_falls_back():
    server = _server(discover_json="not-json")
    result = synthesize_server_discover(server)
    assert result["serverInfo"] == {"name": "S"}


def test_synthesize_gateway_discover_lists_only_enabled_in_aggregate_servers():
    servers = [
        _server(id=1, slug="a", in_aggregate=True, enabled=True),
        _server(id=2, slug="b", in_aggregate=False, enabled=True),
        _server(id=3, slug="c", in_aggregate=True, enabled=False),
    ]
    result = synthesize_gateway_discover(servers)
    assert result["aggregatedServers"] == ["a"]


def test_synthesize_gateway_discover_omits_subscriptions_capability():
    result = synthesize_gateway_discover([])
    assert "subscriptions" not in result["capabilities"]


def test_synthesize_gateway_discover_advertises_both_protocol_versions():
    result = synthesize_gateway_discover([])
    assert "2026-07-28" in result["supportedVersions"]
    assert "2025-06-18" in result["supportedVersions"]
