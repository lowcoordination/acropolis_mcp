from __future__ import annotations

import json
from typing import Optional

from db.models import ServerRecord

ACROPOLIS_VERSION = "0.1.0"


def synthesize_server_discover(server: ServerRecord) -> dict:
    """Build a server/discover result for a single per-server endpoint, from the health
    poller's cached probe data (ServerRecord.discover_json). If never probed yet, returns a
    minimal result advertising only what we know for certain (the slug/name)."""
    cached: dict = {}
    if server.discover_json:
        try:
            cached = json.loads(server.discover_json)
        except json.JSONDecodeError:
            cached = {}

    server_info = cached.get("serverInfo") or {"name": server.name}
    capabilities = cached.get("capabilities") or {}
    supported_versions = [server.upstream_protocol] if server.upstream_protocol else []

    return {
        "serverInfo": server_info,
        "capabilities": capabilities,
        "supportedVersions": supported_versions,
    }


def synthesize_gateway_discover(servers: list[ServerRecord]) -> dict:
    """server/discover for the aggregate /mcp endpoint — presents Acropolis itself as one
    server whose capabilities are the union of its enabled, in_aggregate upstreams. Per the
    spec, subscriptions capability is deliberately omitted (subscriptions/listen is
    unsupported — see argus.bridge._UNSUPPORTED_2026_METHODS and the plan's M2 punt rationale)."""
    aggregated = [s for s in servers if s.enabled and s.in_aggregate]
    return {
        "serverInfo": {"name": "acropolis-gateway", "version": ACROPOLIS_VERSION},
        "capabilities": {
            "tools": {"listChanged": False},
            # resources/prompts are not exposed on the aggregate endpoint in M2 (v1 aggregates
            # tools only — see plan's aggregate scope note).
        },
        "supportedVersions": ["2026-07-28", "2025-06-18"],
        "aggregatedServers": [s.slug for s in aggregated],
    }
