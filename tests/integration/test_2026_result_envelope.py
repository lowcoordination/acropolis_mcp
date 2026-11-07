"""#172: a 2026-07-28 client validates every result strictly. `resultType` is required on all of
them, and `ttlMs` + `cacheScope` on the cacheable ones (tools/list, server/discover, ...).
Open WebUI 0.13.0 (MCP SDK 2.3.0) discarded every Acropolis response for want of them.

2025-generation callers must keep receiving the bare shape they always did."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server

HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
CACHE_FIELDS = {"resultType": "complete", "ttlMs": 0, "cacheScope": "private"}


@pytest.fixture
async def client(tmp_path: Path):
    async with run_fastmcp_server() as upstream:
        settings = Settings(
            data_dir=str(tmp_path), auth_mode="open",
            health_poll_enabled=False, audit_retention_enabled=False,
        )
        db = Database(tmp_path)
        await db.connect()
        await ServerRepo(db).create(slug="test-server", name="Test", upstream_url=f"{upstream.url}/mcp")
        app = create_app(settings, db)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
                yield c
        await db.close()


def _rpc(method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


def _gen2026(method: str, name: str | None = None) -> dict:
    headers = {**HEADERS, "Mcp-Method": method}
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


@pytest.mark.parametrize("path", ["/mcp/test-server", "/mcp"])
async def test_2026_tools_list_carries_required_fields(client, path):
    resp = await client.post(path, json=_rpc("tools/list"), headers=_gen2026("tools/list"))
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["tools"]
    for field, value in CACHE_FIELDS.items():
        assert result[field] == value, field


@pytest.mark.parametrize("path", ["/mcp/test-server", "/mcp"])
async def test_2026_server_discover_carries_required_fields(client, path):
    resp = await client.post(path, json=_rpc("server/discover"), headers=_gen2026("server/discover"))
    assert resp.status_code == 200
    result = resp.json()["result"]
    for field, value in CACHE_FIELDS.items():
        assert result[field] == value, field


async def test_2026_bridged_tools_call_carries_result_type(client):
    resp = await client.post(
        "/mcp/test-server",
        json=_rpc("tools/call", {"name": "echo", "arguments": {"message": "hi"}}),
        headers=_gen2026("tools/call", "echo"),
    )
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["resultType"] == "complete"
    assert result["content"], "the upstream content must survive the envelope"
    # tools/call is not cacheable: no cache directives.
    assert "ttlMs" not in result and "cacheScope" not in result


async def test_2025_client_tools_list_is_unchanged(client):
    resp = await client.post("/mcp/test-server", json=_rpc("tools/list"), headers=HEADERS)
    assert resp.status_code == 200
    assert set(resp.json()["result"]) == {"tools"}


async def test_2025_client_aggregate_tools_list_is_unchanged(client):
    resp = await client.post("/mcp", json=_rpc("tools/list"), headers=HEADERS)
    assert resp.status_code == 200
    assert set(resp.json()["result"]) == {"tools"}
