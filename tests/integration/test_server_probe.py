"""Proves a newly-created server is probed immediately (not left at 'unknown' for up to a
full 60s poll interval), and that POST /servers/{slug}/probe lets the UI force a re-probe."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def client(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
            yield c
    await db.close()


async def test_create_server_probes_immediately_against_real_upstream(client, upstream):
    resp = await client.post(
        "/api/v1/servers", json={"slug": "s", "name": "S", "upstream_url": f"{upstream.url}/mcp"},
    )
    assert resp.status_code == 201
    body = resp.json()
    # No waiting for a poll cycle — the create response itself already reflects a real probe.
    assert body["health_status"] == "healthy"
    assert body["upstream_protocol"] == "2025-06-18"


async def test_create_server_against_dead_upstream_reports_unhealthy_immediately(client):
    resp = await client.post(
        "/api/v1/servers", json={"slug": "dead", "name": "Dead", "upstream_url": "http://127.0.0.1:1/mcp"},
    )
    assert resp.status_code == 201
    assert resp.json()["health_status"] == "unhealthy"


async def test_manual_probe_endpoint_refreshes_health(client, upstream):
    await client.post(
        "/api/v1/servers", json={"slug": "s", "name": "S", "upstream_url": "http://127.0.0.1:1/mcp"},
    )
    # Point it at the real upstream and re-probe — health should flip from unhealthy to healthy.
    await client.put("/api/v1/servers/s", json={"upstream_url": f"{upstream.url}/mcp"})
    resp = await client.post("/api/v1/servers/s/probe")
    assert resp.status_code == 200
    assert resp.json()["health_status"] == "healthy"


async def test_manual_probe_unknown_server_404(client):
    resp = await client.post("/api/v1/servers/nope/probe")
    assert resp.status_code == 404


async def test_manual_probe_also_refreshes_tools_cache(client, upstream):
    await client.post(
        "/api/v1/servers", json={"slug": "s", "name": "S", "upstream_url": f"{upstream.url}/mcp"},
    )
    resp = await client.post("/api/v1/servers/s/probe")
    assert resp.status_code == 200

    tools_resp = await client.get("/api/v1/servers/s/tools")
    names = {t["name"] for t in tools_resp.json()}
    assert "echo" in names
