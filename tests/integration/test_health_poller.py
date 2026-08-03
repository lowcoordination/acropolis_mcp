from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.repo import ServerRepo
from stoa.health import HealthPoller, probe_server

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


async def test_probe_server_falls_back_to_initialize_for_2025_upstream(db, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        health_status, protocol, discover_json = await probe_server(client, cache, server)

    assert health_status == "healthy"
    assert protocol == "2025-06-18"
    assert discover_json["serverInfo"]["name"] == "test-fixture"


async def test_probe_server_unreachable_upstream_is_unhealthy(db):
    server = await ServerRepo(db).create(slug="dead", name="Dead", upstream_url="http://127.0.0.1:1/mcp")
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        health_status, protocol, discover_json = await probe_server(client, cache, server)

    assert health_status == "unhealthy"
    assert protocol is None


async def test_poller_updates_server_health_in_db(db, upstream):
    repo = ServerRepo(db)
    await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    async with httpx.AsyncClient() as client:
        poller = HealthPoller(repo, client, UpstreamHandshakeCache(client))
        await poller.poll_once()

    updated = await repo.get("s")
    assert updated.health_status == "healthy"
    assert updated.upstream_protocol == "2025-06-18"
    assert updated.last_seen_at is not None


async def test_poller_skips_disabled_servers(db, upstream):
    repo = ServerRepo(db)
    await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp", enabled=False)

    async with httpx.AsyncClient() as client:
        poller = HealthPoller(repo, client, UpstreamHandshakeCache(client))
        await poller.poll_once()

    updated = await repo.get("s")
    assert updated.health_status == "unknown"  # untouched — never probed
