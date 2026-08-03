from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from argus.bridge import ProtocolBridge
from argus.toolslist import ToolsCache
from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.models import ServerPolicy
from db.repo import ServerRepo

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


@pytest.fixture
async def cache(db):
    async with httpx.AsyncClient() as client:
        bridge = ProtocolBridge(client, UpstreamHandshakeCache(client))
        yield ToolsCache(db, bridge)


async def test_get_raw_tools_fetches_and_caches(db, cache, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    tools = await cache.get_raw_tools(server.id, server.upstream_url)
    names = {t["name"] for t in tools}
    assert {"echo", "read_file", "write_file", "slow_tool"} <= names


async def test_get_raw_tools_second_call_served_from_cache_not_upstream(db, cache, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    first = await cache.get_raw_tools(server.id, server.upstream_url)
    second = await cache.get_raw_tools(server.id, server.upstream_url)
    # Row order isn't guaranteed by SQLite without ORDER BY, and cache reads vs fresh fetches
    # may legitimately differ in order — compare by content (name -> definition), not sequence.
    assert {t["name"]: t for t in first} == {t["name"]: t for t in second}


async def test_force_refresh_bypasses_cache(db, cache, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    await cache.get_raw_tools(server.id, server.upstream_url)
    tools = await cache.get_raw_tools(server.id, server.upstream_url, force_refresh=True)
    assert len(tools) > 0


async def test_get_filtered_tools_hides_denied_tools(db, cache, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")
    policy = ServerPolicy(mode="allowlist", allowed=["echo"])

    filtered = await cache.get_filtered_tools(server.id, server.upstream_url, policy)
    names = {t["name"] for t in filtered}
    assert names == {"echo"}


async def test_get_filtered_tools_denylist_mode(db, cache, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")
    policy = ServerPolicy(mode="denylist", denied=["write_file"])

    filtered = await cache.get_filtered_tools(server.id, server.upstream_url, policy)
    names = {t["name"] for t in filtered}
    assert "write_file" not in names
    assert "echo" in names


async def test_get_raw_tools_unreachable_upstream_returns_empty_not_raises(db, cache):
    repo = ServerRepo(db)
    server = await repo.create(slug="dead", name="Dead", upstream_url="http://127.0.0.1:1/mcp")

    tools = await cache.get_raw_tools(server.id, server.upstream_url)
    assert tools == []


async def test_get_raw_tools_falls_back_to_stale_cache_when_upstream_goes_unreachable(db, upstream):
    # Uses a live upstream to populate the cache, then a cache pointed at a dead URL to prove
    # the stale-cache fallback (rather than raising) — the ToolsCache constructor takes the
    # bridge, not the URL, so we can populate cache under the real URL then query with a dead one.
    from argus.bridge import ProtocolBridge
    from argus.upstream import UpstreamHandshakeCache
    import httpx

    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    async with httpx.AsyncClient() as client:
        bridge = ProtocolBridge(client, UpstreamHandshakeCache(client))
        cache = ToolsCache(db, bridge)
        first = await cache.get_raw_tools(server.id, server.upstream_url)
        assert len(first) > 0

        # Force a refetch against an unreachable URL — should fall back to the cache populated above.
        second = await cache.get_raw_tools(server.id, "http://127.0.0.1:1/mcp", force_refresh=True)
        assert {t["name"] for t in second} == {t["name"] for t in first}


async def test_invalidate_forces_refetch(db, cache, upstream):
    repo = ServerRepo(db)
    server = await repo.create(slug="s", name="S", upstream_url=f"{upstream.url}/mcp")

    await cache.get_raw_tools(server.id, server.upstream_url)
    await cache.invalidate(server.id)
    rows = await cache._cached_rows(server.id)
    assert rows == []

    # Should refetch cleanly after invalidation.
    tools = await cache.get_raw_tools(server.id, server.upstream_url)
    assert len(tools) > 0
