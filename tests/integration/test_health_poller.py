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
        health_status, protocol, discover_json, health_reason = await probe_server(client, cache, server)

    assert health_status == "healthy"
    assert protocol == "2025-06-18"
    assert discover_json["serverInfo"]["name"] == "test-fixture"


async def test_probe_server_unreachable_upstream_is_unhealthy(db):
    server = await ServerRepo(db).create(slug="dead", name="Dead", upstream_url="http://127.0.0.1:1/mcp")
    async with httpx.AsyncClient() as client:
        cache = UpstreamHandshakeCache(client)
        health_status, protocol, discover_json, health_reason = await probe_server(client, cache, server)

    assert health_status == "unhealthy"
    assert protocol is None
    # A plain network-level failure (no credential configured at all here) must NOT be
    # mistaken for the enterprise #5 secret-resolution-failure case — health_reason stays None.
    assert health_reason is None


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


class _AlwaysFailsSecretProvider:
    """Stands in for a Vault outage/bad key regardless of tier — see
    tests/integration/test_secret_resolution_failure.py's identical helper for the Pipeline
    side of this same regression requirement."""

    async def resolve(self, ref: str) -> str:
        from archon.secrets import SecretResolutionError

        raise SecretResolutionError(ref, "simulated resolution failure for testing")

    async def store(self, ref: str, value: str) -> str:
        raise NotImplementedError

    async def delete(self, ref: str) -> None:
        raise NotImplementedError


async def test_poller_marks_server_unhealthy_with_distinguishable_reason_on_secret_failure(db, upstream):
    """Enterprise #5's HealthPoller requirement, exercised through the REAL probe_server/
    HealthPoller code path (not mocked) — a server whose secret won't resolve reads unhealthy
    with a reason string that's clearly attributable to secret resolution, not a generic/opaque
    failure indistinguishable from the upstream simply being down."""
    repo = ServerRepo(db)
    await repo.create(
        slug="secured", name="Secured", upstream_url=f"{upstream.url}/mcp",
        upstream_auth_header="vault://secret/acropolis/secured#token",
    )

    async with httpx.AsyncClient() as client:
        poller = HealthPoller(
            repo, client, UpstreamHandshakeCache(client),
            secret_provider=_AlwaysFailsSecretProvider(),
        )
        await poller.poll_once()

    updated = await repo.get("secured")
    assert updated.health_status == "unhealthy"
    assert updated.health_reason is not None
    assert "secret resolution failed" in updated.health_reason.lower()
    # The upstream itself is healthy and reachable in this test (the fixture is running) — the
    # ONLY reason this server is unhealthy is the secret, and the reason string must say so
    # rather than reading like a network-level probe failure.
    assert "simulated resolution failure for testing" in updated.health_reason


async def test_poller_marks_server_unhealthy_via_poll_one_too(db, upstream):
    """poll_one() (used right after registering a server, and for an explicit UI re-probe) must
    honour the same guarantee as the background poll_once() loop — same underlying
    _probe_and_store, but worth a direct regression test since it's a distinct public entry
    point operators actually trigger."""
    repo = ServerRepo(db)
    await repo.create(
        slug="secured2", name="Secured2", upstream_url=f"{upstream.url}/mcp",
        upstream_auth_header="vault://secret/acropolis/secured2#token",
    )

    async with httpx.AsyncClient() as client:
        poller = HealthPoller(
            repo, client, UpstreamHandshakeCache(client),
            secret_provider=_AlwaysFailsSecretProvider(),
        )
        await poller.poll_one("secured2")

    updated = await repo.get("secured2")
    assert updated.health_status == "unhealthy"
    assert updated.health_reason is not None
    assert "secret resolution failed" in updated.health_reason.lower()
