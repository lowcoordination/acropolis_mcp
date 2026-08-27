from __future__ import annotations

import asyncio
import json
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


# ---------------------------------------------------------------------------
# Issue #110 — 2026-07-28-generation server/discover probe
# ---------------------------------------------------------------------------

class _Discovery2026Upstream:
    """A raw TCP listener standing in for a 2026-07-28-generation MCP server: answers
    `server/discover` with a spec-shaped DiscoverResult and records every request it receives
    (method, headers, params) so a test can assert exactly what the probe sent.

    Deliberately STRICT about the routing contract, mirroring what the 2026 spec demands of a
    modern transport: the request must carry `Mcp-Method` (canonical casing — the lowercase
    literal the stranded branch had is exactly the failure mode a strict upstream rejects) and
    `MCP-Protocol-Version` matching the body, and the `_meta` envelope must carry
    protocolVersion/clientInfo/clientCapabilities. Any violation gets a JSON-RPC error back,
    which probe_server treats as unhealthy — so a contract violation fails the test loudly
    instead of passing silently."""

    def __init__(self):
        self._server: asyncio.AbstractServer | None = None
        self.url = ""
        # One dict per received request: {"method", "headers" (lowercased keys), "params"}.
        self.requests: list[dict] = []

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        headers: dict[str, str] = {}
        for line in head.decode().split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        body_bytes = await reader.readexactly(length) if length else b""
        body = json.loads(body_bytes) if body_bytes else {}
        self.requests.append({
            "method": body.get("method"),
            "headers": headers,
            "params": body.get("params") or {},
        })

        result = None
        error = None
        if body.get("method") == "server/discover":
            meta = (body.get("params") or {}).get("_meta") or {}
            if headers.get("mcp-method") != "server/discover":
                error = {"code": -32020, "message": "HEADER_MISMATCH: Mcp-Method missing or not matching body"}
            elif headers.get("mcp-protocol-version") != "2026-07-28":
                error = {"code": -32602, "message": "bad MCP-Protocol-Version"}
            elif meta.get("io.modelcontextprotocol/protocolVersion") != "2026-07-28":
                error = {"code": -32602, "message": "_meta missing io.modelcontextprotocol/protocolVersion"}
            elif "io.modelcontextprotocol/clientInfo" not in meta:
                error = {"code": -32602, "message": "_meta missing io.modelcontextprotocol/clientInfo"}
            elif "io.modelcontextprotocol/clientCapabilities" not in meta:
                error = {"code": -32602, "message": "_meta missing io.modelcontextprotocol/clientCapabilities"}
            else:
                result = {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "discovery-2026-fixture", "version": "1.0.0",
                        }
                    },
                }
        else:
            # A stateless 2026 server has no initialize handshake — anything else is not
            # implemented, so a probe that wrongly falls back here reads unhealthy.
            error = {"code": -32601, "message": "method not found"}

        resp_body: dict = {"jsonrpc": "2.0", "id": body.get("id")}
        if result is not None:
            resp_body["result"] = result
        else:
            resp_body["error"] = error
        payload = json.dumps(resp_body).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(payload)).encode() + b"\r\n\r\n" + payload
        )
        await writer.drain()
        writer.close()

    async def start(self) -> None:
        import socket as socket_module

        with socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def test_probe_server_2026_upstream_answers_discover_directly(db):
    """A 2026-generation upstream answers `server/discover` directly — the probe must be a
    single stateless call with NO initialize fallback, and it must carry the modern routing
    headers and the spec's `_meta` envelope (clientInfo INSIDE _meta, never at params top
    level). The fixture enforces the strict 2026 contract, so any deviation surfaces as
    unhealthy rather than a silent pass."""
    upstream = _Discovery2026Upstream()
    await upstream.start()
    try:
        server = await ServerRepo(db).create(slug="gen2026", name="Gen2026", upstream_url=upstream.url)
        async with httpx.AsyncClient() as client:
            cache = UpstreamHandshakeCache(client)
            health_status, protocol, discover_json, health_reason = await probe_server(client, cache, server)

        assert health_status == "healthy"
        assert protocol == "2026-07-28"
        assert discover_json["supportedVersions"] == ["2026-07-28"]
        assert discover_json["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "discovery-2026-fixture"
        assert health_reason is None

        # Single stateless server/discover — the initialize fallback must never run for a
        # 2026-generation upstream.
        assert [r["method"] for r in upstream.requests] == ["server/discover"]

        req = upstream.requests[0]
        assert req["headers"]["mcp-method"] == "server/discover"  # canonical constant, not a literal
        assert req["headers"]["mcp-protocol-version"] == "2026-07-28"
        meta = req["params"]["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        assert meta["io.modelcontextprotocol/clientInfo"] == {"name": "acropolis-gateway", "version": "0.1.0"}
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
        # Per the 2026-07-28 spec, clientInfo lives INSIDE _meta — never at params top level.
        assert "clientInfo" not in req["params"]
    finally:
        await upstream.stop()


async def test_probe_server_2026_upstream_keeps_authorization_header(db):
    """The header-dict rewrite (issue #110) must not disturb the existing behaviour of sending
    a configured upstream credential on the probe — a 2026-discovery request for an
    auth-requiring server still carries its resolved Authorization header."""
    upstream = _Discovery2026Upstream()
    await upstream.start()
    try:
        server = await ServerRepo(db).create(
            slug="gen2026-auth", name="Gen2026Auth", upstream_url=upstream.url,
            upstream_auth_header="Bearer probe-token-123",
        )
        async with httpx.AsyncClient() as client:
            cache = UpstreamHandshakeCache(client)
            health_status, protocol, discover_json, health_reason = await probe_server(client, cache, server)

        assert health_status == "healthy"
        assert protocol == "2026-07-28"
        assert upstream.requests[0]["headers"].get("authorization") == "Bearer probe-token-123"
    finally:
        await upstream.stop()
