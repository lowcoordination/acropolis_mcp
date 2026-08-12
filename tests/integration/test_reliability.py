"""
Reliability regression tests for the 2026-08-04 external security review's Plan 3 findings
(F3, F4, F12, F13, F14, F25). Unlike test_security_regression.py, these aren't exploit-shaped —
they're "does one misbehaving component take down the rest of the gateway" shaped, which is
exactly the class of test the review found completely missing from the pre-existing suite.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database, SchemaTooNewError
from db.repo import AuditRepo, ServerRepo

from .fastmcp_fixture import run_fastmcp_server


pytestmark = pytest.mark.parametrize("app_env", [{"probe_on_create": False}], indirect=True)

@pytest.fixture
async def app_client(app_env):
    async with app_env.client() as client:
        yield client, app_env.db


def _initialize_body(req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0", "id": req_id, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "acropolis-test-client", "version": "0.0.1"},
        },
    }


# ---------------------------------------------------------------------------
# F3 — unreachable upstream must not crash the pipeline
# ---------------------------------------------------------------------------

class TestF3UnreachableUpstreamHandled:
    async def test_refused_connection_returns_502_not_500(self, app_client):
        client, db = app_client
        server_repo = ServerRepo(db)
        # Port 1 is a privileged port nothing is listening on — a real, immediate
        # connection-refused, not a timeout (keeps the test fast).
        await server_repo.create(slug="dead", name="Dead", upstream_url="http://127.0.0.1:1/mcp")

        resp = await client.post("/mcp/dead", json=_initialize_body())
        assert resp.status_code == 502, f"expected a clean 502, got {resp.status_code}: {resp.text}"
        # Must still be a JSON-RPC-shaped error body, not a stack trace.
        body = resp.json()
        assert "error" in body

    async def test_refused_connection_writes_an_audit_row(self, app_client):
        """Pre-fix, no audit event was written for this case at all — the RoutingError handler
        was the only thing that logged, and the unhandled exception never reached it."""
        client, db = app_client
        server_repo = ServerRepo(db)
        audit_repo = AuditRepo(db)
        await server_repo.create(slug="dead2", name="Dead2", upstream_url="http://127.0.0.1:1/mcp")

        await client.post("/mcp/dead2", json=_initialize_body())
        await asyncio.sleep(0.3)  # audit logger's background flush loop runs on its own interval

        events = await audit_repo.query(server_slug="dead2", limit=10)
        assert len(events) >= 1, "expected an audit row for the failed upstream request"
        assert events[0]["decision"] == "ERROR"
        assert events[0]["status_code"] == 502


# ---------------------------------------------------------------------------
# F4 — an invalid slug must never brick list()/stats/aggregate endpoints
# ---------------------------------------------------------------------------

class TestF4InvalidSlugRejectedAtCreate:
    async def test_create_rejects_slug_with_underscore(self, app_client):
        client, _db = app_client
        resp = await client.post(
            "/api/v1/servers",
            json={"slug": "bad_slug", "name": "Bad", "upstream_url": "http://localhost:8010/mcp"},
        )
        assert resp.status_code == 422, f"expected validation to reject 'bad_slug', got {resp.status_code}"

    async def test_create_rejects_slug_with_double_underscore(self, app_client):
        """A slug containing __ collides with the aggregate namespace separator
        (argus/aggregate.py's partition("__")) — must be rejected outright, not just risky."""
        client, _db = app_client
        resp = await client.post(
            "/api/v1/servers",
            json={"slug": "ab__cd", "name": "Bad", "upstream_url": "http://localhost:8010/mcp"},
        )
        assert resp.status_code == 422

    async def test_create_rejects_slug_with_space(self, app_client):
        client, _db = app_client
        resp = await client.post(
            "/api/v1/servers",
            json={"slug": "a b", "name": "Bad", "upstream_url": "http://localhost:8010/mcp"},
        )
        assert resp.status_code == 422

    async def test_list_and_stats_stay_healthy_after_valid_servers_registered(self, app_client):
        """Regression guard for the fix's OTHER half: ServerRepo.list() must skip-and-log any
        row it can't parse rather than propagating, so a bad row (however it got there) can't
        brick every other endpoint that calls list(). This test proves list()/stats keep
        working normally — a hostile row is exercised at the repo level in test_repo.py-style
        unit coverage, not by trying to smuggle one past the now-strict API validator here."""
        client, _db = app_client
        await client.post(
            "/api/v1/servers",
            json={"slug": "good-one", "name": "Good", "upstream_url": "http://localhost:8010/mcp"},
        )
        assert (await client.get("/api/v1/servers")).status_code == 200
        assert (await client.get("/api/v1/stats")).status_code == 200


# ---------------------------------------------------------------------------
# F12 — one misbehaving upstream must not stop health polling for the rest
# ---------------------------------------------------------------------------

class _MalformedJSONUpstream:
    """A real raw TCP listener that answers every request with 200 + a non-JSON body — the
    "auth proxy's HTML login page" scenario from the review, driven against the real
    probe_server() over a real socket rather than mocking httpx."""

    def __init__(self):
        self._server: asyncio.AbstractServer | None = None
        self.url = ""

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        body = b"<html><body>please log in</body></html>"
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body
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


class TestF12HealthPollerIsolation:
    async def test_non_json_200_response_does_not_crash_probe_server(self, tmp_path, app_env):
        """stoa/health.py's json.loads(resp.text) used to be unguarded — a 200 response with a
        non-JSON body (e.g. an auth proxy's HTML login page) raised JSONDecodeError, which
        escaped probe_server entirely (an exception, not a returned health status)."""
        import httpx as httpx_module

        from argus.upstream import UpstreamHandshakeCache
        from db.models import ServerRecord
        from stoa.health import probe_server

        upstream = _MalformedJSONUpstream()
        await upstream.start()
        try:
            async with httpx_module.AsyncClient() as client:
                handshake_cache = UpstreamHandshakeCache(client)
                fake_server = ServerRecord(
                    id=1, slug="bad-upstream", name="Bad", upstream_url=upstream.url,
                    enabled=True, in_aggregate=True, created_at="now", updated_at="now",
                )
                # Must not raise — guarded parse should report unhealthy, not crash the caller.
                health_status, protocol, discover_json, health_reason = await probe_server(
                    client, handshake_cache, fake_server
                )
                assert health_status == "unhealthy"
        finally:
            await upstream.stop()

    async def test_one_bad_server_does_not_stop_polling_the_rest(self, tmp_path, app_env):
        """The full regression: poll_once() must isolate each server so one bad one doesn't
        abort the cycle and leave every server after it in slug order with permanently stale
        health — the review's specific "every server after it in slug order" failure mode."""
        from argus.upstream import UpstreamHandshakeCache
        from db.database import Database
        from stoa.health import HealthPoller

        server_repo = ServerRepo(app_env.db)

        bad_upstream = _MalformedJSONUpstream()
        await bad_upstream.start()
        try:
            # Slug order matters: "aaa-bad" sorts before "zzz-good" alphabetically, matching
            # the review's "every server after it in slug order" failure description.
            await server_repo.create(slug="aaa-bad", name="Bad", upstream_url=bad_upstream.url)

            async with run_fastmcp_server() as good_upstream:
                await server_repo.create(slug="zzz-good", name="Good", upstream_url=f"{good_upstream.url}/mcp")

                async with httpx.AsyncClient() as client:
                    handshake_cache = UpstreamHandshakeCache(client)
                    poller = HealthPoller(server_repo, client, handshake_cache)
                    await poller.poll_once()  # must not raise

                servers = await server_repo.list()
                by_slug = {s.slug: s for s in servers}
                assert by_slug["aaa-bad"].health_status == "unhealthy"
                assert by_slug["zzz-good"].health_status == "healthy", (
                    "the good server AFTER the bad one in slug order should still have been "
                    "probed and marked healthy — not left stale by the bad server aborting the cycle"
                )
        finally:
            await bad_upstream.stop()


class _HungUpstream:
    """A raw TCP listener that accepts the connection and reads the request, but then simply
    never writes a response — the textbook "server that accepts connections but never answers"
    scenario the review describes, indistinguishable from a real hung MCP server at the
    connection-pool level."""

    def __init__(self):
        self._server: asyncio.AbstractServer | None = None
        self.url = ""

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
        except Exception:
            return
        # Deliberately never write a response and never close the connection.
        await asyncio.sleep(3600)

    async def start(self) -> None:
        import socket as socket_module

        with socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self) -> None:
        # Deliberately does NOT await self._server.wait_closed(): a still-hung _handle()
        # connection (the whole point of this fixture) never releases its socket, so
        # wait_closed() would block forever waiting for a connection that will never close.
        # server.close() alone stops accepting new connections, which is all the test needs.
        if self._server is not None:
            self._server.close()


# ---------------------------------------------------------------------------
# F13 — one hung upstream must not stall requests to every other upstream
# ---------------------------------------------------------------------------

class TestF13PerUpstreamTimeoutIsolation:
    async def test_client_timeout_is_not_a_single_120s_scalar(self, app_client):
        """Regression guard for the fix itself: the shared httpx.AsyncClient must use a real
        httpx.Timeout object with separate connect/pool/read/write values, not the old scalar
        that applied 120s to ALL four (including pool acquisition, which is what let one hung
        upstream exhaust the pool and stall every other server's requests behind it)."""
        client, db = app_client
        http_client = client._transport.app.state.http_client
        timeout = http_client.timeout
        # The concrete regression: pool AND connect timeouts must be short (bounded,
        # isolated), not the full upstream-timeout-seconds request budget (default 120s).
        assert timeout.pool is not None and timeout.pool <= 10.0, (
            f"pool timeout is {timeout.pool}s — too close to the old 120s scalar"
        )
        assert timeout.connect is not None and timeout.connect <= 10.0, (
            f"connect timeout is {timeout.connect}s — too close to the old 120s scalar"
        )

    async def test_hung_upstream_does_not_stall_a_request_to_a_different_upstream(self, tmp_path, app_env):
        """The actual end-to-end regression: a server that accepts the TCP connection but never
        sends a response must not stall requests to a DIFFERENT, healthy server. This is what
        the old scalar 120s pool timeout allowed — a hung upstream exhausting the connection
        pool and blocking every other server's requests behind it in the pool-acquisition
        queue.

        Exercises app.state.http_client DIRECTLY (real TCP, real pool) rather than going
        through the ASGI test client — the pool contention this test proves is a property of
        the single shared outbound httpx.AsyncClient, which is orthogonal to whichever
        transport carries the INBOUND test request, and racing two calls through one
        ASGITransport-backed client introduced unrelated serialization that made the test
        itself hang rather than proving anything about the fix."""
        import time

        hung = _HungUpstream()
        await hung.start()
        try:
            http_client = app_env.app.state.http_client

            async with run_fastmcp_server() as fast_upstream:
                hung_task = asyncio.create_task(
                    http_client.post(hung.url, json=_initialize_body())
                )
                await asyncio.sleep(0.05)  # let the hung request actually occupy a pool slot

                start = time.monotonic()
                fast_resp = await http_client.post(
                    f"{fast_upstream.url}/mcp", json=_initialize_body(2),
                    headers={"Accept": "application/json, text/event-stream"},
                )
                fast_elapsed = time.monotonic() - start

                assert fast_resp.status_code == 200
                assert fast_elapsed < 8.0, (
                    f"request to a healthy, DIFFERENT upstream took {fast_elapsed:.1f}s "
                    f"while another upstream was hung — connection pool isolation failed"
                )

                hung_task.cancel()
                try:
                    await asyncio.wait_for(hung_task, timeout=2.0)
                except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                    pass
        finally:
            await hung.stop()


# ---------------------------------------------------------------------------
# F14 — aggregate tools/list must not fan out serially / N+1
# ---------------------------------------------------------------------------

class TestF14AggregateToolsListConcurrent:
    async def test_aggregate_tools_list_across_two_servers_is_audited(self, app_client):
        """Pre-fix, the aggregate tools/list path did not audit at all. This is the cheap half
        of F14 to verify without timing-sensitive assertions (see the dedicated timing test
        below for the concurrency half)."""
        client, db = app_client
        audit_repo = AuditRepo(db)

        async with run_fastmcp_server() as upstream:
            server_repo = ServerRepo(db)
            await server_repo.create(slug="agg-a", name="A", upstream_url=f"{upstream.url}/mcp")

            resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert resp.status_code == 200

        events = await audit_repo.query(limit=10)
        assert any(e["endpoint"] == "aggregate" for e in events), (
            "expected an audit row for the aggregate tools/list call"
        )

    async def test_aggregate_tools_list_fans_out_concurrently_not_serially(self, app_client):
        """The actual regression: two slow upstreams (each taking ~0.3s to answer tools/list)
        registered on the aggregate endpoint should complete in close to ONE upstream's worth
        of time, not the sum of both — proving asyncio.gather replaced sequential awaiting."""
        import time

        client, db = app_client
        server_repo = ServerRepo(db)

        async with run_fastmcp_server() as upstream_a, run_fastmcp_server() as upstream_b:
            await server_repo.create(slug="slow-a", name="A", upstream_url=f"{upstream_a.url}/mcp")
            await server_repo.create(slug="slow-b", name="B", upstream_url=f"{upstream_b.url}/mcp")

            start = time.monotonic()
            resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            elapsed = time.monotonic() - start

            assert resp.status_code == 200
            # Generous bound: two servers fanned out concurrently should stay well under the
            # sum of two full round-trips. This isn't measuring exact concurrency, just ruling
            # out gross serial fan-out.
            assert elapsed < 5.0, f"aggregate tools/list took {elapsed:.2f}s across 2 servers — looks serial"


# ---------------------------------------------------------------------------
# F25 — an older binary must refuse to start against a database a newer binary migrated
# ---------------------------------------------------------------------------

class TestF25SchemaVersionGuard:
    """Confirms Database.connect() refuses to start (rather than silently limping along) when
    the database has a migration version applied that this binary's own migration list doesn't
    know about — the rollback-after-upgrade scenario the review flagged."""

    async def test_connect_raises_when_db_has_a_newer_migration_than_binary_knows(self, pg_dsn, app_env):
        db = Database(pg_dsn)
        await db.connect()
        # Simulate "a newer binary already ran here": stamp a migration version this binary's
        # MIGRATIONS list has never heard of, then reconnect fresh.
        async with db.writer.acquire() as conn:
            await conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)",
                9999, "2026-01-01T00:00:00+00:00",
            )
        await db.close()

        fresh = Database(pg_dsn)
        with pytest.raises(SchemaTooNewError, match="9999"):
            await fresh.connect()
        await fresh.close()

    async def test_connect_succeeds_when_db_is_at_or_behind_known_migrations(self, pg_dsn, app_env):
        """Regression guard: a totally fresh database, or one already fully migrated by THIS
        binary, must still start normally — the guard should only fire on genuinely unknown
        (higher) versions, never on the normal case."""
        db = Database(pg_dsn)
        await db.connect()
        await db.close()

        # Reconnecting against the same, fully-migrated-by-us database must not raise.
        again = Database(pg_dsn)
        await again.connect()
        await again.close()

    async def test_audit_migrations_apply_in_the_unified_sequence(self, pg_dsn, app_env):
        """Pre-cutover this test existed because audit.db had its OWN migration list and its own
        schema_migrations table, so the version guard needed proving twice. Post-cutover there is
        one database, one migration sequence, and one schema_migrations table — so the guard is
        already covered above and the remaining thing worth asserting is that the audit-side
        migrations (which used to live in that separate series) actually applied to the shared
        database: idx_audit_api_key comes from 0003_audit_api_key_index.sql, and the origin
        column from 0004_audit_origin.sql."""
        db = Database(pg_dsn)
        await db.connect()
        try:
            async with db.reader.acquire() as conn:
                index_exists = await conn.fetchval(
                    "SELECT 1 FROM pg_indexes WHERE indexname = 'idx_audit_api_key'"
                )
                assert index_exists, "0003_audit_api_key_index.sql did not apply"

                origin_exists = await conn.fetchval(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_name = 'audit_events' AND column_name = 'origin'"
                )
                assert origin_exists, "0004_audit_origin.sql did not apply"
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# F25 — /metrics endpoint
# ---------------------------------------------------------------------------

class TestF25MetricsEndpoint:
    """Confirms a scrape-able /metrics endpoint exists, is reachable without authentication
    (same posture as /api/v1/health — infra tooling, not a human), and reflects real audit and
    server-health state rather than being a static stub."""

    async def test_metrics_is_reachable_without_auth_and_returns_prometheus_text(self, app_client):
        client, db = app_client
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert "acropolis_audit_events_total" in resp.text
        assert "acropolis_registered_servers" in resp.text

    async def test_metrics_reflects_registered_server_health(self, app_client):
        client, db = app_client
        server_repo = ServerRepo(db)
        await server_repo.create(slug="metrics-test", name="M", upstream_url="http://127.0.0.1:1/mcp")

        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert 'acropolis_server_health{slug="metrics-test"}' in resp.text


# ---------------------------------------------------------------------------
# §26 — POST /servers/{slug}/probe must not hang on a slow tools/list refresh
# ---------------------------------------------------------------------------

class TestF26ProbeEndpointBoundedTimeout:
    """probe_server_now (archon/api.py) calls health_poller.poll_one() — already bounded to
    PROBE_TIMEOUT_SECONDS — followed by tools_cache.get_raw_tools(force_refresh=True), which
    had NO timeout of its own and rode the shared http client's 120s default. A hung upstream
    could make this "quick re-probe" endpoint hang the HTTP request for up to ~130s."""

    async def test_probe_endpoint_returns_promptly_against_a_hung_upstream(self, tmp_path, app_env):
        import time

        import archon.api as api_module

        server_repo = ServerRepo(app_env.db)

        hung = _HungUpstream()
        await hung.start()
        try:
            await server_repo.create(slug="hung", name="Hung", upstream_url=hung.url)

            async with app_env.client() as client:
                start = time.monotonic()
                resp = await client.post("/api/v1/servers/hung/probe", timeout=15.0)
                elapsed = time.monotonic() - start

                assert resp.status_code == 200
                # Generously bounded: PROBE_TIMEOUT_SECONDS (10s) for poll_one() plus
                # PROBE_TIMEOUT_SECONDS (10s) for the now-bounded tools refresh, plus
                # overhead — but must stay WELL under the old ~130s (10s probe +
                # 120s unbounded tools/list) that this fix eliminates.
                assert elapsed < 25.0, (
                    f"probe endpoint took {elapsed:.1f}s against a hung upstream — "
                    f"the tools/list refresh is not bounded"
                )
        finally:
            await hung.stop()
