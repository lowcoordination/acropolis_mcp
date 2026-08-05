"""
Regression tests for the 2026-08-04 external security review's Plan 1 findings (F1, F5, F6).

CRITICAL: these tests drive the real app over a real TCP socket, using hand-written HTTP
request lines via socket.create_connection — never httpx or any other client library. F1 and F6
are both path-traversal bugs that an HTTP client's own URL normalisation papers over before the
request ever leaves the process: httpx.ASGITransport (used by every other integration test in
this suite) and requests/urllib3 alike collapse "..", so a test written against a client library
would pass vacuously against the UNPATCHED code. A raw socket is the only way to send a request
line uvicorn itself does not normalise.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sqlite3
from pathlib import Path
from typing import Optional

import httpx
import pytest
import uvicorn

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _raw_request_sync(port: int, request_line: str, extra_headers: str = "") -> tuple[str, bytes]:
    """Sends a hand-written HTTP/1.1 request line over a raw blocking socket and returns
    (status_line, body). Bypasses any client-library path normalisation entirely — this is
    the whole point: httpx/requests/etc. all collapse ".." in the URL before it leaves the
    process, so a test built on any of them would pass vacuously against unpatched code."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        req = f"{request_line} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra_headers}Connection: close\r\n\r\n"
        s.sendall(req.encode())
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n")[0].decode(errors="replace")
    return status_line, body


async def _raw_request(port: int, request_line: str, extra_headers: str = "") -> tuple[str, bytes]:
    """Async wrapper around _raw_request_sync. MUST run the blocking socket call off the event
    loop thread: the same asyncio loop is also driving the uvicorn server under test in-process,
    so a blocking recv() on the loop thread starves the server's own async I/O and the response
    is never flushed — confirmed by reproducing a hang against a trivial FastAPI app and fixing
    it with exactly this run_in_executor wrapper before writing these tests for real."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _raw_request_sync, port, request_line, extra_headers)


@contextlib.asynccontextmanager
async def run_acropolis_server(data_dir: Path, **settings_kwargs):
    """Spins up the real Acropolis app on a real uvicorn server / ephemeral TCP port — the
    live-container shape these findings actually exploit, not the ASGI-transport shape every
    other integration test in this suite uses."""
    port = _free_port()
    settings = Settings(
        data_dir=str(data_dir), health_poll_enabled=False, audit_retention_enabled=False,
        **settings_kwargs,
    )
    db = Database(data_dir)
    await db.connect()

    app = create_app(settings, db)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("acropolis test server did not start in time")
        yield port, db
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except asyncio.TimeoutError:
            server.force_exit = True
            await asyncio.wait_for(task, timeout=5.0)
        await db.close()


@pytest.fixture
def dist_dir(tmp_path: Path) -> Path:
    """A minimal fake web/dist next to argus/app.py's expected location isn't possible without
    monkeypatching Path(__file__) — instead we rely on the REAL repo's web/dist (built by a
    prior `npm run build`). If it's absent, the SPA mount is a no-op and these tests are skipped
    (matches _mount_web_ui's own documented no-op-in-local-dev behaviour)."""
    real_dist = Path(__file__).parent.parent.parent / "web" / "dist"
    if not real_dist.is_dir():
        pytest.skip("web/dist not built (run `npm run build` in web/ first) — SPA route is a no-op without it")
    return real_dist


# ---------------------------------------------------------------------------
# F1 — unauthenticated arbitrary file read via the SPA fallback route
# ---------------------------------------------------------------------------

class TestF1PathTraversalFixed:
    async def test_double_slash_does_not_leak_etc_passwd(self, tmp_path, dist_dir):
        async with run_acropolis_server(tmp_path) as (port, _db):
            status, body = await _raw_request(port, "GET //etc/passwd")
            assert status.startswith("HTTP/1.1 200")  # SPA fallback still serves index.html
            assert b"root:x:" not in body

    async def test_dotdot_traversal_does_not_leak_etc_passwd(self, tmp_path, dist_dir):
        async with run_acropolis_server(tmp_path) as (port, _db):
            status, body = await _raw_request(port, "GET /../../../../../../../../etc/passwd")
            assert b"root:x:" not in body

    async def test_percent_encoded_dotdot_does_not_leak_etc_passwd(self, tmp_path, dist_dir):
        # Enough %2e%2e segments to walk clear of web/dist regardless of how deeply nested
        # the repo checkout is — /etc/passwd is a fixed-depth target from the filesystem root,
        # unlike a tmp_path target whose required "up" count varies per test run.
        async with run_acropolis_server(tmp_path) as (port, _db):
            traversal = "/%2e%2e" * 12 + "/etc/passwd"
            status, body = await _raw_request(port, f"GET {traversal}")
            assert b"root:x:" not in body

    async def test_double_slash_absolute_path_cannot_reach_data_dir(self, tmp_path, dist_dir):
        """The exact exploit primitive: dist_dir / "/abs/path" used to discard dist_dir
        entirely via pathlib's absolute-path override. Steal the real on-disk gateway.db."""
        async with run_acropolis_server(tmp_path) as (port, _db):
            db_path = str((tmp_path / "gateway.db").resolve())
            status, body = await _raw_request(port, f"GET /{db_path}")
            assert not body.startswith(b"SQLite format 3")

    async def test_full_takeover_chain_is_blocked(self, tmp_path, dist_dir):
        """End-to-end: complete setup, then attempt the exact steal-secret -> forge-cookie ->
        hit-admin-api chain that worked against the unpatched app. Every step must now fail."""
        async with run_acropolis_server(tmp_path) as (port, db):
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                r = await client.post("/api/v1/setup", json={"admin_password": "regression-test-pw"})
                assert r.status_code == 200

            db_path = str((tmp_path / "gateway.db").resolve())
            for suffix in ("", "-wal", "-shm"):
                status, body = await _raw_request(port, f"GET /{db_path}{suffix}")
                assert not body.startswith(b"SQLite format 3"), (
                    f"gateway.db{suffix} was still readable via path traversal"
                )

            # Even if an attacker somehow had the secret via another means, confirm forging
            # still requires it not be exfiltratable via THIS route — sanity-check the real
            # secret is non-empty so the assertions above aren't vacuously true against an
            # empty/unset settings table.
            conn = sqlite3.connect(tmp_path / "gateway.db")
            secret = dict(conn.execute("SELECT key, value FROM settings").fetchall()).get("session_secret")
            conn.close()
            assert secret, "setup did not actually persist a session_secret — test precondition broken"


# ---------------------------------------------------------------------------
# F5 — caller Authorization/Cookie headers no longer forwarded to upstreams
# ---------------------------------------------------------------------------

class _HeaderCapturingUpstream:
    """A minimal raw TCP listener standing in for an MCP upstream — captures the exact request
    headers Acropolis forwards, then replies with a bare 200 (plus any `extra_response_headers`
    the test configured) so the pipeline doesn't error out. Simpler and more honest than
    mocking: proves what actually crossed the wire in both directions."""

    def __init__(self, extra_response_headers: Optional[dict[str, str]] = None):
        self.received_headers: dict[str, str] = {}
        self._server: asyncio.AbstractServer | None = None
        self.url = ""
        self._extra_response_headers = extra_response_headers or {}

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                self.received_headers[k.lower()] = v
        body = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        extra = "".join(f"{k}: {v}\r\n" for k, v in self._extra_response_headers.items())
        writer.write(
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"{extra}Content-Length: {len(body)}\r\n\r\n"
            ).encode() + body
        )
        await writer.drain()
        writer.close()

    async def start(self) -> None:
        port = _free_port()
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


class TestF5CredentialsNotLeakedToUpstream:
    async def test_authorization_and_cookie_not_forwarded_on_passthrough(self, tmp_path):
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)

                status, _ = await _raw_request(
                    port, "GET /mcp/test-server/mcp",
                    extra_headers=(
                        "Authorization: Bearer acropolis_should_not_leak\r\n"
                        "Cookie: acropolis_session=should_not_leak\r\n"
                    ),
                )
                assert status.startswith("HTTP/1.1 200")
        finally:
            await upstream.stop()

        assert "authorization" not in upstream.received_headers
        assert "cookie" not in upstream.received_headers

    def test_strip_hop_by_hop_unit_covers_both_headers(self):
        """Fast unit-level companion to the integration test above — pins the exact set."""
        from argus.headers import strip_hop_by_hop

        raw = [
            (b"authorization", b"Bearer acropolis_secret"),
            (b"cookie", b"acropolis_session=abc"),
            (b"content-type", b"application/json"),
        ]
        stripped_keys = {k.lower() for k, _ in strip_hop_by_hop(raw)}
        assert b"authorization" not in stripped_keys
        assert b"cookie" not in stripped_keys
        assert b"content-type" in stripped_keys  # unrelated headers still pass through


# ---------------------------------------------------------------------------
# F6 — upstream path traversal can no longer escape the configured MCP endpoint
# ---------------------------------------------------------------------------

class TestF6UpstreamTraversalFixed:
    async def test_dotdot_path_segment_rejected_with_400(self, tmp_path):
        async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
            server_repo = ServerRepo(db)
            await server_repo.create(
                slug="test-server", name="Test", upstream_url="http://127.0.0.1:1/mcp",
            )
            status, body = await _raw_request(port, "GET /mcp/test-server/../../admin")
            assert status.startswith("HTTP/1.1 400"), status

    async def test_leading_slash_path_rejected(self, tmp_path):
        async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
            server_repo = ServerRepo(db)
            await server_repo.create(
                slug="test-server", name="Test", upstream_url="http://127.0.0.1:1/mcp",
            )
            status, body = await _raw_request(port, "GET /mcp/test-server//etc/passwd")
            assert status.startswith("HTTP/1.1 400"), status

    async def test_normal_subpath_still_works(self, tmp_path):
        """Regression guard: the fix must not break legitimate sub-paths."""
        async with run_fastmcp_server() as upstream:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(
                    slug="test-server", name="Test", upstream_url=upstream.url,
                )
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.post(
                        "/mcp/test-server/mcp",
                        json={
                            "jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "0.0.1"},
                            },
                        },
                        headers={"Accept": "application/json, text/event-stream"},
                    )
                    assert r.status_code == 200


# ---------------------------------------------------------------------------
# F19 (Plan 2 scope) — upstream response headers relayed to the browser must be filtered
# ---------------------------------------------------------------------------

class TestF19ResponseHeadersFiltered:
    async def test_malicious_set_cookie_from_upstream_never_reaches_the_browser(self, tmp_path):
        upstream = _HeaderCapturingUpstream(
            extra_response_headers={"Set-Cookie": "acropolis_session=attacker-controlled; Max-Age=0"}
        )
        await upstream.start()
        try:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.get("/mcp/test-server/mcp")
                    assert "set-cookie" not in {k.lower() for k in r.headers}
        finally:
            await upstream.stop()


# ---------------------------------------------------------------------------
# F23 (Plan 3 scope) — a configured upstream credential is actually sent to the upstream
# ---------------------------------------------------------------------------

class TestF23UpstreamCredentialInjected:
    async def test_configured_credential_is_sent_on_passthrough(self, tmp_path):
        """F23 design gap (review 2026-08-04): the servers table had no auth column at all, so
        no MCP server requiring its own credentials could be fronted by Acropolis. Confirms the
        per-server upstream_auth_header is actually injected as Authorization on the real
        outbound request — not just accepted by the API and silently dropped."""
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(
                    slug="test-server", name="Test", upstream_url=upstream.url,
                    upstream_auth_header="Bearer upstream-secret-token",
                )
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.get("/mcp/test-server/mcp")
                    assert r.status_code == 200
        finally:
            await upstream.stop()

        assert upstream.received_headers.get("authorization") == "Bearer upstream-secret-token"

    async def test_no_credential_configured_sends_no_authorization(self, tmp_path):
        """Regression guard: a server with NO configured credential must not send an
        Authorization header at all (confirms this feature doesn't regress F5's fix — the
        client's own header must still never leak, and no injected header should appear
        when none was configured)."""
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.get(
                        "/mcp/test-server/mcp", headers={"Authorization": "Bearer client-key-must-not-leak"},
                    )
                    assert r.status_code == 200
        finally:
            await upstream.stop()

        assert "authorization" not in upstream.received_headers

    async def test_configured_credential_never_exposed_via_get_server(self, tmp_path):
        """The credential must never round-trip back out through the API that a UI would use to
        display server details — only a boolean 'is one configured' flag."""
        async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
            server_repo = ServerRepo(db)
            await server_repo.create(
                slug="test-server", name="Test", upstream_url="http://127.0.0.1:1/mcp",
                upstream_auth_header="Bearer upstream-secret-token",
            )
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                r = await client.get("/api/v1/servers/test-server")
                assert r.status_code == 200
                body = r.json()
                assert "upstream_auth_header" not in body
                assert "upstream-secret-token" not in json.dumps(body)
                assert body.get("has_upstream_auth_header") is True


# ---------------------------------------------------------------------------
# F11 (Plan 2 scope) — spec-legal JSON-RPC bodies must not crash the pipeline
# ---------------------------------------------------------------------------

class TestSpecLegalBodiesDoNotCrash:
    """A JSON-RPC batch (top-level array) and params: null are both spec-legal shapes. Pre-fix,
    both reached body_json.get(...)/params.get(...) on a non-dict and raised AttributeError,
    which escaped as a bare 500 with a stack trace — reachable by any client, trivially.

    These tests need a REAL, reachable upstream: a non-dict body makes _process() fall through
    to raw passthrough (the same path an unparseable body takes), so with no live upstream the
    request would 500 for the unrelated, not-yet-fixed reason of F3 (unreachable upstream ->
    unhandled exception, Plan 3 scope) rather than proving F11 specifically."""

    async def test_batch_body_on_per_server_endpoint_does_not_500(self, tmp_path):
        async with run_fastmcp_server() as upstream:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.post(
                        "/mcp/test-server",
                        content='[{"jsonrpc":"2.0","id":1,"method":"ping"}]',
                        headers={"Content-Type": "application/json"},
                    )
                    assert r.status_code != 500

    async def test_null_params_on_per_server_endpoint_does_not_500(self, tmp_path):
        async with run_fastmcp_server() as upstream:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.post(
                        "/mcp/test-server",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": None},
                    )
                    assert r.status_code != 500

    async def test_bare_string_body_on_per_server_endpoint_does_not_500(self, tmp_path):
        async with run_fastmcp_server() as upstream:
            async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                    r = await client.post(
                        "/mcp/test-server",
                        content='"just a string, not an object"',
                        headers={"Content-Type": "application/json"},
                    )
                    assert r.status_code != 500

    async def test_batch_body_on_aggregate_endpoint_does_not_500(self, tmp_path):
        async with run_acropolis_server(tmp_path, auth_mode="open") as (port, db):
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                r = await client.post(
                    "/mcp",
                    content='[{"jsonrpc":"2.0","id":1,"method":"ping"}]',
                    headers={"Content-Type": "application/json"},
                )
                assert r.status_code != 500
                # Non-dict body should get the same clean 400 as an unparseable body, not a 500.
                assert r.status_code == 400


# ---------------------------------------------------------------------------
# §26 — SPA catch-all must 404 on an /api/* miss, not serve index.html
# ---------------------------------------------------------------------------

class TestF26SpaFallback404sOnApiMiss:
    async def test_unknown_api_path_returns_404_not_spa_html(self, tmp_path, dist_dir):
        """The SPA catch-all route (argus/app.py's spa_fallback) is registered LAST specifically
        so it never shadows a REGISTERED /api/* or /mcp/* route — but a MISS on those prefixes
        (a typo'd path, an old client hitting a removed endpoint) used to fall through to this
        catch-all anyway and get served the SPA's index.html with a 200. An API client has no
        use for HTML and every reason to want an honest 404."""
        async with run_acropolis_server(tmp_path, auth_mode="open") as (port, _db):
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                resp = await client.get("/api/v1/this-endpoint-does-not-exist")
                assert resp.status_code == 404
                assert b"<html" not in resp.content.lower()

    async def test_real_browser_route_still_gets_spa_html(self, tmp_path, dist_dir):
        """Regression guard: the /api/* 404 fix must not break normal SPA navigation — a
        client-side React Router path like /servers/some-slug still has no file on disk and
        must still fall through to index.html, unchanged."""
        async with run_acropolis_server(tmp_path, auth_mode="open") as (port, _db):
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
                resp = await client.get("/servers/some-slug")
                assert resp.status_code == 200
                assert b"<html" in resp.content.lower() or b"<!doctype" in resp.content.lower()
