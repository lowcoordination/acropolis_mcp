"""Issue #134 hardening: a token-mode server must REFUSE a request that carries no token.

The authenticated health probe proves a server accepts a valid Acropolis token. It cannot tell a
server that enforces auth from one that has silently stopped: mcp-authn is fail-open on missing
config (no ``TOKEN_*`` env = pass-through), so a redeploy from a manifest that lost the env turns a
protected server back into an open one while every positive check keeps passing. The poller now
sends a tokenless request to each token-mode server and flags it unhealthy if it is not refused.

The upstream below is a raw TCP listener (the house pattern; nothing mocked) whose behaviour on a
request WITHOUT an Authorization header is configurable: refuse with a status, accept normally, or
drop the connection. Every request is recorded as ``(rpc_method, authorization_or_None)``.
"""
from __future__ import annotations

import asyncio
import json
import socket
import time
from pathlib import Path
from typing import Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import stoa.health
from argus.tokens import TokenIssuer
from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.repo import ServerRepo
from stoa.health import AUTH_NOT_ENFORCED_PREFIX, HealthPoller, check_auth_enforced


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Upstream:
    """A 2025-generation MCP upstream. ``unauth_status``: the HTTP status returned to a request that
    has no Authorization header (``None`` = answer it normally, i.e. NOT enforcing). ``drop_unauth``
    closes the connection without answering such a request instead."""

    def __init__(
        self, unauth_status: Optional[int] = 401, drop_unauth: bool = False, set_cookie: bool = False,
    ) -> None:
        self.unauth_status = unauth_status
        self.drop_unauth = drop_unauth
        self.set_cookie = set_cookie
        self.cookies_seen: list[Optional[str]] = []  # Cookie header of each request, in order
        self.requests: list[tuple[str, Optional[str]]] = []
        self.url = ""
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            headers: dict[str, str] = {}
            for line in head.decode(errors="replace").split("\r\n")[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.lower()] = v
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            rpc = json.loads(body) if body else {}
            method = rpc.get("method", "")
            auth = headers.get("authorization")
            self.requests.append((method, auth))
            self.cookies_seen.append(headers.get("cookie"))

            if auth is None and self.drop_unauth:
                return  # finally: closes the socket with no response
            if auth is None and self.unauth_status is not None:
                status, payload = self.unauth_status, {"error": "unauthorized"}
            elif method == "initialize":
                status, payload = 200, {"jsonrpc": "2.0", "id": rpc.get("id"), "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "serverInfo": {"name": "probe-upstream", "version": "0"},
                }}
            elif method == "server/discover":
                # 2025-generation: not implemented -> the poller falls back to initialize.
                status, payload = 200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                        "error": {"code": -32601, "message": "Method not found"}}
            elif method == "ping":
                status, payload = 200, {"jsonrpc": "2.0", "id": rpc.get("id"), "result": {}}
            else:  # notifications/initialized, anything else
                status, payload = 202, None

            data = json.dumps(payload).encode() if payload is not None else b""
            cookie_line = "Set-Cookie: sid=SESSION-SET-ON-AUTHED-RESPONSE; Path=/\r\n" if (
                self.set_cookie and auth is not None) else ""
            writer.write(
                (f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{cookie_line}"
                 f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data
            )
            await writer.drain()
        finally:
            writer.close()

    async def start(self) -> None:
        port = _free_port()
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def unauthenticated_pings(self) -> list[tuple[str, Optional[str]]]:
        return [r for r in self.requests if r[0] == "ping" and r[1] is None]


class _FakeServer:
    """check_auth_enforced reads only slug and upstream_url; a full ServerRecord adds nothing here."""

    def __init__(self, upstream_url: str) -> None:
        self.slug = "fake"
        self.upstream_url = upstream_url


class _WebhookStub:
    def __init__(self) -> None:
        self.unhealthy: list[str] = []

    async def notify_unhealthy(self, server_slug: str) -> None:
        self.unhealthy.append(server_slug)


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
def issuer() -> TokenIssuer:
    return TokenIssuer(rsa.generate_private_key(public_exponent=65537, key_size=2048))


async def _poll(db, upstream: _Upstream, issuer, *, credential_mode: str, webhooks=None,
                polls: int = 1, **server_kwargs):
    repo = ServerRepo(db)
    await repo.create(
        slug="srv", name="S", upstream_url=upstream.url, credential_mode=credential_mode,
        **server_kwargs,
    )
    async with httpx.AsyncClient() as client:
        poller = HealthPoller(
            repo, client, UpstreamHandshakeCache(client), token_issuer=issuer,
            webhook_dispatcher=webhooks,
        )
        for _ in range(polls):
            await poller.poll_once()
    return await repo.get("srv")


async def test_enforcing_server_reads_healthy_and_was_probed_without_a_token(db, issuer):
    up = _Upstream(unauth_status=401)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()

    assert server.health_status == "healthy" and server.health_reason is None, server
    assert len(up.unauthenticated_pings()) == 1, up.requests  # the negative probe really ran
    assert any(a and a.startswith("Bearer ") for _, a in up.requests), "positive probe lost its token"


async def test_403_also_counts_as_refused(db, issuer):
    up = _Upstream(unauth_status=403)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", server


async def test_server_that_accepts_a_tokenless_request_is_flagged_and_alerts_once(db, issuer):
    """The case the check exists for: mcp-authn inert after a redeploy lost its TOKEN_* env."""
    up = _Upstream(unauth_status=None)  # answers the tokenless ping normally
    hooks = _WebhookStub()
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token", webhooks=hooks, polls=2)
    finally:
        await up.stop()

    assert server.health_status == "unhealthy", server
    assert server.health_reason.startswith(AUTH_NOT_ENFORCED_PREFIX), server.health_reason
    assert "HTTP 200" in server.health_reason
    assert server.upstream_protocol is not None, "the good probe's protocol data must be kept"
    assert hooks.unhealthy == ["srv"], "alert on the edge once, not once per poll"


@pytest.mark.parametrize("status", [200, 400, 404, 500])
async def test_any_response_other_than_401_or_403_means_the_gate_was_bypassed(db, issuer, status):
    """The middleware wraps the whole handler, so a tokenless POST is refused before routing or
    parsing. A 404/400/500 means the request reached the application: still not enforcing."""
    up = _Upstream(unauth_status=status)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "unhealthy", (status, server)
    assert f"HTTP {status}" in server.health_reason


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_gateway_class_statuses_are_inconclusive_not_an_alert(db, issuer, status):
    """502/503/504 come from something in front of the app (ingress mid-rollout, a restarting pod's
    Service), never from the middleware, which answers 401 before the app runs. They say nothing
    about auth and must not raise a security alert."""
    up = _Upstream(unauth_status=status)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", (status, server)
    assert server.health_reason is None
    assert len(up.unauthenticated_pings()) == 1, "the negative probe was attempted"


async def test_network_error_on_the_negative_probe_is_inconclusive_not_an_alert(db, issuer):
    """The authenticated probe just succeeded, so a dropped connection on the second request is a
    transient. It must not raise a security alert."""
    up = _Upstream(drop_unauth=True)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", server
    assert server.health_reason is None
    assert len(up.unauthenticated_pings()) == 1, "the negative probe was attempted"


async def test_unreachable_server_is_unhealthy_without_the_negative_probe(db, issuer):
    repo = ServerRepo(db)
    await repo.create(
        slug="down", name="D", upstream_url="http://127.0.0.1:1/mcp", credential_mode="token",
    )
    async with httpx.AsyncClient() as client:
        await HealthPoller(repo, client, UpstreamHandshakeCache(client), token_issuer=issuer).poll_once()
    server = await repo.get("down")
    assert server.health_status == "unhealthy"
    assert server.health_reason is None, "a plain outage keeps its reason-less shape"


@pytest.mark.parametrize("mode,extra", [
    ("none", {}),
    ("static", {"upstream_auth_header": "Bearer legacy"}),
])
async def test_non_token_modes_never_get_the_negative_probe(db, issuer, monkeypatch, mode, extra):
    """Only token-mode servers are supposed to refuse tokenless requests; a none/static server that
    answers one is behaving as configured."""
    async def _must_not_run(*a, **k):
        raise AssertionError("check_auth_enforced must only run for credential_mode='token'")

    monkeypatch.setattr(stoa.health, "check_auth_enforced", _must_not_run)
    up = _Upstream(unauth_status=None)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode=mode, **extra)
    finally:
        await up.stop()
    assert server.health_status == "healthy", server


async def test_the_negative_probe_carries_no_credential_of_any_kind(db):
    """It is a request that must be refused; it must not be able to authenticate by accident, e.g.
    by picking up a legacy upstream_auth_header on a token-mode row."""
    up = _Upstream(unauth_status=None)
    await up.start()
    try:
        repo = ServerRepo(db)
        await repo.create(
            slug="srv", name="S", upstream_url=up.url, credential_mode="token",
            upstream_auth_header="Bearer legacy-secret",
        )
        server = await repo.get("srv")
        reason = await check_auth_enforced(server)
    finally:
        await up.stop()

    assert reason is not None and reason.startswith(AUTH_NOT_ENFORCED_PREFIX)
    assert up.requests == [("ping", None)], up.requests


async def test_the_negative_probe_does_not_replay_a_cookie_from_an_earlier_response(db, issuer):
    """The poller's shared HTTP client keeps a cookie jar. A session cookie the upstream set on the
    AUTHENTICATED probe must not ride along on the tokenless request, or it is not credential-free
    (found by the PR #150 security scan: it did, before the check used its own client)."""
    up = _Upstream(unauth_status=401, set_cookie=True)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()

    assert server.health_status == "healthy", server
    pairs = list(zip(up.requests, up.cookies_seen))
    tokenless = [cookie for (method, auth), cookie in pairs if auth is None]
    assert tokenless == [None], f"the tokenless probe carried a cookie: {pairs}"
    # premise: the jar really did hold the cookie by then (the authenticated follow-up carried it)
    assert any(c and "SESSION-SET-ON-AUTHED-RESPONSE" in c for c in up.cookies_seen), (
        "premise broken: the shared client never stored the cookie, so this proves nothing"
    )


async def test_a_redirect_is_reported_not_followed():
    """A 3xx is the upstream's answer, not an invitation to fetch another host."""
    hits: list[int] = []

    async def target(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        hits.append(1)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    tport = _free_port()
    tsrv = await asyncio.start_server(target, "127.0.0.1", tport)

    async def redirector(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{tport}/mcp\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        writer.close()

    port = _free_port()
    srv = await asyncio.start_server(redirector, "127.0.0.1", port)
    try:
        reason = await check_auth_enforced(_FakeServer(f"http://127.0.0.1:{port}/mcp"))
    finally:
        srv.close()
        tsrv.close()

    assert reason is not None and "HTTP 302" in reason, reason
    assert hits == [], "the redirect target was contacted"


async def test_the_response_body_is_never_read(monkeypatch):
    """Only the status line matters. An upstream that sends headers promising a huge body and then
    stalls must not hold the check (or memory) hostage: it returns as soon as the status arrives."""
    monkeypatch.setattr(stoa.health, "AUTH_CHECK_DEADLINE_SECONDS", 8.0)  # far above what we assert

    async def staller(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 401 X\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\n")
        await writer.drain()
        try:
            await asyncio.sleep(30)
        finally:
            writer.close()

    port = _free_port()
    srv = await asyncio.start_server(staller, "127.0.0.1", port)
    t0 = time.monotonic()
    try:
        reason = await check_auth_enforced(_FakeServer(f"http://127.0.0.1:{port}/mcp"))
    finally:
        srv.close()
    assert reason is None
    assert time.monotonic() - t0 < 3.0, "the check waited for a body it does not need"


async def test_headers_dripped_slowly_hit_the_overall_deadline(monkeypatch):
    """httpx's timeout is per I/O operation, so a response dripped one byte at a time can outlast it
    indefinitely, and the poll loop is serial. The overall deadline bounds it; the answer is
    inconclusive (no alert)."""
    monkeypatch.setattr(stoa.health, "AUTH_CHECK_DEADLINE_SECONDS", 1.0)

    async def dripper(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        try:
            for ch in b"HTTP/1.1 401 X\r\nX-Pad: " + b"a" * 200:
                writer.write(bytes([ch]))
                await writer.drain()
                await asyncio.sleep(0.4)
        except Exception:
            pass
        finally:
            writer.close()

    port = _free_port()
    srv = await asyncio.start_server(dripper, "127.0.0.1", port)
    t0 = time.monotonic()
    try:
        reason = await check_auth_enforced(_FakeServer(f"http://127.0.0.1:{port}/mcp"))
    finally:
        srv.close()
    assert reason is None, "an overrun must be inconclusive, not an alert"
    assert time.monotonic() - t0 < 3.0, "the overall deadline did not bound the check"
