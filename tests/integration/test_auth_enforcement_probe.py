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
import base64
import json
import logging
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
from stoa.health import (
    AUDIENCE_NOT_ENFORCED_PREFIX,
    AUTH_NOT_ENFORCED_PREFIX,
    HealthPoller,
    check_auth_enforced,
)

from .fixture_token_verifier import verify_request_token


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


DROP = -1  # wrong_audience_status: close the connection without answering


class _Upstream:
    """A 2025-generation MCP upstream. ``unauth_status``: the HTTP status returned to a request that
    has no Authorization header (``None`` = answer it normally, i.e. NOT enforcing). ``drop_unauth``
    closes the connection without answering such a request instead.

    A request that DOES carry an Authorization header is checked with the in-repo fixture verifier
    (the Python mirror of the Go middleware) once ``trust()`` has been called, so the upstream
    behaves like a token-mode server: ``audience_check`` is how it treats the token's audience —
    ``"enforce"`` (a correct server: a token for any other audience is a 401), ``"skip"`` (verifies
    the signature, never looks at ``aud``) or ``"accept_any"`` (does not verify at all). Before
    ``trust()`` any authenticated request is accepted, as the original stub did."""

    def __init__(
        self, unauth_status: Optional[int] = 401, drop_unauth: bool = False, set_cookie: bool = False,
        audience_check: str = "enforce", wrong_audience_status: int = 401,
    ) -> None:
        self.unauth_status = unauth_status
        self.drop_unauth = drop_unauth
        self.set_cookie = set_cookie
        self.audience_check = audience_check
        self.wrong_audience_status = wrong_audience_status
        self._public_key = None
        self._audience = ""
        self.authed_tokens: list[str] = []  # every bearer token that arrived, in order
        self.cookies_seen: list[Optional[str]] = []  # Cookie header of each request, in order
        self.requests: list[tuple[str, Optional[str]]] = []
        self.url = ""
        self._server: asyncio.AbstractServer | None = None

    def trust(self, issuer: TokenIssuer, audience: str) -> None:
        """Verify authenticated requests against ``issuer``'s key, expecting ``audience``."""
        self._public_key = issuer._public_key
        self._audience = audience

    def _token_status(self, auth: str) -> Optional[int]:
        """An HTTP error status if the fixture verifier rejects this bearer token, else None."""
        if self._public_key is None or self.audience_check == "accept_any":
            return None
        token = auth.removeprefix("Bearer ")
        audience = self._audience
        if self.audience_check == "skip":
            # A verifier that checks the signature but not the audience: expect whatever it says.
            segment = token.split(".")[1]
            audience = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))["aud"]
        try:
            verify_request_token(
                token, audience=audience, issuer="acropolis", public_key=self._public_key,
            )
        except AssertionError:
            return self.wrong_audience_status
        return None

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
            if auth is not None:
                self.authed_tokens.append(auth.removeprefix("Bearer "))

            if auth is None and self.drop_unauth:
                return  # finally: closes the socket with no response
            if auth is None and self.unauth_status is not None:
                status, payload = self.unauth_status, {"error": "unauthorized"}
            elif auth is not None and (rejected := self._token_status(auth)) is not None:
                if rejected == DROP:
                    return
                status, payload = rejected, {"error": "bad token"}
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

    def authenticated_pings(self) -> list[str]:
        """Bearer tokens that arrived on a ``ping`` — only the wrong-audience probe sends one."""
        return [a.removeprefix("Bearer ") for m, a in self.requests if m == "ping" and a is not None]


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
    if credential_mode == "token":
        upstream.trust(issuer, "srv")
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


# --- Issue #156: a token-mode server must also refuse a genuine token for the WRONG audience ---------


def _claims(token: str) -> dict:
    segment = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


async def test_a_correct_server_is_healthy_and_gets_exactly_one_wrong_audience_request(db, issuer):
    up = _Upstream(unauth_status=401, audience_check="enforce")
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()

    assert server.health_status == "healthy" and server.health_reason is None, server
    probes = up.authenticated_pings()
    assert len(probes) == 1, "the extra cost is one request per token-mode server per poll"
    # Genuinely issued by this Acropolis (it verifies against the issuer's key, for its OWN audience)…
    claims = verify_request_token(
        probes[0], audience=_claims(probes[0])["aud"], issuer="acropolis", public_key=issuer._public_key,
    )
    # …and for an audience that is not this server's.
    assert claims["aud"] != "srv"


async def test_the_probe_token_never_enters_the_per_slug_cache(db, issuer):
    up = _Upstream(unauth_status=401)
    await up.start()
    try:
        await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert set(issuer._cache) == {"srv"}, "the probe audience was cached"
    assert _claims(await issuer.get_token("srv"))["aud"] == "srv"


async def test_a_server_that_skips_the_audience_check_is_flagged_and_alerts_once(db, issuer):
    """The case this probe exists for: it refuses a missing token and verifies the signature, so the
    tokenless check passes, but it never looks at ``aud`` — so a token meant for any other server
    works on this one."""
    up = _Upstream(unauth_status=401, audience_check="skip")
    hooks = _WebhookStub()
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token", webhooks=hooks, polls=2)
    finally:
        await up.stop()

    assert server.health_status == "unhealthy", server
    assert server.health_reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX), server.health_reason
    assert "HTTP 200" in server.health_reason
    assert server.upstream_protocol is not None, "the good probe's protocol data must be kept"
    assert hooks.unhealthy == ["srv"], "alert on the edge once, not once per poll"


async def test_a_server_that_verifies_nothing_is_flagged_for_the_audience(db, issuer):
    """Refuses a tokenless request but accepts any bearer string."""
    up = _Upstream(unauth_status=401, audience_check="accept_any")
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "unhealthy"
    assert server.health_reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX), server.health_reason


@pytest.mark.parametrize("status", [401, 403])
async def test_403_counts_as_a_refusal_of_the_wrong_audience_too(db, issuer, status):
    up = _Upstream(wrong_audience_status=status)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", server


@pytest.mark.parametrize("status", [400, 404, 429, 500])
async def test_any_error_but_401_or_403_to_the_wrong_audience_is_flagged(db, issuer, status):
    """Same rule as the tokenless request: the gate answers 401 before anything else can run, so any
    other status means the token got past it. (A 200 is covered by the skip/accept-any tests.)"""
    up = _Upstream(wrong_audience_status=status)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
        probes = up.authenticated_pings()
    finally:
        await up.stop()
    assert server.health_status == "unhealthy", (status, server)
    assert server.health_reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX)
    assert f"HTTP {status}" in server.health_reason
    assert len(probes) == 1


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_gateway_class_statuses_on_the_audience_probe_are_inconclusive(db, issuer, status):
    up = _Upstream(wrong_audience_status=status)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", (status, server)
    assert server.health_reason is None
    assert len(up.authenticated_pings()) == 1, "the probe was attempted"


async def test_a_dropped_connection_on_the_audience_probe_is_inconclusive(db, issuer):
    up = _Upstream(wrong_audience_status=DROP)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", server
    assert server.health_reason is None
    assert len(up.authenticated_pings()) == 1, "the probe was attempted"


async def test_no_audience_probe_when_the_tokenless_check_failed(db, issuer):
    """Already unhealthy for a worse reason; a second request adds nothing."""
    up = _Upstream(unauth_status=None, audience_check="accept_any")
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_reason.startswith(AUTH_NOT_ENFORCED_PREFIX), server.health_reason
    assert up.authenticated_pings() == []


async def test_no_audience_probe_when_the_tokenless_check_was_inconclusive(db, issuer):
    """A dropped tokenless request is a transient; piling a second request onto a flaky server buys
    nothing, and the next poll tries again."""
    up = _Upstream(drop_unauth=True, audience_check="accept_any")
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", server
    assert up.authenticated_pings() == []


async def test_without_an_issuer_only_the_tokenless_request_is_sent(db):
    up = _Upstream(unauth_status=401)
    await up.start()
    try:
        repo = ServerRepo(db)
        await repo.create(slug="srv", name="S", upstream_url=up.url, credential_mode="token")
        assert await check_auth_enforced(await repo.get("srv")) is None
    finally:
        await up.stop()
    assert up.requests == [("ping", None)], up.requests


async def test_the_probe_token_is_not_logged_stored_or_put_in_the_reason(db, issuer, caplog):
    caplog.set_level(logging.DEBUG)
    up = _Upstream(unauth_status=401, audience_check="skip")
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    (probe,) = up.authenticated_pings()
    assert server.health_reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX)
    assert probe not in server.health_reason
    assert probe not in caplog.text and probe.split(".")[1] not in caplog.text
    assert probe not in server.model_dump_json()


async def test_a_redirect_on_the_audience_probe_is_reported_and_the_token_goes_nowhere_else():
    """A 3xx is the upstream's answer. Following it would hand the probe token to another host."""
    hits: list[dict] = []

    async def target(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        hits.append(head)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    tport = _free_port()
    tsrv = await asyncio.start_server(target, "127.0.0.1", tport)

    async def redirector(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        if b"authorization" in head.lower():
            writer.write(
                f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{tport}/mcp\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n".encode()
            )
        else:
            writer.write(b"HTTP/1.1 401 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    port = _free_port()
    srv = await asyncio.start_server(redirector, "127.0.0.1", port)
    issuer = TokenIssuer(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    try:
        reason = await check_auth_enforced(_FakeServer(f"http://127.0.0.1:{port}/mcp"), issuer)
    finally:
        srv.close()
        tsrv.close()

    assert reason is not None and reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX) and "HTTP 302" in reason
    assert hits == [], "the redirect target was contacted"


async def test_the_audience_probe_does_not_replay_a_cookie(db, issuer):
    """Same hardening as the tokenless request: a fresh client, so the poller's cookie jar (which
    holds whatever the authenticated probe made the upstream set) cannot ride along."""
    up = _Upstream(set_cookie=True)
    await up.start()
    try:
        server = await _poll(db, up, issuer, credential_mode="token")
    finally:
        await up.stop()
    assert server.health_status == "healthy", server
    probe_cookies = [c for (m, a), c in zip(up.requests, up.cookies_seen) if m == "ping" and a is not None]
    assert probe_cookies == [None], probe_cookies
    assert any(c and "SESSION-SET-ON-AUTHED-RESPONSE" in c for c in up.cookies_seen), "premise broken"


async def _raw_server(handler):
    port = _free_port()
    return await asyncio.start_server(handler, "127.0.0.1", port), port


def _tokenless_refusing(after_head):
    """A raw upstream that 401s a tokenless request and hands an authenticated one to ``after_head``."""
    async def handler(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        try:
            if b"authorization" not in head.lower():
                writer.write(b"HTTP/1.1 401 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            else:
                await after_head(writer)
        except Exception:
            pass
        finally:
            writer.close()
    return handler


async def test_the_audience_probe_never_reads_the_response_body(monkeypatch):
    monkeypatch.setattr(stoa.health, "AUTH_CHECK_DEADLINE_SECONDS", 8.0)  # far above what we assert

    async def promise_a_huge_body(writer):
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(30)

    srv, port = await _raw_server(_tokenless_refusing(promise_a_huge_body))
    issuer = TokenIssuer(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    t0 = time.monotonic()
    try:
        reason = await check_auth_enforced(_FakeServer(f"http://127.0.0.1:{port}/mcp"), issuer)
    finally:
        srv.close()
    assert reason is not None and reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX) and "HTTP 200" in reason
    assert time.monotonic() - t0 < 3.0, "the probe waited for a body it does not need"


async def test_a_dripped_audience_answer_hits_the_overall_deadline(monkeypatch):
    monkeypatch.setattr(stoa.health, "AUTH_CHECK_DEADLINE_SECONDS", 1.0)

    async def drip(writer):
        for ch in b"HTTP/1.1 200 X\r\nX-Pad: " + b"a" * 200:
            writer.write(bytes([ch]))
            await writer.drain()
            await asyncio.sleep(0.4)

    srv, port = await _raw_server(_tokenless_refusing(drip))
    issuer = TokenIssuer(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    t0 = time.monotonic()
    try:
        reason = await check_auth_enforced(_FakeServer(f"http://127.0.0.1:{port}/mcp"), issuer)
    finally:
        srv.close()
    assert reason is None, "an overrun must be inconclusive, not an alert"
    assert time.monotonic() - t0 < 3.0, "the overall deadline did not bound the probe"


async def test_a_flapping_server_is_flagged_while_wrong_and_clears_when_it_refuses(db, issuer):
    """A server that accepts the wrong-audience token once and refuses it the next time reads
    unhealthy, then healthy: the reason is rewritten each poll, not latched."""
    up = _Upstream(unauth_status=401, audience_check="skip")
    await up.start()
    try:
        repo = ServerRepo(db)
        await repo.create(slug="srv", name="S", upstream_url=up.url, credential_mode="token")
        up.trust(issuer, "srv")
        async with httpx.AsyncClient() as client:
            poller = HealthPoller(repo, client, UpstreamHandshakeCache(client), token_issuer=issuer)
            await poller.poll_once()
            first = await repo.get("srv")
            up.audience_check = "enforce"
            await poller.poll_once()
            second = await repo.get("srv")
    finally:
        await up.stop()
    assert first.health_status == "unhealthy" and first.health_reason.startswith(AUDIENCE_NOT_ENFORCED_PREFIX)
    assert second.health_status == "healthy" and second.health_reason is None


async def test_the_enforcement_requests_ignore_proxy_environment_variables(monkeypatch, issuer):
    """``trust_env=False``: a proxy configured in the poller's environment must not see the probe
    token (nor can ``.netrc`` credentials ride along). Both requests go straight to the server."""
    proxied: list[bytes] = []

    async def proxy(reader, writer):
        proxied.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 401 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    psrv, pport = await _raw_server(proxy)
    for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{pport}")
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    up = _Upstream(unauth_status=401)
    await up.start()
    up.trust(issuer, "srv")
    try:
        reason = await check_auth_enforced(_FakeServer(up.url), issuer)
    finally:
        await up.stop()
        psrv.close()
    assert reason is None
    assert proxied == [], "a request went through the environment's proxy"
    assert len(up.unauthenticated_pings()) == 1 and len(up.authenticated_pings()) == 1
