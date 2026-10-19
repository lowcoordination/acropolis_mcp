"""Issue #152: one hostile, slow or oversized upstream must not stall or exhaust health polling.

httpx's timeout applies to each I/O operation, not to the exchange, and ``client.post`` buffers the
whole body. So before this fix an upstream dripping one byte at a time outlasted any timeout, and
because polling was serial every server after it in slug order stopped getting health updates; and a
64 MiB body was held in memory in full. The upstreams below are raw asyncio listeners (nothing
mocked) whose behaviour per request is a coroutine, so each hostile shape is a few lines.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import socket
import time
import tracemalloc
from pathlib import Path
from typing import Awaitable, Callable, Optional

import httpx
import pytest

import stoa.health
import argus.upstream
from argus.upstream import (
    UpstreamHandshakeCache, UpstreamHandshakeTimeout, UpstreamHandshakeTooLarge,
)
from db.database import Database
from db.repo import ServerRepo
from stoa.health import (
    PROBE_RESPONSE_REJECTED_PREFIX, PROBE_TIMEOUT_PREFIX, HealthPoller,
)

Behaviour = Callable[["_Raw", dict, asyncio.StreamWriter], Awaitable[None]]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Raw:
    """A raw TCP HTTP upstream. ``behaviour(upstream, rpc_request, writer)`` decides the response."""

    def __init__(self, behaviour: Behaviour, tracker: Optional["_Raw"] = None) -> None:
        self.behaviour = behaviour
        self.requests: list[str] = []
        self.in_flight = 0
        self.max_in_flight = 0
        # Servers in one test can share a tracker so concurrency is counted across all of them.
        self.tracker = tracker or self
        self.url = ""
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        t = self.tracker
        t.in_flight += 1
        t.max_in_flight = max(t.max_in_flight, t.in_flight)
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = 0
            for line in head.decode(errors="replace").split("\r\n")[1:]:
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1])
            rpc = json.loads(await reader.readexactly(length))
            self.requests.append(rpc.get("method", ""))
            await self.behaviour(self, rpc, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass  # the client gave up on us, which is exactly what several tests want
        finally:
            t.in_flight -= 1
            writer.close()

    async def start(self) -> "_Raw":
        port = _free_port()
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"
        return self

    async def stop(self) -> None:
        for w in list(self._writers):
            w.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def _send_json(w: asyncio.StreamWriter, status: int, payload: Optional[dict],
                     extra: str = "") -> None:
    data = json.dumps(payload).encode() if payload is not None else b""
    w.write((f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}"
             f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
    await w.drain()


async def healthy(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """A normal 2025-generation upstream: discover is unknown, initialize works."""
    method = rpc.get("method")
    if method == "initialize":
        await _send_json(w, 200, {"jsonrpc": "2.0", "id": rpc["id"], "result": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "serverInfo": {"name": "stub", "version": "0"}}})
    elif method == "server/discover":
        await _send_json(w, 200, {"jsonrpc": "2.0", "id": rpc["id"],
                                  "error": {"code": -32601, "message": "Method not found"}})
    else:
        await _send_json(w, 202, None)


def slow(delay: float) -> Behaviour:
    async def _b(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
        await asyncio.sleep(delay)
        await healthy(up, rpc, w)
    return _b


async def drip(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """Valid status line and headers, then one body byte every 0.3 s for as long as the client
    listens — each byte lands inside any per-operation timeout, so only an OVERALL deadline ends it."""
    w.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
    await w.drain()
    while True:
        w.write(b" ")
        await w.drain()
        await asyncio.sleep(0.3)


async def drip_headers(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """The response HEAD itself arrives one byte at a time."""
    for byte in b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 100_000:
        w.write(bytes([byte]))
        await w.drain()
        await asyncio.sleep(0.3)


async def silent(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """Accepts the request, never answers (no status line at all)."""
    await asyncio.sleep(60)


async def headers_then_nothing(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """Complete headers promising a body, then the connection is simply held open."""
    w.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n")
    await w.drain()
    await asyncio.sleep(60)


_CHUNK = b"x" * 65536


async def huge_content_length(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """Declares 64 MiB and sends it as fast as the socket takes it."""
    total = 64 * 1024 * 1024
    w.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {total}\r\n\r\n".encode())
    for _ in range(total // len(_CHUNK)):
        w.write(_CHUNK)
        await w.drain()


async def declared_huge_sends_little(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    w.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999999999\r\n\r\n{")
    await w.drain()
    await asyncio.sleep(60)


async def endless_chunked(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """No Content-Length, chunked, never terminates."""
    w.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
    chunk = f"{len(_CHUNK):x}\r\n".encode() + _CHUNK + b"\r\n"
    while True:
        w.write(chunk)
        await w.drain()


async def endless_sse(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """A text/event-stream that keeps emitting comment/keepalive frames and never finishes."""
    w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
    frame = b": keepalive " + b"k" * 4000 + b"\n\n"
    chunk = f"{len(frame):x}\r\n".encode() + frame + b"\r\n"
    while True:
        w.write(chunk)
        await w.drain()


async def nested_json(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """Under the byte cap, but deep enough to overflow the JSON parser's recursion limit."""
    body = b"[" * 900_000
    w.write((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
    await w.drain()


async def gzip_bomb(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
    """~64 KiB on the wire, ~64 MiB once inflated. A decoder would expand it before we could count."""
    body = gzip.compress(b"\x00" * (64 * 1024 * 1024), compresslevel=9)
    w.write((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
             f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
    await w.drain()


class _Landing:
    """Records whether anything ever reached it (the target of a redirect)."""

    def __init__(self) -> None:
        self.hits = 0

    async def behaviour(self, up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
        self.hits += 1
        await healthy(up, rpc, w)


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture(autouse=True)
def short_budgets(monkeypatch):
    """Shrink the production budgets so hostile cases resolve in a couple of seconds."""
    monkeypatch.setattr(stoa.health, "PROBE_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(stoa.health, "PROBE_DEADLINE_SECONDS", 2.5)


class _Webhooks:
    def __init__(self) -> None:
        self.unhealthy: list[str] = []

    async def notify_unhealthy(self, slug: str) -> None:
        self.unhealthy.append(slug)


async def _poll(db, ups: dict[str, _Raw], *, polls: int = 1, webhooks=None, limit: float = 20.0):
    """Register one server per (slug, upstream), run ``polls`` poll cycles under a hard test-level
    limit, and return ({slug: record}, elapsed_seconds). The client follows redirects on purpose
    (production's does not): the probe must refuse to follow one regardless of the client's setting."""
    repo = ServerRepo(db)
    for slug, up in ups.items():
        await repo.create(slug=slug, name=slug, upstream_url=up.url)
    started = time.monotonic()
    async with httpx.AsyncClient(follow_redirects=True) as client:
        poller = HealthPoller(repo, client, UpstreamHandshakeCache(client), webhook_dispatcher=webhooks)
        for _ in range(polls):
            await asyncio.wait_for(poller.poll_once(), timeout=limit)
    elapsed = time.monotonic() - started
    return {slug: await repo.get(slug) for slug in ups}, elapsed


async def _with(*ups: _Raw):
    for u in ups:
        await u.start()


async def _stop(*ups: _Raw):
    for u in ups:
        await u.stop()


# ---- the acceptance cases from the issue -------------------------------------------------------


async def test_dripping_upstream_cannot_stall_the_cycle_or_starve_later_servers(db):
    """The headline case. The dripper sorts FIRST, so under serial polling every other server
    waits behind it for as long as it keeps dripping."""
    dripper, ok_b, ok_c = _Raw(drip), _Raw(healthy), _Raw(healthy)
    await _with(dripper, ok_b, ok_c)
    try:
        servers, elapsed = await _poll(db, {"a-drip": dripper, "b-ok": ok_b, "c-ok": ok_c}, limit=10)
    finally:
        await _stop(dripper, ok_b, ok_c)

    assert servers["a-drip"].health_status == "unhealthy", servers["a-drip"]
    assert servers["a-drip"].health_reason.startswith(PROBE_TIMEOUT_PREFIX), servers["a-drip"].health_reason
    for slug in ("b-ok", "c-ok"):
        assert servers[slug].health_status == "healthy", servers[slug]
        assert servers[slug].last_seen_at is not None, "a server behind the dripper got no fresh update"
    assert elapsed < 2.5 + 1.5, f"cycle took {elapsed:.1f}s, longer than one probe deadline"


async def test_oversized_body_is_rejected_with_bounded_memory(db):
    big = _Raw(huge_content_length)
    await _with(big)
    tracemalloc.start()
    try:
        servers, _ = await _poll(db, {"big": big})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        await _stop(big)

    assert servers["big"].health_status == "unhealthy"
    assert servers["big"].health_reason.startswith(PROBE_RESPONSE_REJECTED_PREFIX), servers["big"].health_reason
    # A 64 MiB body fully buffered peaks far above this; the cap is 1 MiB.
    assert peak < 16 * 1024 * 1024, f"peak traced allocation {peak / 1e6:.1f} MB for a 64 MiB body"


async def test_slow_servers_are_probed_concurrently_not_serially(db):
    n, delay = 6, 0.5  # discover + initialize + notification = 3 requests of `delay` each
    tracker = _Raw(healthy)
    ups = {f"s{i}": _Raw(slow(delay), tracker=tracker) for i in range(n)}
    await _with(*ups.values())
    try:
        servers, elapsed = await _poll(db, ups, limit=30)
    finally:
        await _stop(*ups.values())

    assert all(s.health_status == "healthy" for s in servers.values()), servers
    serial_floor = n * 3 * delay
    assert elapsed < serial_floor / 2, f"{n} slow servers took {elapsed:.1f}s; serial is >= {serial_floor}s"
    assert tracker.max_in_flight > 1, "probes never overlapped"


async def test_concurrency_is_bounded_by_the_semaphore(db, monkeypatch):
    monkeypatch.setattr(stoa.health, "MAX_CONCURRENT_PROBES", 2)
    tracker = _Raw(healthy)
    ups = {f"s{i}": _Raw(slow(0.3), tracker=tracker) for i in range(6)}
    await _with(*ups.values())
    try:
        servers, _ = await _poll(db, ups, limit=30)
    finally:
        await _stop(*ups.values())
    assert all(s.health_status == "healthy" for s in servers.values()), servers
    assert tracker.max_in_flight == 2, f"observed {tracker.max_in_flight} simultaneous probes, limit is 2"


# ---- hostile shapes -----------------------------------------------------------------------------


@pytest.mark.parametrize("behaviour,prefix", [
    (drip_headers, PROBE_TIMEOUT_PREFIX),             # slow headers
    (silent, PROBE_TIMEOUT_PREFIX),                   # accepted, never answered
    (headers_then_nothing, PROBE_TIMEOUT_PREFIX),     # connection held open after headers
    (declared_huge_sends_little, PROBE_RESPONSE_REJECTED_PREFIX),  # huge Content-Length, refused up front
    (endless_chunked, PROBE_RESPONSE_REJECTED_PREFIX),  # chunked, never ends
    (endless_sse, PROBE_RESPONSE_REJECTED_PREFIX),      # event-stream that never finishes
    (gzip_bomb, PROBE_RESPONSE_REJECTED_PREFIX),        # compressed body that inflates 1000:1
], ids=lambda v: getattr(v, "__name__", v))
async def test_hostile_response_shapes_are_unhealthy_with_a_reason_and_do_not_block_others(
    db, behaviour, prefix,
):
    bad, good = _Raw(behaviour), _Raw(healthy)
    await _with(bad, good)
    try:
        servers, elapsed = await _poll(db, {"a-bad": bad, "b-good": good}, limit=15)
    finally:
        await _stop(bad, good)

    assert servers["a-bad"].health_status == "unhealthy", servers["a-bad"]
    assert servers["a-bad"].health_reason.startswith(prefix), servers["a-bad"].health_reason
    assert servers["b-good"].health_status == "healthy"
    assert elapsed < 6, f"cycle took {elapsed:.1f}s"


async def test_deeply_nested_json_reads_unhealthy_instead_of_freezing_the_row(db):
    """RecursionError is not a ValueError. Uncaught, it escaped probe_server and the server's health
    row was simply never written: a stale 'healthy' that no webhook would ever correct."""
    bad = _Raw(nested_json)
    await bad.start()
    hooks = _Webhooks()
    try:
        repo = ServerRepo(db)
        await repo.create(slug="nest", name="n", upstream_url=bad.url)
        await repo.set_health("nest", health_status="healthy")
        async with httpx.AsyncClient() as client:
            poller = HealthPoller(repo, client, UpstreamHandshakeCache(client), webhook_dispatcher=hooks)
            await asyncio.wait_for(poller.poll_once(), timeout=15)
        server = await repo.get("nest")
    finally:
        await _stop(bad)
    assert server.health_status == "unhealthy", server
    assert hooks.unhealthy == ["nest"]


async def test_reasons_do_not_echo_upstream_header_text(db):
    async def long_encoding(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
        w.write(b"HTTP/1.1 200 OK\r\nContent-Encoding: " + b"Z" * 5000 + b"\r\nContent-Length: 0\r\n\r\n")
        await w.drain()

    bad = _Raw(long_encoding)
    await bad.start()
    try:
        servers, _ = await _poll(db, {"enc": bad})
    finally:
        await _stop(bad)
    assert servers["enc"].health_reason.startswith(PROBE_RESPONSE_REJECTED_PREFIX)
    assert len(servers["enc"].health_reason) < 120, len(servers["enc"].health_reason)


async def test_redirect_is_not_followed(db):
    landing = _Landing()
    target = _Raw(landing.behaviour)
    await target.start()

    async def redirect(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
        w.write(f"HTTP/1.1 307 Temporary Redirect\r\nLocation: {target.url}\r\nContent-Length: 0\r\n\r\n".encode())
        await w.drain()

    red = _Raw(redirect)
    await red.start()
    try:
        servers, _ = await _poll(db, {"red": red})
    finally:
        await _stop(red, target)
    assert servers["red"].health_status == "unhealthy"
    assert landing.hits == 0, "the probe chased a redirect to another host"


async def test_oversized_initialize_response_on_the_fallback_path_is_rejected(db):
    """server/discover answers 'method not found' (small, fine); the initialize fallback is the
    one that is hostile — the handshake path needs the same bounds, not only the first request."""
    async def hostile_initialize(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
        if rpc.get("method") == "initialize":
            await endless_chunked(up, rpc, w)
        else:
            await healthy(up, rpc, w)

    bad = _Raw(hostile_initialize)
    await bad.start()
    try:
        servers, elapsed = await _poll(db, {"bad": bad}, limit=15)
    finally:
        await _stop(bad)
    assert servers["bad"].health_status == "unhealthy"
    assert servers["bad"].health_reason.startswith(PROBE_RESPONSE_REJECTED_PREFIX), servers["bad"].health_reason
    assert elapsed < 4


async def test_probe_whose_secret_resolution_hangs_hits_the_overall_deadline(db):
    """Not every stall is on the upstream's socket: the overall per-server deadline also covers the
    secret provider call that precedes the request."""
    from archon.secrets import SecretProvider

    class Hanging(SecretProvider):
        async def resolve(self, value: str) -> str:
            await asyncio.sleep(60)
            return value

    repo = ServerRepo(db)
    ok = _Raw(healthy)
    await ok.start()
    await repo.create(slug="a-hang", name="h", upstream_url=ok.url, upstream_auth_header="Bearer x")
    await repo.create(slug="b-ok", name="o", upstream_url=ok.url)
    try:
        started = time.monotonic()
        async with httpx.AsyncClient() as client:
            poller = HealthPoller(repo, client, UpstreamHandshakeCache(client), secret_provider=Hanging())
            await asyncio.wait_for(poller.poll_once(), timeout=10)
        elapsed = time.monotonic() - started
    finally:
        await _stop(ok)
    hung = await repo.get("a-hang")
    assert hung.health_status == "unhealthy" and hung.health_reason.startswith(PROBE_TIMEOUT_PREFIX), hung
    assert (await repo.get("b-ok")).health_status == "healthy"
    assert elapsed < 2.5 + 1.5


# ---- behaviour that must be preserved ------------------------------------------------------------


async def test_unhealthy_webhook_fires_once_on_the_edge_for_a_timed_out_server(db):
    dripper = _Raw(drip)
    await dripper.start()
    hooks = _Webhooks()
    try:
        servers, _ = await _poll(db, {"drip": dripper}, polls=2, webhooks=hooks)
    finally:
        await _stop(dripper)
    assert servers["drip"].health_status == "unhealthy"
    assert hooks.unhealthy == ["drip"], "alert on the healthy->unhealthy edge once, not once per poll"


async def test_exception_in_one_probe_does_not_abort_the_others(db, monkeypatch):
    real = stoa.health.probe_server

    async def flaky(client, cache, server, **kw):
        if server.slug == "a-boom":
            raise RuntimeError("probe blew up")
        return await real(client, cache, server, **kw)

    monkeypatch.setattr(stoa.health, "probe_server", flaky)
    boom, ok = _Raw(healthy), _Raw(healthy)
    await _with(boom, ok)
    try:
        servers, _ = await _poll(db, {"a-boom": boom, "b-ok": ok})
    finally:
        await _stop(boom, ok)
    assert servers["a-boom"].health_status == "unknown"
    assert servers["b-ok"].health_status == "healthy"


# ---- the handshake on its own (data-plane entry point included) ---------------------------------


async def test_handshake_without_a_deadline_still_caps_the_body():
    """The data plane calls get_or_handshake with no timeout (its own budgets are unchanged), but a
    megabyte-plus initialize reply is never legitimate and must not be buffered."""
    big = _Raw(huge_content_length)
    await big.start()
    try:
        async with httpx.AsyncClient() as client:
            with pytest.raises(UpstreamHandshakeTooLarge):
                await asyncio.wait_for(
                    UpstreamHandshakeCache(client).get_or_handshake(1, big.url), timeout=10)
    finally:
        await _stop(big)


async def test_handshake_with_a_deadline_gives_up_on_a_dripping_upstream():
    dripper = _Raw(drip)
    await dripper.start()
    try:
        async with httpx.AsyncClient() as client:
            with pytest.raises(UpstreamHandshakeTimeout):
                await asyncio.wait_for(
                    UpstreamHandshakeCache(client).get_or_handshake(1, dripper.url, timeout=1.0),
                    timeout=10)
    finally:
        await _stop(dripper)


async def test_a_stalled_initialized_notification_cannot_hold_the_handshake_open(monkeypatch):
    """notifications/initialized is fire-and-forget and runs under the per-server handshake lock.
    The client's own timeouts here are generous (as in production), so only the notification's
    own deadline can end the wait."""
    monkeypatch.setattr(argus.upstream, "INITIALIZED_NOTIFICATION_DEADLINE_SECONDS", 0.5)

    async def stall_on_notification(up: _Raw, rpc: dict, w: asyncio.StreamWriter) -> None:
        if rpc.get("method") == "notifications/initialized":
            await drip(up, rpc, w)
        else:
            await healthy(up, rpc, w)

    up = _Raw(stall_on_notification)
    await up.start()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            started = time.monotonic()
            result = await asyncio.wait_for(
                UpstreamHandshakeCache(client).get_or_handshake(1, up.url), timeout=8)
            elapsed = time.monotonic() - started
    finally:
        await _stop(up)
    assert result.protocol_version == "2025-06-18"
    assert elapsed < 4
