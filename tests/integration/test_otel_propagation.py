"""Enterprise #9 (OTel tracing) — wire-level traceparent propagation tests.

CRITICAL, matching test_security_regression.py's own module docstring: these tests drive the
real app over a real TCP socket via a raw-socket-capturing upstream (_HeaderCapturingUpstream,
same pattern as tests/integration/test_security_regression.py), not an httpx mock — the claim
under test is what actually crosses the wire to the upstream, not what a mock recorded.

Two claims:

1. Disabled-by-default regression: with tracing OFF (ACROPOLIS_OTEL_ENABLED unset), no
   traceparent header reaches the upstream at all — even though argus/headers.py's
   strip_hop_by_hop no longer strips a CLIENT-supplied traceparent for tracing-specific reasons,
   inject_headers() returns {} when tracing is inactive, so nothing ever re-adds one.
2. Enabled propagation: with tracing ON and an in-memory span exporter installed, an inbound
   traceparent is honored (the root span parents under it) and the OUTBOUND traceparent sent to
   the upstream is the gateway's OWN span context — same trace id as the inbound header, but a
   DIFFERENT (gateway-generated) span id that parent-chains under the upstream.forward span, not
   a verbatim copy of what the client sent.
"""
from __future__ import annotations

import asyncio
import contextlib
import re
import socket
from pathlib import Path

import pytest
import uvicorn

from archon.settings import Settings
from argus.app import create_app
from argus.tracing import ENABLED_ENV_VAR, TracingManager
from db.database import Database
from db.repo import ServerRepo

pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

# W3C Trace Context: version-trace_id-parent_id-flags. Flags is any 2-hex-digit byte (bit 0 =
# sampled; other bits are reserved and may legitimately be set — e.g. OTel Python's own
# `random-trace-id` flag on newer SDK versions), so this deliberately doesn't pin it to just
# "00"/"01" the way an earlier draft of this test did.
TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _HeaderCapturingUpstream:
    """Raw TCP listener standing in for an MCP upstream — captures the exact request headers
    Acropolis forwards. Same pattern as test_security_regression.py's class of the same name
    (not imported directly — that class is private to its own module, and duplicating this
    ~25-line fixture keeps this file's dependency on that module's internals at zero)."""

    def __init__(self) -> None:
        self.received_headers: dict[str, str] = {}
        self._server: asyncio.AbstractServer | None = None
        self.url = ""

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        content_length = 0
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                self.received_headers[k.lower()] = v
                if k.lower() == "content-length":
                    content_length = int(v.strip())
        if content_length:
            await reader.readexactly(content_length)
        body = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        writer.write(
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
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


async def _raw_post(port: int, path: str, body: bytes, extra_headers: str = "") -> str:
    """Sends a real HTTP/1.1 POST over a raw blocking socket, off the event loop thread (same
    run_in_executor requirement as test_security_regression.py's _raw_request — the loop is also
    driving the uvicorn server under test)."""
    def _sync() -> str:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            req = (
                f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                f"{extra_headers}Connection: close\r\n\r\n"
            ).encode() + body
            s.sendall(req)
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return buf.split(b"\r\n\r\n")[0].split(b"\r\n")[0].decode(errors="replace")

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync)


@contextlib.asynccontextmanager
async def _run_acropolis_server(data_dir: Path, exporter: InMemorySpanExporter | None = None, **settings_kwargs):
    """Same shape as test_security_regression.py's run_acropolis_server, plus: if `exporter` is
    given, swaps an already-init()'d TracingManager (backed by that exporter) onto
    app.state.pipeline/bridge right after create_app — same "construct then replace" seam
    test_otel_span_shape.py uses, needed here because there is no settings-object way to inject
    a custom exporter (see design decision 6: real OTel env vars only, no Acropolis-specific
    endpoint config). ACROPOLIS_OTEL_ENABLED must still be set in the environment by the caller
    for anything downstream of `is_reference`/etc. to matter — but the actual exporter used is
    controlled here, not by OTEL_EXPORTER_OTLP_ENDPOINT."""
    port = _free_port()
    settings = Settings(
        data_dir=str(data_dir), health_poll_enabled=False, audit_retention_enabled=False,
        **settings_kwargs,
    )
    db = Database(data_dir)
    await db.connect()

    app = create_app(settings, db)
    if exporter is not None:
        manager = TracingManager(enabled=True, sample_ratio=1.0)
        manager.init(exporter=exporter)
        app.state.pipeline._tracing = manager
        app.state.bridge._tracing = manager

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
        yield port, db, app
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except asyncio.TimeoutError:
            server.force_exit = True
            await asyncio.wait_for(task, timeout=5.0)
        await db.close()


TOOLS_CALL_BODY = (
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
    b'"params":{"name":"echo","arguments":{"message":"hi"}}}'
)


class TestDisabledMeansNoTraceparentReachesUpstream:
    async def test_no_traceparent_emitted_when_tracing_disabled(self, tmp_path, monkeypatch):
        monkeypatch.delenv(ENABLED_ENV_VAR, raising=False)
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with _run_acropolis_server(tmp_path, auth_mode="open") as (port, db, app):
                assert app.state.tracing.active is False  # sanity: really is disabled
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)

                status = await _raw_post(port, "/mcp/test-server/mcp", TOOLS_CALL_BODY)
                assert status.startswith("HTTP/1.1 200"), status
        finally:
            await upstream.stop()

        assert "traceparent" not in upstream.received_headers

    async def test_client_supplied_traceparent_is_not_forwarded_either_when_disabled(self, tmp_path, monkeypatch):
        """Even a CLIENT that sends its own traceparent must not have it pass straight through
        when tracing is disabled — see argus/headers.py's TRACE_CONTEXT_HEADERS: the client
        header is unconditionally stripped by strip_hop_by_hop, full stop, regardless of the
        tracing gate. This is the single strongest version of the disabled-by-default claim."""
        monkeypatch.delenv(ENABLED_ENV_VAR, raising=False)
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with _run_acropolis_server(tmp_path, auth_mode="open") as (port, db, app):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)

                client_traceparent = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
                status = await _raw_post(
                    port, "/mcp/test-server/mcp", TOOLS_CALL_BODY,
                    extra_headers=f"traceparent: {client_traceparent}\r\n",
                )
                assert status.startswith("HTTP/1.1 200"), status
        finally:
            await upstream.stop()

        assert "traceparent" not in upstream.received_headers


class TestEnabledPropagatesCorrectlyParentChained:
    async def test_outbound_traceparent_matches_trace_id_and_parents_under_forward_span(self, tmp_path):
        exporter = InMemorySpanExporter()
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with _run_acropolis_server(tmp_path, auth_mode="open", exporter=exporter) as (port, db, app):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)

                inbound_trace_id = "a" * 32
                inbound_span_id = "b" * 16
                client_traceparent = f"00-{inbound_trace_id}-{inbound_span_id}-01"
                status = await _raw_post(
                    port, "/mcp/test-server/mcp", TOOLS_CALL_BODY,
                    extra_headers=f"traceparent: {client_traceparent}\r\n",
                )
                assert status.startswith("HTTP/1.1 200"), status
        finally:
            await upstream.stop()

        outbound = upstream.received_headers.get("traceparent")
        assert outbound is not None, "no traceparent reached the upstream at all"
        m = TRACEPARENT_RE.match(outbound)
        assert m is not None, f"outbound traceparent is not well-formed W3C: {outbound!r}"
        outbound_trace_id, outbound_span_id, _flags = m.groups()

        # Trace ID must match the CLIENT's — this is the "continues the same trace" claim.
        assert outbound_trace_id == inbound_trace_id

        # Span ID must NOT be a verbatim copy of the client's own span id — it must be the
        # gateway's own upstream.forward span, freshly generated.
        assert outbound_span_id != inbound_span_id

        # And that span id must be the ACTUAL upstream.forward span's id, from the real
        # in-memory-exported span tree for this call — the strongest possible version of
        # "correctly parent-chained", not just "looks well-formed".
        spans = {s.name: s for s in exporter.get_finished_spans()}
        forward_span = spans["upstream.forward"]
        assert format(forward_span.context.span_id, "016x") == outbound_span_id
        assert format(forward_span.context.trace_id, "032x") == inbound_trace_id

        # And the root `request` span itself must be parented under the CLIENT's inbound
        # traceparent (same trace id, and its parent span id is the client's span id) — proving
        # the root span honored the inbound context rather than starting a disconnected trace.
        root_span = spans["request"]
        assert format(root_span.context.trace_id, "032x") == inbound_trace_id
        assert root_span.parent is not None
        assert format(root_span.parent.span_id, "016x") == inbound_span_id

    async def test_no_inbound_traceparent_still_produces_a_valid_outbound_one(self, tmp_path):
        """When the client sends no traceparent at all, tracing must still work — a fresh trace
        starts at the root span, and the upstream still gets a well-formed traceparent for it."""
        exporter = InMemorySpanExporter()
        upstream = _HeaderCapturingUpstream()
        await upstream.start()
        try:
            async with _run_acropolis_server(tmp_path, auth_mode="open", exporter=exporter) as (port, db, app):
                server_repo = ServerRepo(db)
                await server_repo.create(slug="test-server", name="Test", upstream_url=upstream.url)

                status = await _raw_post(port, "/mcp/test-server/mcp", TOOLS_CALL_BODY)
                assert status.startswith("HTTP/1.1 200"), status
        finally:
            await upstream.stop()

        outbound = upstream.received_headers.get("traceparent")
        assert outbound is not None
        assert TRACEPARENT_RE.match(outbound) is not None
