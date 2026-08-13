"""Benchmark harness for enterprise #9 (OpenTelemetry tracing) — measures added latency per
tools/call request from span creation/export, tracing on vs. off, at the SAME representative
argument sizes tests/bench/bench_dlp.py used (small/medium/large), per the plan's explicit
instruction to reuse that harness's shape rather than inventing a new one.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_otel

The numbers this script prints are what docs/observability.md's "Overhead" section reports.
Re-run and update that doc if argus/tracing.py's span points or export mechanism change
materially.

Requires the `otel` extra (`pip install -e '.[otel]'`) — OTel is deliberately optional in the
base install (see pyproject.toml's otel group comment); this bench measures a code path that
does not exist without it.

Shares the stats/timing/argument machinery with the other benches via tests/bench/_harness.py
(the epic's harness issue). One migration note: this bench previously built its app on the
legacy SQLite Database(tmp_path) shape, which ceased to exist when the app went Postgres-only
(enterprise #7) — it now provisions a real Postgres database via the harness, which is also
what production runs.

Scope note: this measures a FULL bridged tools/call request through the real Acropolis app (root
span + policy.evaluate + bridge.handshake + upstream.forward — the shape a real 2026-generation
client's call takes), against a real in-process FastMCP upstream, over httpx.ASGITransport (no
real network hop, so the number isolates tracing overhead rather than network jitter). The
"tracing on" runs use an InMemorySpanExporter (SimpleSpanProcessor, synchronous export) — this is
the WORST-CASE export cost a real deployment would see; a real OTLP exporter's BatchSpanProcessor
(what app.py actually wires in production) exports off the request's critical path entirely, so
a production deployment's added latency should be lower than what's measured here, not higher.
This conservative choice is deliberate and documented in docs/observability.md.
"""
from __future__ import annotations

import asyncio
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.bench._harness import (  # noqa: E402
    iters, percentile, postgres_url, print_latency_table, quiet_logging,
    representative_arguments, stop_infra, time_call,
)

# Quiet every logger below WARNING — this benchmark drives thousands of real requests through
# the app (audit logging, httpx request logging, FastMCP's own request logging all fire per
# call), and the resulting console noise makes the actual results hard to find. Must run
# before httpx/mcp import so their loggers start already-quiet.
quiet_logging()

import httpx  # noqa: E402

from archon.settings import Settings  # noqa: E402
from argus.app import create_app  # noqa: E402
from argus.tracing import TracingManager, _DisabledTracingManager  # noqa: E402
from db.database import Database  # noqa: E402
from db.repo import ServerRepo  # noqa: E402
from tests.integration.fastmcp_fixture import run_fastmcp_server  # noqa: E402

ITERATIONS = iters(500, 5)
WARMUP_ITERATIONS = iters(50, 2)


async def _make_app(tmp_path: Path, dsn: str, upstream_url: str, tracing_active: bool):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(dsn)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="bench-server", name="Bench", upstream_url=f"{upstream_url}/mcp")

    app = create_app(settings, db)
    if tracing_active:
        # Worst-case, not best-case: SimpleSpanProcessor exports synchronously, on the request's
        # own critical path — see this module's docstring for why that's the conservative choice
        # for an overhead number, versus the BatchSpanProcessor app.py actually wires for a real
        # OTLP collector in production.
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        manager = TracingManager(enabled=True, sample_ratio=1.0)
        manager.init(exporter=InMemorySpanExporter())
        app.state.pipeline._tracing = manager
        app.state.bridge._tracing = manager
    else:
        app.state.pipeline._tracing = _DisabledTracingManager()
        app.state.bridge._tracing = _DisabledTracingManager()

    return app, db


async def _time_calls(app, arguments: dict, iterations: int) -> list[float]:
    transport = httpx.ASGITransport(app=app)
    headers = {
        "Content-Type": "application/json", "Accept": "application/json",
        "Mcp-Method": "tools/call", "Mcp-Name": "echo",
    }
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "echo", "arguments": arguments},
    }

    # One client for the whole loop (keep-alive reuse), exactly as the pre-migration bench did —
    # only the timing loop moved to the harness.
    async with httpx.AsyncClient(transport=transport, base_url="http://bench.test") as client:

        async def _one() -> None:
            resp = await client.post("/mcp/bench-server", json=body, headers=headers)
            assert resp.status_code == 200, resp.text

        return await time_call(_one, iterations)


async def _bench_one(tmp_path_root: Path, upstream_url: str, size_label: str) -> dict:
    arguments = representative_arguments(size_label)
    arg_bytes = sum(len(str(v)) for v in arguments.values())

    off_dir = tmp_path_root / f"off-{size_label}"
    on_dir = tmp_path_root / f"on-{size_label}"
    off_dir.mkdir(parents=True, exist_ok=True)
    on_dir.mkdir(parents=True, exist_ok=True)

    # One fresh database per app, mirroring conftest's per-instance isolation: both apps
    # register the same "bench-server" slug, and only a per-app database keeps the second
    # create from colliding with the first.
    off_app, off_db = await _make_app(off_dir, await postgres_url(), upstream_url, tracing_active=False)
    async with off_app.router.lifespan_context(off_app):
        await _time_calls(off_app, arguments, WARMUP_ITERATIONS)
        off_samples = await _time_calls(off_app, arguments, ITERATIONS)
    await off_db.close()

    on_app, on_db = await _make_app(on_dir, await postgres_url(), upstream_url, tracing_active=True)
    async with on_app.router.lifespan_context(on_app):
        await _time_calls(on_app, arguments, WARMUP_ITERATIONS)
        on_samples = await _time_calls(on_app, arguments, ITERATIONS)
    await on_db.close()

    return {
        "size_label": size_label,
        "arg_bytes": arg_bytes,
        "off_p50": statistics.median(off_samples),
        "off_p99": percentile(off_samples, 99),
        "on_p50": statistics.median(on_samples),
        "on_p99": percentile(on_samples, 99),
    }


async def main() -> None:
    import tempfile

    print(f"OTel tracing overhead benchmark — {ITERATIONS} iterations per cell")
    print("Full bridged tools/call request (request -> policy.evaluate -> bridge.handshake -> "
          "upstream.forward), tracing on (in-memory exporter, synchronous SimpleSpanProcessor — "
          "worst case) vs. off (fully disabled, byte-identical to pre-feature code path).\n")

    try:
        async with run_fastmcp_server() as upstream:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path_root = Path(tmp_dir)
                results = []
                for size_label in ("small", "medium", "large"):
                    results.append(await _bench_one(tmp_path_root, upstream.url, size_label))
    finally:
        await stop_infra()

    print_latency_table("4 spans per call (request, policy.evaluate, bridge.handshake, upstream.forward)", results)


if __name__ == "__main__":
    asyncio.run(main())
