"""Benchmark harness for enterprise #9 (OpenTelemetry tracing) — measures added latency per
tools/call request from span creation/export, tracing on vs. off, at the SAME representative
argument sizes tests/bench/bench_dlp.py used (small/medium/large), per the plan's explicit
instruction to reuse that harness's shape rather than inventing a new one.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_otel

The numbers this script prints are what docs/observability.md's "Overhead" section reports.
Re-run and update that doc if argus/tracing.py's span points or export mechanism change
materially.

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
import logging
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Quiet every logger below WARNING — this benchmark drives thousands of real requests through
# the app (audit logging, httpx request logging, FastMCP's own request logging all fire per
# call), and the resulting console noise makes the actual results hard to find. Mirrors
# bench_dlp.py's console output discipline of "print exactly the table, nothing else load-bearing".
logging.basicConfig(level=logging.WARNING)
for _name in ("argus", "archon", "stoa", "httpx", "httpcore", "mcp", "uvicorn"):
    logging.getLogger(_name).setLevel(logging.WARNING)

import httpx  # noqa: E402

from archon.settings import Settings  # noqa: E402
from argus.app import create_app  # noqa: E402
from argus.tracing import TracingManager, _DisabledTracingManager  # noqa: E402
from db.database import Database  # noqa: E402
from db.repo import ServerRepo  # noqa: E402
from tests.integration.fastmcp_fixture import run_fastmcp_server  # noqa: E402

ITERATIONS = 500
WARMUP_ITERATIONS = 50


def _representative_arguments(size_label: str) -> dict:
    """Identical argument shapes to bench_dlp.py's _representative_arguments — same sizes, same
    filler text — so the two benchmarks' numbers are directly comparable at each size label."""
    filler = (
        "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet, consectetur "
        "adipiscing elit. "
    )
    if size_label == "small":
        return {"query": "find all TODO comments in the repo", "limit": 20}
    if size_label == "medium":
        return {"message": filler * 10, "channel": "general"}  # ~730 chars
    if size_label == "large":
        return {"content": filler * 200, "path": "/tmp/report.txt"}  # ~14.6 KB
    raise ValueError(size_label)


async def _make_app(tmp_path: Path, upstream_url: str, tracing_active: bool):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
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
    import time

    transport = httpx.ASGITransport(app=app)
    headers = {
        "Content-Type": "application/json", "Accept": "application/json",
        "Mcp-Method": "tools/call", "Mcp-Name": "echo",
    }
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "echo", "arguments": arguments},
    }
    samples = []
    async with httpx.AsyncClient(transport=transport, base_url="http://bench.test") as client:
        for _ in range(iterations):
            start = time.perf_counter()
            resp = await client.post("/mcp/bench-server", json=body, headers=headers)
            samples.append((time.perf_counter() - start) * 1000)  # ms
            assert resp.status_code == 200, resp.text
    return samples


def _percentile(samples: list[float], pct: float) -> float:
    return statistics.quantiles(samples, n=100)[int(pct) - 1] if len(samples) >= 100 else max(samples)


async def _bench_one(tmp_path_root: Path, upstream_url: str, size_label: str) -> dict:
    arguments = _representative_arguments(size_label)
    arg_bytes = sum(len(str(v)) for v in arguments.values())

    off_dir = tmp_path_root / f"off-{size_label}"
    on_dir = tmp_path_root / f"on-{size_label}"
    off_dir.mkdir(parents=True, exist_ok=True)
    on_dir.mkdir(parents=True, exist_ok=True)

    off_app, off_db = await _make_app(off_dir, upstream_url, tracing_active=False)
    async with off_app.router.lifespan_context(off_app):
        await _time_calls(off_app, arguments, WARMUP_ITERATIONS)
        off_samples = await _time_calls(off_app, arguments, ITERATIONS)
    await off_db.close()

    on_app, on_db = await _make_app(on_dir, upstream_url, tracing_active=True)
    async with on_app.router.lifespan_context(on_app):
        await _time_calls(on_app, arguments, WARMUP_ITERATIONS)
        on_samples = await _time_calls(on_app, arguments, ITERATIONS)
    await on_db.close()

    return {
        "size_label": size_label,
        "arg_bytes": arg_bytes,
        "off_p50": statistics.median(off_samples),
        "off_p99": _percentile(off_samples, 99),
        "on_p50": statistics.median(on_samples),
        "on_p99": _percentile(on_samples, 99),
    }


def _print_table(label: str, results: list[dict]) -> None:
    print(f"\n--- {label} ---")
    print(f"{'size':<8} {'arg bytes':>10} {'off p50':>9} {'off p99':>9} {'on p50':>9} {'on p99':>9} {'added p50':>10} {'added p99':>10}")
    for r in results:
        added_p50 = r["on_p50"] - r["off_p50"]
        added_p99 = r["on_p99"] - r["off_p99"]
        print(
            f"{r['size_label']:<8} {r['arg_bytes']:>10} {r['off_p50']:>8.3f}ms {r['off_p99']:>8.3f}ms "
            f"{r['on_p50']:>8.3f}ms {r['on_p99']:>8.3f}ms {added_p50:>9.3f}ms {added_p99:>9.3f}ms"
        )


async def main() -> None:
    import tempfile

    print(f"OTel tracing overhead benchmark — {ITERATIONS} iterations per cell")
    print("Full bridged tools/call request (request -> policy.evaluate -> bridge.handshake -> "
          "upstream.forward), tracing on (in-memory exporter, synchronous SimpleSpanProcessor — "
          "worst case) vs. off (fully disabled, byte-identical to pre-feature code path).\n")

    async with run_fastmcp_server() as upstream:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path_root = Path(tmp_dir)
            results = []
            for size_label in ("small", "medium", "large"):
                results.append(await _bench_one(tmp_path_root, upstream.url, size_label))

    _print_table("4 spans per call (request, policy.evaluate, bridge.handshake, upstream.forward)", results)


if __name__ == "__main__":
    asyncio.run(main())
