"""Benchmark harness for the quota path (enterprise #11) — measures `UsageRepo.increment` /
`total_since` cost under burst and with accumulated period history, and the DOCUMENTED
check-then-act overshoot (`Pipeline._check_quota`) as a measured distribution.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_quotas

Requires a REAL Postgres (ACROPOLIS_TEST_DATABASE_URL or a disposable docker container via
the harness). The suite's no-mocks discipline applies to benches too: a mocked pool would
measure the mock.

Four measurements:

1. **Single-op cost** — `increment` and `total_since` p50/p99. This is the per-call tax the
   quota feature adds to every forwarded tools/call: one atomic upsert unconditionally, one
   SUM when a quota is configured.
2. **Hot-bucket burst** — N concurrent callers incrementing ONE (key, hour) bucket. The
   upsert serializes on the row via the UNIQUE index; correctness is proven by
   test_postgres_races.py::TestUsageIncrementRace, and this measures the cost of that
   serialization. Contrast cell: N callers on N distinct buckets (no shared row) separates
   row-lock cost from pool cost.
3. **Read vs. history** — `total_since` cost at 1/7/30 days of accumulated hour buckets
   (24/168/720 rows). Answers "does a month-period quota check slow as the period grows"
   with a table instead of a guess.
4. **Measured overshoot** — the accepted check-then-act race (Pipeline._check_quota's
   docstring; docs/quotas.md's accepted limitation): quota_calls=5, burst sizes 20/50/100/200,
   reported as allowed (200) and forwarded (upstream actually reached) distributions. NO
   assertions — the burst test in test_quotas.py owns the correctness bounds; this puts a
   measured typical value behind the docs' "bounded by the burst size" claim.

Scope note: measures the rollup read/write path and the documented TOCTOU window. It does not
re-litigate the TOCTOU decision (accepted and documented — the bench quantifies it) and does
not measure the full pipeline (the pipeline bench owns that composition).
"""
from __future__ import annotations

import asyncio
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from archon.auth.apikeys import ApiKeyService  # noqa: E402
from archon.settings import Settings  # noqa: E402
from argus.app import create_app  # noqa: E402
from argus.quotas import period_start  # noqa: E402
from db.database import Database, utcnow  # noqa: E402
from db.repo import ApiKeyRepo, ServerRepo, UsageRepo  # noqa: E402
from tests.bench._harness import (  # noqa: E402
    iters, markdown_table, percentile, postgres_url, quiet_logging, stop_infra,
    time_call, write_results,
)
from tests.integration.fastmcp_fixture import run_fastmcp_server  # noqa: E402

quiet_logging()

ITERATIONS = iters(300, 5)
WARMUP_ITERATIONS = iters(20, 2)
CONCURRENCY_LEVELS = (1, 8, 16, 32, 64, 128)
INCREMENTS_PER_CALLER = iters(50, 3)
HISTORY_DAYS = (1, 7, 30)
OVERSHOOT_SIZES = (20, 50, 100, 200)
OVERSHOOT_TRIALS = iters(10, 2)
QUOTA_CALLS = 5  # the burst test's own quota_calls, so the overshoot numbers are comparable

SLUG = "q"  # repo-layer parts (1-3) — never called through the app
APP_SLUG = "q-app"  # Part 4's server, wired to the real FastMCP upstream


async def _time_op(fn, iterations: int) -> list[float]:
    return await time_call(fn, iterations)


# ---------------------------------------------------------------------------
# Parts 1-3: the rollup read/write path in isolation (real Postgres, repo layer)
# ---------------------------------------------------------------------------


async def _bench_single_op(usage: UsageRepo, key_id: int, server_id: int, project_id: int) -> tuple[list[str], list[list]]:
    """Part 1: p50/p99 of one increment (atomic upsert) and one total_since (SUM)."""
    ts = utcnow()
    since = period_start("day").isoformat()
    await _time_op(lambda: usage.increment(ts_iso=ts, api_key_id=key_id, server_id=server_id, tool="echo", project_id=project_id), WARMUP_ITERATIONS)
    await _time_op(lambda: usage.total_since(api_key_id=key_id, since_iso=since), WARMUP_ITERATIONS)

    inc = await _time_op(lambda: usage.increment(ts_iso=ts, api_key_id=key_id, server_id=server_id, tool="echo", project_id=project_id), ITERATIONS)
    tot = await _time_op(lambda: usage.total_since(api_key_id=key_id, since_iso=since), ITERATIONS)
    headers = ["op", "p50 ms", "p99 ms"]
    rows = [
        ["increment (atomic upsert)", round(statistics.median(inc), 4), round(percentile(inc, 99), 4)],
        ["total_since (SUM over hour buckets)", round(statistics.median(tot), 4), round(percentile(tot, 99), 4)],
    ]
    return headers, rows


async def _burst_increments(usage: UsageRepo, key_id: int, server_id: int, project_id: int,
                            tools: list[str], n: int, per_caller: int) -> dict:
    """N concurrent callers, `per_caller` increments each; caller i uses `tools[i]` (pass the
    same tool name n times for the hot-bucket case, distinct names for the contrast cell).
    Samples are per-increment; wall time over the whole gather gives increments/s."""
    ts = utcnow()
    samples: list[float] = []

    async def _worker(i: int) -> None:
        for _ in range(per_caller):
            start = time.perf_counter()
            await usage.increment(ts_iso=ts, api_key_id=key_id, server_id=server_id, tool=tools[i], project_id=project_id)
            samples.append((time.perf_counter() - start) * 1000)

    wall_start = time.perf_counter()
    await asyncio.gather(*(_worker(i) for i in range(n)))
    wall_secs = time.perf_counter() - wall_start
    total = n * per_caller
    return {
        "increments_per_sec": round(total / wall_secs, 1),
        "p50_ms": round(statistics.median(samples), 3),
        "p99_ms": round(percentile(samples, 99), 3),
    }


async def _bench_burst(usage: UsageRepo, key_id: int, server_id: int, project_id: int) -> tuple[list[str], list[list]]:
    """Part 2: hot-bucket vs distinct-bucket burst — the cost of the row-lock serialization
    the UNIQUE index provides, separated from pool cost."""
    headers = ["concurrency", "hot-bucket inc/s", "hot p50 ms", "hot p99 ms", "distinct inc/s", "distinct p50 ms", "distinct p99 ms"]
    rows = []
    await _burst_increments(usage, key_id, server_id, project_id, ["warm"], 1, WARMUP_ITERATIONS)
    for n in CONCURRENCY_LEVELS:
        hot = await _burst_increments(usage, key_id, server_id, project_id, ["echo"] * n, n, INCREMENTS_PER_CALLER)
        distinct = await _burst_increments(
            usage, key_id, server_id, project_id,
            [f"echo-{i}" for i in range(n)], n, INCREMENTS_PER_CALLER,
        )
        rows.append([
            n, hot["increments_per_sec"], hot["p50_ms"], hot["p99_ms"],
            distinct["increments_per_sec"], distinct["p50_ms"], distinct["p99_ms"],
        ])
    return headers, rows


async def _seed_history(usage: UsageRepo, key_id: int, server_id: int, project_id: int, days: int) -> None:
    """Seed `days` of hour buckets (24 rows/day) for one key, in the past so today's buckets
    stay untouched. Each increment is a real upsert — the same path production writes."""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    for d in range(1, days + 1):
        for h in range(24):
            ts = (today - timedelta(days=d) + timedelta(hours=h)).isoformat()
            await usage.increment(ts_iso=ts, api_key_id=key_id, server_id=server_id, tool="hist", project_id=project_id)


async def _bench_read_vs_history(usage: UsageRepo, key_id: int, server_id: int, project_id: int) -> tuple[list[str], list[list]]:
    """Part 3: total_since cost at 1/7/30 days of accumulated hour buckets."""
    headers = ["history", "hour buckets", "p50 ms", "p99 ms"]
    rows = []
    for days in HISTORY_DAYS:
        await _seed_history(usage, key_id, server_id, project_id, days)
        since = period_start("day").isoformat()
        samples = await _time_op(lambda: usage.total_since(api_key_id=key_id, since_iso=since), iters(200, 5))
        rows.append([f"{days} day(s)", days * 24, round(statistics.median(samples), 4), round(percentile(samples, 99), 4)])
    return headers, rows


# ---------------------------------------------------------------------------
# Part 4: measured TOCTOU overshoot through the real pipeline
# ---------------------------------------------------------------------------


def _tool_call_headers(tool: str) -> dict:
    return {
        "Content-Type": "application/json", "Accept": "application/json",
        "Mcp-Method": "tools/call", "Mcp-Name": tool,
    }


def _tool_call_body(tool: str, req_id: int) -> dict:
    return {
        "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
        "params": {"name": tool, "arguments": {"message": "hi"}},
    }


async def _call_tool(transport: httpx.ASGITransport, plaintext_key: str, slug: str, tool: str, req_id: int) -> httpx.Response:
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        return await client.post(
            f"/mcp/{slug}", json=_tool_call_body(tool, req_id),
            headers={**_tool_call_headers(tool), "Authorization": f"Bearer {plaintext_key}"},
        )


async def _bench_overshoot(api_keys: ApiKeyService, transport: httpx.ASGITransport, upstream) -> tuple[list[str], list[list]]:
    """Part 4: the documented check-then-act race, quantified. Fresh key per trial (a quota is
    per-key per-day; a consumed key cannot serve two trials), scoped to APP_SLUG so auth passes.
    Allowed = 200 responses; forwarded = the upstream call_counter delta (the ground truth
    test_quotas uses). No assertions — the pytest canary owns the bounds."""
    headers = ["burst size", "trial", "allowed (200)", "forwarded (upstream)"]
    rows = []
    for size in OVERSHOOT_SIZES:
        for t in range(OVERSHOOT_TRIALS):
            key = await api_keys.create(
                name=f"overshoot-{size}-{t}", server_scopes=[APP_SLUG],
                quota_calls=QUOTA_CALLS, quota_period="day",
            )
            before = upstream.call_counter.get("echo", 0)
            responses = await asyncio.wait_for(
                asyncio.gather(*[_call_tool(transport, key.plaintext, APP_SLUG, "echo", req_id=i) for i in range(size)]),
                timeout=30.0,
            )
            allowed = sum(1 for r in responses if r.status_code == 200)
            forwarded = upstream.call_counter.get("echo", 0) - before
            rows.append([size, t, allowed, forwarded])
    return headers, rows


async def main() -> None:
    print("Quota-path benchmark — rollup cost and measured TOCTOU overshoot (enterprise #11)")

    dsn = await postgres_url()
    db = Database(dsn)
    await db.connect()
    sections: list[tuple[str, list[str], list[list]]] = []
    try:
        server_repo = ServerRepo(db)
        await server_repo.create(slug=SLUG, name="Quota bench", upstream_url="http://127.0.0.1:9/mcp")
        api_keys = ApiKeyService(ApiKeyRepo(db))
        usage = UsageRepo(db)

        main_key = await api_keys.create(name="main", server_scopes=[SLUG])
        hist_key = await api_keys.create(name="hist", server_scopes=[SLUG])
        main_server = await server_repo.get(SLUG)

        async def _section(title: str, headers_rows) -> None:
            headers, rows = headers_rows
            sections.append((title, headers, rows))

        await _section("Part 1 — single-op cost (repo layer)", await _bench_single_op(usage, main_key.record.id, main_server.id, main_server.project_id))
        await _section("Part 2 — burst: hot bucket vs distinct buckets", await _bench_burst(usage, main_key.record.id, main_server.id, main_server.project_id))
        await _section("Part 3 — read vs. accumulated history", await _bench_read_vs_history(usage, hist_key.record.id, main_server.id, main_server.project_id))

        # Part 4 needs the real app + upstream: a second server wired to the fixture URL, and
        # keys scoped to it (auth 403s otherwise).
        settings = Settings(
            data_dir=tempfile.mkdtemp(prefix="bench-quotas-"), auth_mode="keyed",
            health_poll_enabled=False, audit_retention_enabled=False,
        )
        app = create_app(settings, db, probe_on_create=False)
        transport = httpx.ASGITransport(app=app)
        async with run_fastmcp_server() as upstream:
            await server_repo.create(slug=APP_SLUG, name="Quota bench app", upstream_url=f"{upstream.url}/mcp")
            async with app.router.lifespan_context(app):
                await _section("Part 4 — measured overshoot (quota_calls=5, no assertions)", await _bench_overshoot(api_keys, transport, upstream))
    finally:
        await db.close()
        await stop_infra()

    md_parts = []
    for title, headers, rows in sections:
        print(f"\n{title}")
        print(markdown_table(headers, rows))
        md_parts.append(f"## {title}\n\n{markdown_table(headers, rows)}")

    path = write_results("quotas", "\n".join(md_parts), module="bench_quotas")
    print(f"\nResults written to {path} — verdict section left for review" if path else "\nSmoke mode: results not written (write_results is a no-op under --smoke)")


if __name__ == "__main__":
    asyncio.run(main())
