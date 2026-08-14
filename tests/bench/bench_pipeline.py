"""Benchmark harness for the FULL pipeline (`Pipeline.handle()` end-to-end) — the
per-release regression baseline the epic's Why section calls for: actual req/s and p50/p99
through the full auth -> rate-limit -> quota -> policy -> forward chain, against a REAL
uvicorn server, a real FastMCP upstream, and real Postgres.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_pipeline

Topology (the fixture philosophy of test_rate_limit_valkey.py applied to the app itself):
- the real app served by real uvicorn on an ephemeral port — NOT ASGITransport; the point is
  including the HTTP/uvicorn layer the per-subsystem benches deliberately exclude,
- a real FastMCP upstream (tests/integration/fastmcp_fixture),
- real Postgres via the harness,
- a pooled httpx client, API-key auth ON (`_authenticate`'s `verify()` is a real per-call
  DB lookup — open auth would understate the baseline).

Three measurements:

1. **Throughput ceiling** — N concurrent clients × M `tools/call` (echo, message argument),
   passthrough policy: req/s, p50/p99 per level.
2. **Feature layering** — the same shape toggling one feature at a time (server rate limit,
   key quota, DLP built-in detectors): added p50/p99 per feature on the REAL path. This is
   the composed version of the per-subsystem "added p50" tables, which no single-layer bench
   can produce — the sum of the isolated costs may not equal the composed cost, and nothing
   else would know.
3. **Server-vs-client cross-check** — the audit rows' `latency_ms` vs client-measured p50 on
   the same requests; divergence is time spent outside the pipeline's own clock (uvicorn,
   HTTP framing, connection handling).

Scope note (honest, house style): single-process event loop on one core — this measures the
app's async ceiling on the bench machine, not a deployment's capacity, and absolute numbers
are machine-dependent. Its job is DELTAS: baseline vs future, feature off vs on.
Multi-process/multi-replica questions belong to the load tier (tests/bench/load/).

Re-run policy (decided in the epic): re-run at each release, commit the new results file
alongside, and read the before/after delta into the release notes. Hot-path PRs may be asked
to re-run ad hoc — a review request, not a CI gate.
"""
from __future__ import annotations

import asyncio
import itertools
import socket
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402
import uvicorn  # noqa: E402

from archon.auth.apikeys import ApiKeyService  # noqa: E402
from archon.settings import Settings  # noqa: E402
from argus.app import create_app  # noqa: E402
from db.database import Database  # noqa: E402
from db.models import ServerPolicy  # noqa: E402
from db.repo import ApiKeyRepo, AuditRepo, ServerRepo  # noqa: E402
from tests.bench._harness import (  # noqa: E402
    iters, markdown_table, percentile, postgres_url, quiet_logging, stop_infra,
    time_call, write_results,
)
from tests.integration.fastmcp_fixture import run_fastmcp_server  # noqa: E402

quiet_logging()

CONCURRENCY_LEVELS = (1, 8, 16, 32, 64, 128)
CALLS_PER_CLIENT = iters(50, 3)
LAYER_LEVELS = (16, 64)  # Part 2 is per-feature; two levels keep it tractable
WARMUP_CALLS = iters(20, 2)
CROSSCHECK_CALLS = iters(100, 5)
CLIENT_MAX_CONNECTIONS = 512  # raise the client pool past the sweep's peak concurrency

SLUG = "p"
CROSSCHECK_SLUG = "p3"

# Features configured to NEVER block: the layering question is the added cost of each check on
# the hot path, not what a refusal feels like (bench_rate_limit / bench_quotas own that).
RATE_LIMIT_SPEC = "100000/second"
QUOTA_CALLS = 1_000_000_000
QUOTA_PERIOD = "month"
DLP_DETECTORS = {
    "credit_card": "redact",
    "email": "redact",
    "us_ssn": "redact",
    "aws_access_key": "redact",
    "private_key_pem": "redact",
    "high_entropy_string": "redact",
}

_HEADERS = {
    "Content-Type": "application/json", "Accept": "application/json",
    "Mcp-Method": "tools/call", "Mcp-Name": "echo",
}
_BODY = {
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "echo", "arguments": {"message": "hi"}},
}

# Every request carries a UNIQUE JSON-RPC id. The bridge multiplexes concurrent calls onto ONE
# upstream session, and the streamable-http upstream keys its per-request response streams by
# rpc id — two in-flight requests with the same id displace each other upstream, and the
# displaced one hangs until the read timeout (the bridge's documented id-collision behavior,
# see argus/bridge.py's sanitize_rpc_id comment). Real MCP clients number requests distinctly;
# a benchmark must too, or it measures its own collision instead of the pipeline.
_rpc_ids = itertools.count(1)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _start_server(app) -> tuple[uvicorn.Server, int, asyncio.Task]:
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            return server, port, task
        await asyncio.sleep(0.05)
    raise RuntimeError("app uvicorn server did not start in time")


async def _stop_server(server: uvicorn.Server, task: asyncio.Task) -> None:
    server.should_exit = True
    try:
        await asyncio.wait_for(task, timeout=5.0)
    except asyncio.TimeoutError:
        server.force_exit = True
        await asyncio.wait_for(task, timeout=5.0)


async def _sweep(client: httpx.AsyncClient, port: int, key: str, slug: str, n: int, per_caller: int) -> dict:
    """N concurrent clients (sharing the pooled client), `per_caller` calls each; samples are
    per-call, wall time over the whole gather gives req/s."""
    samples: list[float] = []

    async def _worker() -> None:
        for _ in range(per_caller):
            body = {**_BODY, "id": next(_rpc_ids)}
            start = time.perf_counter()
            resp = await client.post(
                f"/mcp/{slug}", json=body,
                headers={**_HEADERS, "Authorization": f"Bearer {key}"},
            )
            samples.append((time.perf_counter() - start) * 1000)
            assert resp.status_code == 200, resp.text

    wall_start = time.perf_counter()
    await asyncio.gather(*(_worker() for _ in range(n)))
    wall_secs = time.perf_counter() - wall_start
    total = n * per_caller
    return {
        "req_per_sec": round(total / wall_secs, 1),
        "p50_ms": round(statistics.median(samples), 3),
        "p99_ms": round(percentile(samples, 99), 3),
    }


async def _bench_ceiling(client, port, key) -> tuple[list[str], list[list]]:
    """Part 1: passthrough policy, plain key — the full-chain baseline."""
    headers = ["concurrency", "req/s", "p50 ms", "p99 ms"]
    rows = []
    await _sweep(client, port, key, SLUG, 1, WARMUP_CALLS)
    for n in CONCURRENCY_LEVELS:
        r = await _sweep(client, port, key, SLUG, n, CALLS_PER_CLIENT)
        rows.append([n, r["req_per_sec"], r["p50_ms"], r["p99_ms"]])
    return headers, rows


async def _bench_layering(client, port, server_repo: ServerRepo, server_id: int, api_keys: ApiKeyService) -> tuple[list[str], list[list]]:
    """Part 2: one feature at a time on the real path, at two concurrency levels."""
    headers = ["config", "concurrency", "req/s", "p50 ms", "p99 ms", "added p50 vs baseline"]
    rows = []
    baseline_by_level: dict[int, float] = {}

    configs = [
        ("baseline (passthrough)", ServerPolicy(), None),
        ("+ server rate limit", ServerPolicy(rate_limit=RATE_LIMIT_SPEC), None),
        ("+ key quota", ServerPolicy(), QUOTA_CALLS),
        ("+ DLP built-in detectors", ServerPolicy(dlp_detectors=DLP_DETECTORS), None),
    ]
    for name, policy, quota_calls in configs:
        await server_repo.set_policy(server_id, policy)
        key = (await api_keys.create(
            name=f"layer-{name.replace(' ', '-')}", server_scopes=[SLUG],
            quota_calls=quota_calls, quota_period=QUOTA_PERIOD if quota_calls else None,
        )).plaintext
        for n in LAYER_LEVELS:
            r = await _sweep(client, port, key, SLUG, n, CALLS_PER_CLIENT)
            added = ""
            if name.startswith("baseline"):
                baseline_by_level[n] = r["p50_ms"]
            else:
                added = round(r["p50_ms"] - baseline_by_level[n], 3)
            rows.append([name, n, r["req_per_sec"], r["p50_ms"], r["p99_ms"], added])
    return headers, rows


async def _bench_crosscheck(client, port, key, db) -> tuple[list[str], list[list]]:
    """Part 3: audit-row latency_ms vs client p50 on the same requests (dedicated server
    slug so the audit query is unambiguous).

    Finding (filed as #99): the ALLOWED path logs `latency_ms` frozen at audit_common
    construction — BEFORE policy evaluation and the upstream forward — so forwarded rows
    record ~0, contradicting docs/observability.md's "gateway-total latency_ms" claim. This
    part therefore currently measures THAT bug (audit p50 ≈ 0 vs a real client p50), not the
    uvicorn/HTTP gap it was designed for; the verdict states the numbers either way, and the
    comparison becomes meaningful once #99 lands."""
    client_samples = await _sweep(client, port, key, CROSSCHECK_SLUG, 16, CROSSCHECK_CALLS)
    # AuditLogger enqueues and flushes in the background — settle so every row is queryable.
    await asyncio.sleep(0.5)
    audit = AuditRepo(db)
    rows_db = await audit.query(server_slug=CROSSCHECK_SLUG, decision="ALLOWED", limit=2000)
    latencies = [r["latency_ms"] for r in rows_db if r.get("latency_ms") is not None]
    headers = ["measurement", "p50 ms", "p99 ms", "samples"]
    return headers, [
        ["client-measured", client_samples["p50_ms"], client_samples["p99_ms"], 16 * CROSSCHECK_CALLS],
        ["audit-row latency_ms", round(statistics.median(latencies), 3), round(percentile(latencies, 99), 3), len(latencies)],
    ]


async def main() -> None:
    print("Pipeline benchmark — full-chain throughput baseline (per-release regression gate)")

    dsn = await postgres_url()
    db = Database(dsn)
    await db.connect()
    sections: list[tuple[str, list[str], list[list]]] = []
    try:
        server_repo = ServerRepo(db)
        api_keys = ApiKeyService(ApiKeyRepo(db))

        async with run_fastmcp_server() as up:
            settings = Settings(
                data_dir=tempfile.mkdtemp(prefix="bench-pipeline-"), auth_mode="keyed",
                health_poll_enabled=False, audit_retention_enabled=False,
            )
            await server_repo.create(slug=SLUG, name="Pipeline bench", upstream_url=f"{up.url}/mcp")
            await server_repo.create(slug=CROSSCHECK_SLUG, name="Pipeline cross-check", upstream_url=f"{up.url}/mcp")

            app = create_app(settings, db, probe_on_create=False)
            uvicorn_server, port, server_task = await _start_server(app)
            try:
                key = (await api_keys.create(name="p-key", server_scopes=[SLUG])).plaintext
                x_key = (await api_keys.create(name="p3-key", server_scopes=[CROSSCHECK_SLUG])).plaintext

                async def _section(title: str, headers_rows) -> None:
                    headers, rows = headers_rows
                    sections.append((title, headers, rows))

                limits = httpx.Limits(max_connections=CLIENT_MAX_CONNECTIONS)
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", limits=limits) as client:
                    await _section("Part 1 — throughput ceiling (passthrough)", await _bench_ceiling(client, port, key))
                    server_id = (await server_repo.get(SLUG)).id
                    await _section("Part 2 — feature layering (one feature at a time)", await _bench_layering(client, port, server_repo, server_id, api_keys))
                    await _section("Part 3 — audit latency_ms vs client p50", await _bench_crosscheck(client, port, x_key, db))
            finally:
                await _stop_server(uvicorn_server, server_task)
    finally:
        await db.close()
        await stop_infra()

    md_parts = []
    for title, headers, rows in sections:
        print(f"\n{title}")
        print(markdown_table(headers, rows))
        md_parts.append(f"## {title}\n\n{markdown_table(headers, rows)}")

    # The results file is the per-release baseline: it records the git SHA it was measured at
    # (via the harness writer) and carries a comparison template for the next release's rerun.
    md_parts.append(
        "## Compare against baseline (next release)\n\n"
        "| metric | this run (SHA above) | next release | delta |\n"
        "| --- | --- | --- | --- |\n"
        "| Part 1 p50 @ 16-way | TBD | TBD | TBD |\n"
        "| Part 1 req/s @ 64-way | TBD | TBD | TBD |\n"
        "| Part 2 added p50 (+quota) | TBD | TBD | TBD |\n"
    )
    path = write_results("pipeline-baseline", "\n".join(md_parts), module="bench_pipeline")
    print(f"\nResults written to {path} — verdict section left for review" if path else "\nSmoke mode: results not written (write_results is a no-op under --smoke)")


if __name__ == "__main__":
    asyncio.run(main())
