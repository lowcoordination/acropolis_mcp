"""Bench-load orchestrator for the multi-replica claim (epic #89, load issue).

Runs the app as TWO real replicas (docker compose, `tests/bench/load/docker-compose.bench.yml`)
against ONE shared Postgres and ONE shared Valkey, seeds a server with a 100/minute rate limit
plus a key, and measures what no single-process bench can:

    python -m tests.bench.load.bench_load

Three measurements:

1. **Multi-replica rate-limit verification (the go/no-go).** Two concurrent worker groups (one
   per replica, real HTTP), 25 workers each, hammering `tools/call` for 30s. The configured
   limit (100/minute) is SHARED across replicas via Valkey: reasoned expectation is aggregate
   2xx ≈ 100 + refill-in-window (~150 over 30s from a full bucket), NOT 2× that (~300) — 300
   would mean each replica enforced its own copy (the exact bug #31 exists to fix, and what
   the #86 replicas>1 documentation claim promises does NOT happen).
2. **Connection-churn throughput profile** — `hey` against one replica's `/api/v1/health`:
   req/s and latency histogram at `-n 10000 -c 50` — real TCP/keep-alive behavior no in-process
   bench sees. `hey` is shelled out to (`shutil.which` with an actionable error); it cannot
   drive the MCP parts because its fixed `-d` body cannot vary JSON-RPC ids, and the
   2025-generation streamable-http upstream keys response streams by rpc id — constant-id
   concurrent load hangs (the bridge's documented id-collision behavior, reproduced while
   developing bench_pipeline). The MCP parts therefore use a Python worker with unique ids.
3. **Cross-process rollup correctness at HTTP level** — exactly N known calls split across BOTH
   replicas, then `usage_rollups` total must be exactly N: the atomic upsert's cross-process
   exactness (which test_postgres_races.py proves at SQL level) verified through two live app
   processes.

Local / pre-release only — explicitly NOT CI (a multi-container compose load test on a shared
runner is a flake farm; see the epic's CI issue). `--smoke` scales every number down to prove
the orchestration end-to-end: compose up -> seed -> load -> report -> compose down.

Topology is recorded in the results file (compose file SHA, machine, hey version if used)
because external-tool numbers are noisier than in-process ones.
"""
from __future__ import annotations

import asyncio
import contextlib
import itertools
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from sse_starlette.sse import AppStatus  # noqa: E402

from archon.auth.apikeys import ApiKeyService  # noqa: E402
from argus.quotas import period_start  # noqa: E402
from db.database import Database  # noqa: E402
from db.models import ServerPolicy  # noqa: E402
from db.repo import ApiKeyRepo, ServerRepo, UsageRepo  # noqa: E402
from tests.bench._harness import (  # noqa: E402
    SMOKE, iters, markdown_table, quiet_logging, write_results,
)
from tests.integration.fastmcp_fixture import build_test_server  # noqa: E402

quiet_logging()

HERE = Path(__file__).resolve().parent
COMPOSE_FILE = HERE / "docker-compose.bench.yml"
REPO_ROOT = Path(__file__).resolve().parents[3]

PG_URL = "postgresql://acropolis:acropolis-bench@127.0.0.1:55435/acropolis"
REPLICA_PORTS = (5591, 5592)

SLUG = "bench"
ROLLUP_SLUG = "rollup"
RATE_LIMIT_SPEC = "100/minute"  # the claim under test: shared across replicas

LOAD_WINDOW_SECONDS = iters(30, 5)  # Part 1 hammering window
LOAD_WORKERS_PER_REPLICA = 25  # concurrent workers per replica during the window
HEY_REQUESTS = 10_000  # Part 2 (smoke: 300)
HEY_CONCURRENCY = 50  # Part 2 (smoke: 10)
ROLLUP_CALLS = 500  # Part 3 known-count cross-process check (smoke: 40)

_HEADERS = {
    "Content-Type": "application/json", "Accept": "application/json",
    "Mcp-Method": "tools/call", "Mcp-Name": "echo",
}
_rpc_ids = itertools.count(1)


def _tool_call_body() -> dict:
    return {
        "jsonrpc": "2.0", "id": next(_rpc_ids), "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hi"}},
    }


def _compose(*args: str) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed ({proc.returncode}):\n"
            f"{proc.stderr or proc.stdout}"
        )
    return proc


async def _wait_healthy(url: str, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
        while time.monotonic() < deadline:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(1.0)
    raise RuntimeError(f"replica at {url} never became healthy within {timeout}s")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.asynccontextmanager
async def _run_upstream_hostwide():
    """A FastMCP upstream bound to 0.0.0.0, reachable from the app CONTAINERS via
    host.docker.internal (the shared fixture binds 127.0.0.1, which containers cannot reach
    through the docker bridge). Reuses the fixture's build_test_server so the tool surface is
    identical; mirrors run_fastmcp_server's boot/shutdown, including the AppStatus reset."""
    AppStatus.should_exit = False
    port = _free_port()
    mcp = build_test_server({})
    mcp.settings.port = port
    # The app containers reach this upstream as host.docker.internal, which FastMCP's
    # DNS-rebinding protection rejects (it auto-allows only localhost hosts). This is a bench
    # fixture on a dev machine, not a deployment — disable the protection for the upstream.
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    else:
        raise RuntimeError("bench upstream server did not start in time")
    try:
        yield port
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except asyncio.TimeoutError:
            server.force_exit = True
            await asyncio.wait_for(task, timeout=5.0)


async def _seed(db_url: str, upstream_url: str) -> tuple[int, str, int, str, int]:
    """Create the rate-limited server + key and an UNLIMITED rollup server + key (Part 3
    measures rollups, not rate limits — it must not be throttled by Part 1's drained bucket).
    Returns (server_id, load_key, load_key_id, rollup_key, rollup_key_id). The rate-limit
    bucket starts full: registration happens here, right before the load starts, so the
    refill-in-window term of the expected aggregate is small and the shared-vs-per-replica
    signal is clean."""
    db = Database(db_url)
    await db.connect()
    try:
        server_repo = ServerRepo(db)
        server = await server_repo.create(
            slug=SLUG, name="Load bench", upstream_url=upstream_url,
        )
        await server_repo.set_policy(server.id, ServerPolicy(rate_limit=RATE_LIMIT_SPEC))
        load_key = await ApiKeyService(ApiKeyRepo(db)).create(name="load-key", server_scopes=[SLUG])
        await server_repo.create(slug=ROLLUP_SLUG, name="Rollup bench", upstream_url=upstream_url)
        rollup_key = await ApiKeyService(ApiKeyRepo(db)).create(name="rollup-key", server_scopes=[ROLLUP_SLUG])
        return server.id, load_key.plaintext, load_key.record.id, rollup_key.plaintext, rollup_key.record.id
    finally:
        await db.close()


async def _load_part1(ports: tuple[int, ...], key: str) -> list[list]:
    """Two worker groups (one per replica), each hammering tools/call for the window.
    Counts 2xx and 429 per replica; the aggregate is the go/no-go number."""
    async def _group(port: int) -> dict:
        counts = {"allowed": 0, "refused": 0, "other": 0}
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}",
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=100),
        ) as client:
            async def _worker() -> None:
                while time.monotonic() < window_end:
                    resp = await client.post(
                        f"/mcp/{SLUG}", json=_tool_call_body(),
                        headers={**_HEADERS, "Authorization": f"Bearer {key}"},
                    )
                    if resp.status_code == 200:
                        counts["allowed"] += 1
                    elif resp.status_code == 429:
                        counts["refused"] += 1
                    else:
                        counts["other"] += 1

            window_end = time.monotonic() + LOAD_WINDOW_SECONDS
            await asyncio.gather(*(_worker() for _ in range(LOAD_WORKERS_PER_REPLICA)))
        return counts

    groups = await asyncio.gather(_group(ports[0]), _group(ports[1]))
    rows = []
    for port, g in zip(ports, groups):
        rows.append([f"replica :{port}", g["allowed"], g["refused"], g["other"]])
    rows.append([
        "AGGREGATE", sum(g["allowed"] for g in groups),
        sum(g["refused"] for g in groups), sum(g["other"] for g in groups),
    ])
    return rows


async def _load_part2() -> str:
    """hey connection-churn profile against /api/v1/health (no JSON-RPC — see the module
    docstring for why hey cannot drive the MCP parts)."""
    hey = shutil.which("hey")
    if hey is None:
        return (
            "Part 2 skipped: `hey` not found on PATH (install it — e.g. "
            "`go install github.com/rakyll/hey@latest` — or brew/apt). The connection-churn "
            "profile needs it; Parts 1 and 3 do not."
        )
    proc = subprocess.run(
        [
            hey, "-n", str(HEY_REQUESTS), "-c", str(HEY_CONCURRENCY),
            "-m", "GET", f"http://127.0.0.1:{REPLICA_PORTS[0]}/api/v1/health",
        ],
        capture_output=True, text=True, timeout=300,
    )
    # hey prints its summary to stderr; keep the whole thing verbatim — it IS the record.
    return proc.stderr or proc.stdout


async def _load_part3(db_url: str, key_id: int, key: str) -> list[list]:
    """Exactly ROLLUP_CALLS known calls against the UNLIMITED rollup server, alternating
    across BOTH replicas, then the rollup total must grow by exactly that count (cross-process
    upsert exactness at the HTTP level). Reads the rollup before and after — Part 1's hammering
    has already written to the load key's bucket, so the DELTA on the rollup key is the claim."""
    per_replica = ROLLUP_CALLS // 2

    async def _send(port: int, n: int) -> None:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=httpx.Timeout(30.0),
        ) as client:
            for _ in range(n):
                resp = await client.post(
                    f"/mcp/{ROLLUP_SLUG}", json=_tool_call_body(),
                    headers={**_HEADERS, "Authorization": f"Bearer {key}"},
                )
                assert resp.status_code == 200, resp.text

    async def _rollup_total() -> int:
        db = Database(db_url)
        await db.connect()
        try:
            return await UsageRepo(db).total_since(
                api_key_id=key_id, since_iso=period_start("day").isoformat(),
            )
        finally:
            await db.close()

    before = await _rollup_total()
    await asyncio.gather(
        _send(REPLICA_PORTS[0], per_replica),
        _send(REPLICA_PORTS[1], per_replica),
    )
    after = await _rollup_total()
    delta = after - before
    return [[
        "usage_rollups delta", delta, "expected", ROLLUP_CALLS,
        "match", "yes" if delta == ROLLUP_CALLS else "NO",
    ]]


async def main() -> None:
    print("Load tier: multi-replica rate-limit verification (epic #89)")
    print(f"Window {LOAD_WINDOW_SECONDS}s, {LOAD_WORKERS_PER_REPLICA} workers/replica, "
          f"rate limit {RATE_LIMIT_SPEC} (shared); smoke={SMOKE}")

    compose_up = _compose("up", "-d", "--build", "--wait")
    md_parts: list[str] = []
    try:
        await _wait_healthy(f"http://127.0.0.1:{REPLICA_PORTS[0]}/api/v1/health")
        await _wait_healthy(f"http://127.0.0.1:{REPLICA_PORTS[1]}/api/v1/health")

        async with _run_upstream_hostwide() as upstream_port:
            upstream_url = f"http://host.docker.internal:{upstream_port}/mcp"
            server_id, key, key_id, rollup_key, rollup_key_id = await _seed(PG_URL, upstream_url)

            print("\nPart 1 — multi-replica rate-limit verification (100/minute SHARED, 30s window)")
            rows1 = await _load_part1(REPLICA_PORTS, key)
            headers1 = ["replica", "allowed (2xx)", "refused (429)", "other"]
            print(markdown_table(headers1, rows1))
            md_parts.append(f"## Part 1 — multi-replica rate-limit verification\n\n"
                            f"Configured {RATE_LIMIT_SPEC} SHARED across {len(REPLICA_PORTS)} replicas; "
                            f"window {LOAD_WINDOW_SECONDS}s, {LOAD_WORKERS_PER_REPLICA} workers/replica.\n\n"
                            f"{markdown_table(headers1, rows1)}")

            print("\nPart 2 — connection-churn profile (hey, /api/v1/health)")
            part2 = await _load_part2()
            print(part2[:500] if len(part2) > 500 else part2)
            md_parts.append(f"## Part 2 — connection-churn profile (hey)\n\n```\n{part2}\n```")

            print("\nPart 3 — cross-process rollup correctness (500 known calls across both replicas)")
            rows3 = await _load_part3(PG_URL, rollup_key_id, rollup_key)
            headers3 = ["measure", "value", "vs", "expected", "match", "?"]
            print(markdown_table(headers3, rows3))
            md_parts.append(f"## Part 3 — cross-process rollup correctness\n\n{markdown_table(headers3, rows3)}")
    finally:
        _compose("down", "--volumes")

    path = write_results("load-multi-replica", "\n".join(md_parts), module="bench_load")
    print(f"\nResults written to {path} — verdict section left for review")


if __name__ == "__main__":
    asyncio.run(main())
