"""Benchmark harness for the distributed rate-limit backend (issue #31) — measures the cost
of the shared-state Valkey backend versus the in-memory default, under concurrency, in
degraded mode, and as an atomicity number.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_rate_limit

Requires the `distributed` extra (the redis client) — the Valkey backend does not exist
without it. Runs against a REAL Valkey (ACROPOLIS_TEST_VALKEY_URL or a disposable docker
container via the harness), never fakeredis: a mock would assert that `eval` got called,
not that concurrent callers actually got a correct answer — the exact reasoning
test_rate_limit_valkey.py uses.

Five measurements:

1. **Single-check cost, memory vs Valkey** — the added per-request latency of switching an
   operator's backend from in-memory to shared-state (the price of issue #31's correctness).
2. **Hot-key concurrency sweep** — N concurrent callers hammering ONE registered bucket.
   In-memory serializes on the bucket's asyncio.Lock; Valkey serializes server-side on the
   single Lua key. Where each flattens, and how p99 grows past it, is the question.
3. **Cardinality contrast** — the same sweep with each caller on its OWN key. In-memory
   locks are per-bucket (should scale); Valkey funnels every check through one connection
   pool and one server event loop. Parts 2+3 together answer "is the bottleneck the lock,
   the network, or the pool".
4. **Degraded-mode latency** — the fail-closed path (`RateLimitBackendUnavailable`), three
   flavors because they fail at different speeds: (a) a closed port (connection refused —
   the fast error path), (b) a `docker pause`d container (hung connection — the slow path
   through the 2.0s socket budgets), and (c) the default-pool client as shipped under a
   burst past redis-py 8.x's 100-connection async pool cap — a production ceiling this
   bench surfaced, measured on record and filed separately (#97). (a)+(b) examine
   `build_valkey_backend`'s claim that "a slow backend must degrade to a fast 429, not a
   hang". Pause is only ever applied to a container this bench itself started.
5. **Atomicity as a number** — N concurrent consumers against a `5/minute` bucket, per
   backend, reported as allowed vs theoretical (5 + refill-in-window, which rounds to 5 for
   a burst). Reported, not asserted: drift here is the measurement signal that the
   asyncio.Lock or the Lua script's atomicity weakened — the same claim
   test_rate_limit_valkey.py asserts as pass/fail, tracked as a number instead.

Scope note: this measures the `RateLimitBackend` SEAM (`register`/`ensure_current`/
`check`/`check_all`) in isolation — not the full `Pipeline._check_rate_limits` path (that
composition is the pipeline bench's job, and it adds auth/policy/audit fixed overhead that is
identical for both backends). Per-tool keys are not measured: `tool_key` is constructed and
checked but never registered (the F9 gap, see argus/rate_limiter.py's `tool_key` docstring),
so there is no per-tool limit to measure.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.rate_limiter import InMemoryBackend, RateLimitBackendUnavailable  # noqa: E402
from argus.rate_limit_valkey import ValkeyBackend, build_valkey_backend  # noqa: E402
from tests.bench._harness import (  # noqa: E402
    iters, markdown_table, percentile, quiet_logging, stop_infra, time_call,
    valkey_container_name, valkey_url, write_results,
)

# Quiet every logger below WARNING (redis-py and the app's loggers fire per call).
quiet_logging()

ITERATIONS = iters(300, 5)
WARMUP_ITERATIONS = iters(20, 2)
CONCURRENCY_LEVELS = (1, 8, 16, 32, 64, 128)
CHECKS_PER_CALLER = iters(50, 3)
CLOSED_PORT_ITERATIONS = iters(100, 5)
PAUSED_ITERATIONS = iters(50, 1)  # each refusal costs ~2s (the socket timeout) — smoke stays tiny
ATOMICITY_LEVELS = (8, 32, 128)
ATOMICITY_TRIALS = iters(5, 2)
POOL_EXHAUSTION_BURST = 200  # 2× the default pool cap (see Part 4c)

KEY = "bench-server"
REPRESENTATIVE_SPEC = "100/second"  # Part 1: a realistic operator-configured limit
HOT_KEY_SPEC = "100000/second"  # Parts 2/3: a bucket too large to refuse — pure mechanism cost
ATOMIC_SPEC = "5/minute"

# redis-py 8.x's async ConnectionPool defaults max_connections to 100 (the change from older
# 2**31 defaults), and build_valkey_backend does not override it. The concurrency sweeps
# (Parts 2/3) deliberately measure the LOCK/LUA mechanism, not the pool ceiling, so they use
# a production-shaped client with the pool raised to clear the sweep; the DEFAULT-pool wiring
# as shipped is itself measured separately in Part 4c, where its exhaustion behavior belongs.
SWEEP_MAX_CONNECTIONS = 512


async def _time_checks(backend, key: str, iterations: int) -> list[float]:
    return await time_call(lambda: backend.check(key), iterations)


async def _sweep(backend, keys: list[str], n: int, per_caller: int) -> dict:
    """N concurrent callers, `per_caller` checks each; caller i consumes `keys[i]` (pass the
    same key object n times for the hot-key case, distinct keys for the cardinality case).
    Samples are per-check; wall time over the whole gather gives checks/s."""
    samples: list[float] = []

    async def _worker(i: int) -> None:
        key = keys[i]
        for _ in range(per_caller):
            start = time.perf_counter()
            await backend.check(key)
            samples.append((time.perf_counter() - start) * 1000)

    wall_start = time.perf_counter()
    await asyncio.gather(*(_worker(i) for i in range(n)))
    wall_secs = time.perf_counter() - wall_start
    total = n * per_caller
    return {
        "wall_secs": round(wall_secs, 2),
        "checks_per_sec": round(total / wall_secs, 1),
        "p50_ms": round(statistics.median(samples), 3),
        "p99_ms": round(percentile(samples, 99), 3),
    }


async def _bench_single_check(memory, valkey) -> tuple[list[str], list[list]]:
    """Part 1: added per-check cost of the Valkey backend vs in-memory, one key."""
    memory.register(KEY, REPRESENTATIVE_SPEC)
    valkey.register(KEY, REPRESENTATIVE_SPEC)
    await _time_checks(memory, KEY, WARMUP_ITERATIONS)
    await _time_checks(valkey, KEY, WARMUP_ITERATIONS)

    mem = await _time_checks(memory, KEY, ITERATIONS)
    val = await _time_checks(valkey, KEY, ITERATIONS)
    headers = ["memory p50 ms", "memory p99 ms", "valkey p50 ms", "valkey p99 ms", "added p50 ms"]
    rows = [[
        round(statistics.median(mem), 4), round(percentile(mem, 99), 4),
        round(statistics.median(val), 4), round(percentile(val, 99), 4),
        round(statistics.median(val) - statistics.median(mem), 4),
    ]]
    return headers, rows


async def _bench_hot_key(memory, valkey_sweep) -> tuple[list[str], list[list]]:
    """Part 2: all callers on ONE bucket — lock (in-memory) vs Lua-key (Valkey) contention.
    `valkey_sweep` is the oversized-pool client (see SWEEP_MAX_CONNECTIONS) so this measures
    the lock/Lua mechanism, not the production pool's ceiling (which Part 4c owns)."""
    memory.register(KEY, HOT_KEY_SPEC)
    valkey_sweep.register(KEY, HOT_KEY_SPEC)
    await _sweep(memory, [KEY], 1, WARMUP_ITERATIONS)  # warm the pool
    await _sweep(valkey_sweep, [KEY], 1, WARMUP_ITERATIONS)

    headers = ["concurrency", "mem checks/s", "mem p50 ms", "mem p99 ms", "val checks/s", "val p50 ms", "val p99 ms"]
    rows = []
    for n in CONCURRENCY_LEVELS:
        m = await _sweep(memory, [KEY] * n, n, CHECKS_PER_CALLER)
        v = await _sweep(valkey_sweep, [KEY] * n, n, CHECKS_PER_CALLER)
        rows.append([
            n, m["checks_per_sec"], m["p50_ms"], m["p99_ms"],
            v["checks_per_sec"], v["p50_ms"], v["p99_ms"],
        ])
    return headers, rows


async def _bench_cardinality(memory, valkey_sweep) -> tuple[list[str], list[list]]:
    """Part 3: each caller on its OWN key — per-bucket locks (memory) vs one pool/server (Valkey)."""
    headers = ["concurrency", "mem checks/s", "mem p50 ms", "mem p99 ms", "val checks/s", "val p50 ms", "val p99 ms"]
    rows = []
    for n in CONCURRENCY_LEVELS:
        mem_keys = [f"bench-server-m-{i}" for i in range(n)]
        val_keys = [f"bench-server-v-{i}" for i in range(n)]
        for k in mem_keys:
            memory.register(k, HOT_KEY_SPEC)
        for k in val_keys:
            valkey_sweep.register(k, HOT_KEY_SPEC)
        m = await _sweep(memory, mem_keys, n, CHECKS_PER_CALLER)
        v = await _sweep(valkey_sweep, val_keys, n, CHECKS_PER_CALLER)
        rows.append([
            n, m["checks_per_sec"], m["p50_ms"], m["p99_ms"],
            v["checks_per_sec"], v["p50_ms"], v["p99_ms"],
        ])
    return headers, rows


async def _time_refusals(fn, iterations: int) -> tuple[list[float], int]:
    """Time `iterations` awaited calls of `fn`, treating RateLimitBackendUnavailable as the
    expected outcome (degraded-mode parts). Returns (per-call ms samples, refusals_seen)."""
    samples: list[float] = []
    refusals = 0
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            await fn()
        except RateLimitBackendUnavailable:
            refusals += 1
        samples.append((time.perf_counter() - start) * 1000)
    return samples, refusals


async def _bench_degraded(valkey, url: str) -> tuple[list[str], list[list]]:
    """Part 4: fail-closed refusal latency. (a) closed port — the fast error path; (b) a
    paused container — the slow path through the 2.0s socket budgets, only if this bench owns
    the container (never an operator-provided server); (c) the DEFAULT-pool client as shipped
    under a burst past redis-py's 100-connection async pool cap — a finding this bench
    surfaced, measured here so the production wiring's exhaustion behavior is on record."""
    from redis.asyncio import Redis

    # (a) closed port: connection refused is immediate — no timeout wait.
    closed_client = Redis.from_url(
        "redis://127.0.0.1:59999/0", socket_connect_timeout=2.0, socket_timeout=2.0,
    )
    closed = ValkeyBackend(closed_client)
    closed.register(KEY, REPRESENTATIVE_SPEC)
    samples_a, refusals_a = await _time_refusals(lambda: closed.check(KEY), CLOSED_PORT_ITERATIONS)
    await closed_client.aclose()

    headers = ["case", "refusals/total", "p50 ms", "p99 ms"]
    rows = [[
        "closed port (connection refused)",
        f"{refusals_a}/{CLOSED_PORT_ITERATIONS}",
        round(statistics.median(samples_a), 3),
        round(percentile(samples_a, 99), 3),
    ]]

    container = valkey_container_name()
    if container is None:
        # Loud, honest skip — never silent: pausing an operator-provided server is not safe,
        # and a bench must not quietly change what it measured.
        print(
            "Part 4b skipped: Valkey provided via ACROPOLIS_TEST_VALKEY_URL — pausing an "
            "operator-provided server is not safe. Unset it to exercise the docker-pause case."
        )
        rows.append(["paused container (hung connection)", "skipped — external Valkey", "-", "-"])
    else:
        subprocess.run(["docker", "pause", container], check=True, capture_output=True)
        try:
            samples_b, refusals_b = await _time_refusals(
                lambda: valkey.check(KEY), PAUSED_ITERATIONS,
            )
        finally:
            subprocess.run(["docker", "unpause", container], check=True, capture_output=True)

        # Recovery sanity check: the bench owns this container and must leave it usable. This
        # is a validity guard for the measurement, not a performance assertion.
        recovered = False
        try:
            recovered = await valkey.check(KEY) is not None
        except Exception:  # noqa: BLE001 — reporting recovery failure is the point
            recovered = False
        rows.append([
            "paused container (hung connection)",
            f"{refusals_b}/{PAUSED_ITERATIONS}",
            round(statistics.median(samples_b), 3),
            round(percentile(samples_b, 99), 3),
        ])
        print(f"Recovery check after unpause: {'OK' if recovered else 'FAILED — container left in a bad state'}")

    # (c) default-pool exhaustion: build_valkey_backend as shipped (redis-py 8.x async pool
    # caps at 100 connections), a burst 2× past it. Refusals are instantaneous (pool raises,
    # no wait) — the finding is the CAP, and that those refusals 429 fail-closed.
    default_pool = build_valkey_backend(url)
    default_pool.register(KEY, REPRESENTATIVE_SPEC)
    samples_c: list[float] = []
    refusals_c = 0

    async def _burst() -> None:
        nonlocal refusals_c
        start = time.perf_counter()
        try:
            await default_pool.check(KEY)
        except RateLimitBackendUnavailable:
            refusals_c += 1
        samples_c.append((time.perf_counter() - start) * 1000)

    await asyncio.gather(*(_burst() for _ in range(POOL_EXHAUSTION_BURST)))
    await default_pool._client.aclose()  # noqa: SLF001 — the bench manages the infra it built
    rows.append([
        f"default pool, {POOL_EXHAUSTION_BURST}-way burst (pool cap)",
        f"{refusals_c}/{POOL_EXHAUSTION_BURST}",
        round(statistics.median(samples_c), 3),
        round(percentile(samples_c, 99), 3),
    ])
    return headers, rows


async def _bench_atomicity(memory, valkey_sweep) -> tuple[list[str], list[list]]:
    """Part 5: allowed vs theoretical for a `5/minute` bucket under an N-way burst. A fresh
    key per trial (unique per run) so no state carries between trials or runs — the Lua script
    treats a missing key as a full bucket, and a fresh in-memory bucket is full by construction.
    Theoretical = 5 + refill-in-window, which rounds to 5 for a sub-ms burst; a result above 5
    is the drift signal this part exists to surface as a number. Uses the oversized-pool client
    (SWEEP_MAX_CONNECTIONS): the question is the bucket's atomicity, not the pool's ceiling
    (Part 4c owns that)."""
    headers = ["concurrency", "backend", "allowed per trial", "theoretical"]
    rows = []
    for n in ATOMICITY_LEVELS:
        for label, backend in (("memory", memory), ("valkey", valkey_sweep)):
            counts = []
            for t in range(ATOMICITY_TRIALS):
                key = f"bench-atomic-{n}-{t}-{uuid.uuid4().hex[:6]}"
                backend.register(key, ATOMIC_SPEC)
                results = await asyncio.gather(*(backend.check(key) for _ in range(n)))
                counts.append(sum(1 for r in results if r))
            rows.append([n, label, ", ".join(str(c) for c in counts), "5"])
    return headers, rows


async def main() -> None:
    print("Rate-limit backend benchmark — in-memory vs Valkey (issue #31)")
    print(f"Concurrency sweep: {CONCURRENCY_LEVELS}, {CHECKS_PER_CALLER} checks/caller")

    url = await valkey_url()
    valkey = build_valkey_backend(url)
    # Parts 2/3 measure the lock/Lua mechanism, not the production pool ceiling — see
    # SWEEP_MAX_CONNECTIONS and Part 4c for why the sweep client is oversized.
    valkey_sweep = build_valkey_backend(url, max_connections=SWEEP_MAX_CONNECTIONS)
    memory = InMemoryBackend()
    sections: list[tuple[str, list[str], list[list]]] = []
    try:
        # No flushall on purpose: the bench's keys are prefixed (acropolis:ratelimit:) and
        # Parts 1-4 measure LATENCY (identical whether the check is allowed or denied), while
        # Part 5 uses unique per-run keys. Leftover state cannot distort any measurement, and
        # flushing db 0 of an operator-provided server is not something a bench should do.

        async def _section(title: str, headers_rows) -> None:
            headers, rows = headers_rows
            sections.append((title, headers, rows))

        await _section("Part 1 — single-check cost (memory vs Valkey, 100/second)", await _bench_single_check(memory, valkey))
        await _section("Part 2 — hot-key sweep (one bucket, 100000/second)", await _bench_hot_key(memory, valkey_sweep))
        await _section("Part 3 — cardinality sweep (one key per caller)", await _bench_cardinality(memory, valkey_sweep))
        await _section("Part 4 — degraded mode: fail-closed refusal latency", await _bench_degraded(valkey, url))
        await _section("Part 5 — atomicity as a number (5/minute bucket)", await _bench_atomicity(memory, valkey_sweep))
    finally:
        await valkey._client.aclose()  # noqa: SLF001 — the bench manages the infra it built
        await valkey_sweep._client.aclose()  # noqa: SLF001 — the bench manages the infra it built
        await stop_infra()

    md_parts = []
    for title, headers, rows in sections:
        print(f"\n{title}")
        print(markdown_table(headers, rows))
        md_parts.append(f"## {title}\n\n{markdown_table(headers, rows)}")

    path = write_results("rate-limit", "\n".join(md_parts), module="bench_rate_limit")
    print(f"\nResults written to {path} — verdict section left for review" if path else "\nSmoke mode: results not written (write_results is a no-op under --smoke)")


if __name__ == "__main__":
    asyncio.run(main())
