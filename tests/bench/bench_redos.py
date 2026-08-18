"""Benchmark harness for R5 (issue #32) — measure the ReDoS-mitigation cost before changing it.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_redos

The numbers this script prints are what issue #32's go/no-go on an re2 rewrite gets decided
on; the accepted finding is that the process-based matcher (`_match_with_timeout`) costs
~20-22ms per match and is capped at 16 concurrent matches by `_regex_semaphore`, so tail
latency degrades before throughput does under a burst.

Three measurements:

1. **Single-match cost** — `evaluate()` with one `block_patterns` param rule vs. a policy with
   no rules at all, at the same argument sizes bench_dlp.py uses. This is the added per-call
   cost when a server actually configures block patterns.
2. **Concurrency sweep** — N concurrent evaluators each performing M matches, N in
   {1, 8, 16, 24, 32, 64}. This is where the semaphore's 16-way cap shows up: at N > 16,
   requests 17+ block on the semaphore, so **p50/p99 climb while throughput flattens**.
3. **Adversarial worst case** — a genuinely catastrophic pattern (`^(a*)*\1$` against crafted
   input — chosen because re2 rejects the backreference, keeping this on the process/timeout
   path; `(a+)+$` is now matched inline by re2, see the SLOW_PATTERN_POLICY comment) driven
   through the real timeout path. Each such match costs the full 0.5s timeout plus spawn; this
   documents the degraded mode a naive thread-based fix (already rejected in-code) would
   reintroduce.

Scope note, same as bench_dlp.py's: this measures the POLICY-EVALUATION layer, not the full
tools/call path — the forkserver spawn dominates the added cost, so a full-pipeline bench
would measure the same number plus fixed overhead (auth/policy fetch/audit enqueue) that is
identical on and off. The go/no-go decision only needs the delta, and this isolates it.

Shares the stats/timing/argument machinery with the other benches via tests/bench/_harness.py
(the epic's harness issue).
"""
from __future__ import annotations

import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.policy import evaluate  # noqa: E402
from db.models import ParamRule, ServerPolicy  # noqa: E402
from tests.bench._harness import (  # noqa: E402
    iters, percentile, representative_arguments, time_call,
)

ITERATIONS = iters(100, 5)
WARMUP_ITERATIONS = iters(15, 2)
CONCURRENCY_LEVELS = (1, 8, 16, 24, 32, 64)
CONCURRENCY_ITERATIONS = iters(30, 3)
TIMEOUT_ITERATIONS = iters(8, 1)  # adversarial case is deliberately small — each run costs ~0.5s

NO_RULES_POLICY = ServerPolicy(mode="passthrough")

# One operator-configured block pattern on the tool's primary argument — the common case for a
# server that uses block_patterns at all. The pattern does NOT match the benchmark values (no
# match is the common case; the forkserver still runs the search, which is where the cost is).
WITH_BLOCK_PATTERN_POLICY = ServerPolicy(
    mode="passthrough",
    param_rules={"bench_tool": {"query": ParamRule(block_patterns=[r"^[a-z0-9 _.-]+$"])}},
)

# #112: "(a+)+$" is now compiled to re2 and matched inline in microseconds (linear-time
# guarantee), so the adversarial case must use a pattern re2 REJECTS — a backreference keeps
# it on the process/timeout path, which is what Part 3 measures. Against crafted input this
# hangs Python's re for many seconds, comfortably under the 200-char pattern cap. Driven
# through the real matcher, each evaluate() on this costs the full
# _REGEX_MATCH_TIMEOUT_SECONDS (0.5s) and returns UNDETERMINED (fail-closed -> blocked).
SLOW_PATTERN_POLICY = ServerPolicy(
    mode="passthrough",
    param_rules={"bench_tool": {"query": ParamRule(block_patterns=[r"^(a*)*\1$"])}},
)
SLOW_ARGUMENT = {"query": "a" * 31 + "b"}


async def _time_evaluate(policy: ServerPolicy, arguments: dict, iterations: int) -> list[float]:
    return await time_call(
        lambda: evaluate("bench_tool", arguments, "bench-server", policy), iterations
    )


async def _bench_single_match() -> dict:
    """Part 1: added per-match cost of one block_pattern vs. no rules, by argument size."""
    report = {"part": "single-match", "rows": []}
    for size_label in ("small", "medium", "large"):
        arguments = representative_arguments(size_label)
        arg_bytes = sum(len(str(v)) for v in arguments.values())

        # Warm up (forkserver's first spawn is meaningfully slower than steady state).
        await _time_evaluate(NO_RULES_POLICY, arguments, WARMUP_ITERATIONS)
        await _time_evaluate(WITH_BLOCK_PATTERN_POLICY, arguments, WARMUP_ITERATIONS)

        off = await _time_evaluate(NO_RULES_POLICY, arguments, ITERATIONS)
        on = await _time_evaluate(WITH_BLOCK_PATTERN_POLICY, arguments, ITERATIONS)
        report["rows"].append(
            {
                "size": size_label,
                "arg_bytes": arg_bytes,
                "no_rules_p50_ms": round(statistics.median(off), 3),
                "no_rules_p99_ms": round(percentile(off, 99), 3),
                "block_pattern_p50_ms": round(statistics.median(on), 3),
                "block_pattern_p99_ms": round(percentile(on, 99), 3),
                "added_p50_ms": round(statistics.median(on) - statistics.median(off), 3),
            }
        )
    return report


async def _bench_concurrency() -> dict:
    """Part 2: p50/p99 + throughput across concurrency levels — finds the semaphore queue
    point. Uses the SMALL argument set: it is the only one carrying the rule's `query` param
    (Part 1 proved the cost is zero when the named param is absent), so this is the only sweep
    that actually drives the forkserver. Each evaluator performs CONCURRENCY_ITERATIONS
    matches; the wall time of the whole gather gives throughput, per-match samples give
    latency. Fewer iterations than Part 1 because each match costs ~100ms here (the forkserver
    spawn) — 64 × 30 matches at 16-way parallelism is already ~12s of wall time."""
    report = {"part": "concurrency", "rows": []}
    arguments = representative_arguments("small")
    await _time_evaluate(WITH_BLOCK_PATTERN_POLICY, arguments, WARMUP_ITERATIONS)

    for n in CONCURRENCY_LEVELS:
        samples: list[float] = []

        async def _worker() -> None:
            for _ in range(CONCURRENCY_ITERATIONS):
                start = time.perf_counter()
                await evaluate("bench_tool", arguments, "bench-server", WITH_BLOCK_PATTERN_POLICY)
                samples.append((time.perf_counter() - start) * 1000)

        wall_start = time.perf_counter()
        await asyncio.gather(*(_worker() for _ in range(n)))
        wall_secs = time.perf_counter() - wall_start
        total_matches = n * CONCURRENCY_ITERATIONS
        report["rows"].append(
            {
                "concurrency": n,
                "matches": total_matches,
                "wall_secs": round(wall_secs, 2),
                "matches_per_sec": round(total_matches / wall_secs, 1),
                "p50_ms": round(statistics.median(samples), 3),
                "p99_ms": round(percentile(samples, 99), 3),
            }
        )
    return report


async def _bench_timeout_path() -> dict:
    """Part 3: the adversarial worst case — a catastrophic pattern driven through the real
    timeout path. Each match costs the full 0.5s budget. Runs at concurrency 24 to show the
    semaphore queue: 16 slots are occupied for the full timeout, the other 8 wait behind them.
    """
    report = {"part": "adversarial-timeout", "rows": []}
    await _time_evaluate(SLOW_PATTERN_POLICY, SLOW_ARGUMENT, 2)  # warm the forkserver

    for n in (4, 24):
        samples: list[float] = []

        async def _worker() -> None:
            for _ in range(2):
                start = time.perf_counter()
                await evaluate("bench_tool", SLOW_ARGUMENT, "bench-server", SLOW_PATTERN_POLICY)
                samples.append((time.perf_counter() - start) * 1000)

        wall_start = time.perf_counter()
        await asyncio.gather(*(_worker() for _ in range(n)))
        wall_secs = time.perf_counter() - wall_start
        report["rows"].append(
            {
                "concurrency": n,
                "matches": n * 2,
                "wall_secs": round(wall_secs, 2),
                "p50_ms": round(statistics.median(samples), 1),
                "p99_ms": round(percentile(samples, 99), 1),
            }
        )
    return report


def _print_report(report: dict) -> None:
    if report["part"] == "single-match":
        print(f"\nPart 1 — single-match cost ({ITERATIONS} iters, warmed)")
        print(f"{'size':<7}{'bytes':>8}{'no-rules p50/p99':>20}{'block-pat p50/p99':>22}{'added p50':>11}")
        for r in report["rows"]:
            print(
                f"{r['size']:<7}{r['arg_bytes']:>8}{f'{r['no_rules_p50_ms']}/{r['no_rules_p99_ms']} ms':>20}"
                f"{f'{r['block_pattern_p50_ms']}/{r['block_pattern_p99_ms']} ms':>22}{r['added_p50_ms']:>10} ms"
            )
    elif report["part"] == "concurrency":
        print(f"\nPart 2 — concurrency sweep ({CONCURRENCY_ITERATIONS} matches/evaluator, query-carrying args)")
        print(f"{'concurrency':>12}{'wall s':>9}{'matches/s':>12}{'p50 ms':>10}{'p99 ms':>10}")
        for r in report["rows"]:
            print(
                f"{r['concurrency']:>12}{r['wall_secs']:>9}{r['matches_per_sec']:>12}"
                f"{r['p50_ms']:>10}{r['p99_ms']:>10}"
            )
    elif report["part"] == "adversarial-timeout":
        print(f"\nPart 3 — adversarial timeout path (backref pattern vs crafted input, 0.5s budget)")
        print(f"{'concurrency':>12}{'wall s':>9}{'p50 ms':>10}{'p99 ms':>10}")
        for r in report["rows"]:
            print(
                f"{r['concurrency']:>12}{r['wall_secs']:>9}{r['p50_ms']:>10}{r['p99_ms']:>10}"
            )


async def main() -> None:
    print("R5 benchmark: ReDoS-mitigation forkserver cost (issue #32)")
    for report in (
        await _bench_single_match(),
        await _bench_concurrency(),
        await _bench_timeout_path(),
    ):
        _print_report(report)


if __name__ == "__main__":
    asyncio.run(main())
