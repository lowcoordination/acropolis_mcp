"""Benchmark harness for enterprise #10 (DLP redaction) — measures added latency per
tools/call request from DLP argument scanning, on vs off, at representative argument sizes.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_dlp

The numbers this script prints are what docs/dlp.md's "Performance" section reports. Re-run
and update that doc if argus/dlp.py's detector set or matching strategy changes materially.

Shares the stats/timing/argument machinery with the other benches via tests/bench/_harness.py
(the epic's harness issue).

Scope note: this measures ARGUMENT scanning only, matching the PR's scope (see docs/dlp.md).
The "extrapolated response-scanning cost" section applies the same per-KB scanning rate to
response-sized payloads to produce the honest, documented finding behind the decision to defer
response scanning to a future, benchmark-gated PR — it does not benchmark a real response-body
scanning implementation, because none exists yet.
"""
from __future__ import annotations

import asyncio
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.policy import evaluate  # noqa: E402
from db.models import DlpCustomPattern, ServerPolicy  # noqa: E402
from tests.bench._harness import (  # noqa: E402
    iters, percentile, print_latency_table, representative_arguments, time_call,
)

ITERATIONS = iters(300, 5)
WARMUP_ITERATIONS = iters(20, 2)

NO_DLP_POLICY = ServerPolicy(mode="passthrough")

# Built-in detectors only — curated, fixed-at-deploy-time patterns matched directly (not via
# the forkserver), see argus/dlp.py's _scan_value_with_detector. This is the cost profile most
# servers will actually see, since custom_patterns is an explicit additional opt-in.
BUILTIN_DETECTORS_POLICY = ServerPolicy(
    mode="passthrough",
    dlp_detectors={
        "credit_card": "redact",
        "email": "redact",
        "us_ssn": "redact",
        "aws_access_key": "redact",
        "private_key_pem": "redact",
        "high_entropy_string": "redact",
    },
)

# Adds ONE operator-supplied custom pattern on top of the built-ins — every custom pattern
# match is routed through _match_with_timeout's forkserver process-spawn machinery (F2's
# ReDoS-safe path), which has a fixed ~20ms+ per-spawn cost documented in argus/policy.py.
# Benchmarked SEPARATELY from the builtin-only case because this cost is dominated by spawn
# overhead, not argument size — conflating the two would misattribute a fixed forkserver tax to
# "DLP scanning cost" in general, when it's specifically the custom-pattern (untrusted regex)
# path's cost.
WITH_CUSTOM_PATTERN_POLICY = ServerPolicy(
    mode="passthrough",
    dlp_detectors=dict(BUILTIN_DETECTORS_POLICY.dlp_detectors),
    dlp_custom_patterns=[
        DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="redact"),
    ],
)


async def _time_evaluate(policy: ServerPolicy, arguments: dict, iterations: int) -> list[float]:
    return await time_call(
        lambda: evaluate("bench_tool", arguments, "bench-server", policy), iterations
    )


async def _bench_one(size_label: str, policy: ServerPolicy) -> dict:
    arguments = representative_arguments(size_label)
    arg_bytes = sum(len(str(v)) for v in arguments.values())

    # Warm up (forkserver's first spawn is meaningfully slower than steady state — see
    # argus/policy.py's module comment on forkserver overhead).
    await _time_evaluate(NO_DLP_POLICY, arguments, WARMUP_ITERATIONS)
    await _time_evaluate(policy, arguments, WARMUP_ITERATIONS)

    off_samples = await _time_evaluate(NO_DLP_POLICY, arguments, ITERATIONS)
    on_samples = await _time_evaluate(policy, arguments, ITERATIONS)

    return {
        "size_label": size_label,
        "arg_bytes": arg_bytes,
        "off_p50": statistics.median(off_samples),
        "off_p99": percentile(off_samples, 99),
        "on_p50": statistics.median(on_samples),
        "on_p99": percentile(on_samples, 99),
    }


async def main() -> None:
    print(f"DLP argument-scanning benchmark — {ITERATIONS} iterations per cell\n")

    builtin_results = []
    custom_results = []
    for size_label in ("small", "medium", "large"):
        builtin_results.append(await _bench_one(size_label, BUILTIN_DETECTORS_POLICY))
        custom_results.append(await _bench_one(size_label, WITH_CUSTOM_PATTERN_POLICY))

    print_latency_table(
        f"{len(BUILTIN_DETECTORS_POLICY.dlp_detectors)} built-in detectors only (no custom_patterns — "
        "no forkserver spawn)",
        builtin_results,
    )
    print_latency_table(
        f"built-ins + 1 custom_pattern (forkserver-routed, F2 ReDoS-safe path)",
        custom_results,
    )

    # Extrapolation for the response-scanning deferral decision (see docs/dlp.md). Uses the
    # BUILT-IN-ONLY "large" cell's added-latency-per-KB as the scanning rate (the realistic
    # profile most servers run — custom patterns are an explicit opt-in with a fundamentally
    # different, spawn-dominated cost shape that doesn't scale with payload size the same way)
    # and projects it out to representative response payload sizes. This is a projection from
    # argument-scanning measurements, NOT a benchmark of an actual response-scanning
    # implementation — flagged explicitly here and in the doc so the number is never mistaken
    # for a real measurement.
    large = builtin_results[-1]
    added_p99_per_kb = (large["on_p99"] - large["off_p99"]) / (large["arg_bytes"] / 1024)
    print("\nExtrapolation for response-scanning cost (NOT a real benchmark — see docs/dlp.md):")
    print(f"  (based on built-in-detector-only scanning rate: {added_p99_per_kb:.4f}ms added p99 per KB)")
    for response_kb in (10, 100, 1000):
        projected_ms = added_p99_per_kb * response_kb
        print(f"  {response_kb:>5} KB response -> ~{projected_ms:.2f}ms added p99 (projected)")


if __name__ == "__main__":
    asyncio.run(main())
