"""Benchmark harness for enterprise #10 (DLP redaction) — measures added latency per
tools/call request from DLP argument scanning, on vs off, at representative argument sizes.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_dlp

The numbers this script prints are what docs/dlp.md's "Performance" section reports. Re-run
and update that doc if argus/dlp.py's detector set or matching strategy changes materially.

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
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.policy import evaluate  # noqa: E402
from db.models import DlpCustomPattern, ServerPolicy  # noqa: E402

ITERATIONS = 300
WARMUP_ITERATIONS = 20

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


def _representative_arguments(size_label: str) -> dict:
    """Argument shapes meant to be representative of real tool calls, not adversarial —
    ordinary text with no DLP matches at all, since that's the common case a false-positive-
    averse feature must stay cheap for."""
    filler = (
        "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet, consectetur "
        "adipiscing elit. "
    )
    if size_label == "small":
        # A typical short tool call — e.g. a file path or a short search query.
        return {"query": "find all TODO comments in the repo", "limit": 20}
    if size_label == "medium":
        # A paragraph-sized argument — e.g. a code review comment or a chat message tool arg.
        return {"message": filler * 10, "channel": "general"}  # ~730 chars
    if size_label == "large":
        # A large single argument — e.g. a full file being written or a long document.
        return {"content": filler * 200, "path": "/tmp/report.txt"}  # ~14.6 KB
    raise ValueError(size_label)


async def _time_evaluate(policy: ServerPolicy, arguments: dict, iterations: int) -> list[float]:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        await evaluate("bench_tool", arguments, "bench-server", policy)
        samples.append((time.perf_counter() - start) * 1000)  # ms
    return samples


def _percentile(samples: list[float], pct: float) -> float:
    return statistics.quantiles(samples, n=100)[int(pct) - 1] if len(samples) >= 100 else max(samples)


async def _bench_one(size_label: str, policy: ServerPolicy) -> dict:
    arguments = _representative_arguments(size_label)
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
    print(f"DLP argument-scanning benchmark — {ITERATIONS} iterations per cell\n")

    builtin_results = []
    custom_results = []
    for size_label in ("small", "medium", "large"):
        builtin_results.append(await _bench_one(size_label, BUILTIN_DETECTORS_POLICY))
        custom_results.append(await _bench_one(size_label, WITH_CUSTOM_PATTERN_POLICY))

    _print_table(
        f"{len(BUILTIN_DETECTORS_POLICY.dlp_detectors)} built-in detectors only (no custom_patterns — "
        "no forkserver spawn)",
        builtin_results,
    )
    _print_table(
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
