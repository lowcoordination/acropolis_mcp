"""Benchmark harness for enterprise #10 (DLP redaction) — measures added latency per
tools/call request from DLP argument scanning, on vs off, at representative argument sizes.

Run directly (not via pytest — this is a measurement tool, not a correctness test):

    python -m tests.bench.bench_dlp

The numbers this script prints are what docs/dlp.md's "Performance" section reports. Re-run
and update that doc if argus/dlp.py's detector set or matching strategy changes materially.

Shares the stats/timing/argument machinery with the other benches via tests/bench/_harness.py
(the epic's harness issue).

Two parts. ARGUMENT scanning (evaluate(), on vs off). RESPONSE scanning (issue #165): measured,
replacing the earlier extrapolation. It runs argus.response_dlp.scan_result with all eleven
built-ins on `kubectl logs`-shaped results at 10 KB, 100 KB and 1 MB, and prints a per-detector
breakdown at 100 KB. The spec's gate (Verification 7) is 100 KB p99 <= 11 ms (2x the 5.5 ms
projection).

End to end, optionally: `--e2e http://127.0.0.1:18000 ON_SLUG OFF_SLUG` times a passthrough
tools/call through a running Acropolis to a fixture upstream whose `logs` tool returns `size`
bytes when called with {"kind": "big", "size": N}, with response DLP on (ON_SLUG) and off.
"""
from __future__ import annotations

import asyncio
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.dlp import BUILTIN_DETECTORS  # noqa: E402
from argus.policy import evaluate  # noqa: E402
from argus.response_dlp import scan_result  # noqa: E402
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

    await bench_responses()
    if "--e2e" in sys.argv:
        k = sys.argv.index("--e2e")
        await bench_e2e(*sys.argv[k + 1:k + 4])


# --------------------------------------------------------------------------- response DLP

RESPONSE_ITERATIONS = {10: iters(300, 5), 100: iters(150, 5), 1000: iters(30, 2)}

# Spec Verification 7, as revised by Amendment 1 (approved 2026-10-29). The original rule (all 11
# built-ins, 100 KB p99 <= 11 ms) came from an extrapolation that the six argument-era detectors
# alone already miss. The gate now measures the set Hephaestus's servers ship with, plus a
# linearity check that catches a pattern starting to backtrack.
SECRETS_7 = (
    "bearer_token", "jwt", "github_token", "secret_assignment", "url_credentials",
    "aws_access_key", "private_key_pem",
)
GATE_SECRETS_100KB_P99_MS = 15.0
GATE_SECRETS_1MB_MAX_MS = 150.0
GATE_ALL_LINEARITY = 12.0  # all 11: 1 MB p50 / 100 KB p50

# Budget above the largest size, so these measure scanning, not truncation.
ALL_BUILTINS_RESPONSE_POLICY = ServerPolicy(
    response_dlp_detectors={name: "redact" for name in BUILTIN_DETECTORS},
    response_dlp_max_bytes=16_777_216,
)
SECRETS_7_RESPONSE_POLICY = ServerPolicy(
    response_dlp_detectors={name: "redact" for name in SECRETS_7},
    response_dlp_max_bytes=16_777_216,
)


def kubectl_logs(n_bytes: int, seed: int = 7) -> str:
    """Log lines shaped like a Java service's `kubectl logs`: timestamps, thread names, paths,
    request ids, durations, a user email per line (pessimistic for the email detector), and a
    planted secret roughly every 100 lines."""
    rng = random.Random(seed)
    lines, size, i = [], 0, 0
    while size < n_bytes:
        if i % 100 == 99:
            line = f"2026-10-28T12:00:00.000Z WARN  [main] c.example.Db - retry dsn=postgres://app:s3cr3tpw@db:5432/items\n"
        else:
            line = (
                f"2026-10-28T12:{i % 60:02d}:{i % 60:02d}.{i % 1000:03d}Z INFO  [http-nio-8080-exec-{i % 16}] "
                f"c.example.api.ItemController - GET /api/v1/items/{rng.randint(1, 99999)} status=200 "
                f"dur={rng.randint(1, 900)}ms req_id={rng.getrandbits(64):016x} user=user{i % 50}@example.com\n"
            )
        lines.append(line)
        size += len(line)
        i += 1
    return "".join(lines)[:n_bytes]


def _tools_call_result(text: str) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}], "isError": False}}


async def _bench_response_set(label: str, policy: ServerPolicy) -> dict[int, tuple[float, float]]:
    """Returns {kb: (p50, tail)}; tail is p99 with >= 100 samples, else max."""
    print(f"\nResponse DLP: scan_result, {label}, kubectl-logs-shaped text\n")
    print(f"{'size':>8} {'iters':>6} {'p50 ms':>9} {'tail ms':>9}")
    out = {}
    for kb in (10, 100, 1000):
        message = _tools_call_result(kubectl_logs(kb * 1024))
        n = RESPONSE_ITERATIONS[kb]
        await time_call(lambda: scan_result(message, policy), iters(5, 1))
        samples = await time_call(lambda: scan_result(message, policy), n)
        tail = percentile(samples, 99) if n >= 100 else max(samples)
        out[kb] = (statistics.median(samples), tail)
        print(f"{kb:>6}KB {n:>6} {out[kb][0]:>9.2f} {tail:>9.2f}  ({'p99' if n >= 100 else 'max'})")
    return out


async def bench_responses() -> None:
    secrets = await _bench_response_set(f"secrets-7 ({', '.join(SECRETS_7)})", SECRETS_7_RESPONSE_POLICY)
    everything = await _bench_response_set(f"all {len(BUILTIN_DETECTORS)} built-ins (recorded, not gated)",
                                           ALL_BUILTINS_RESPONSE_POLICY)

    text = kubectl_logs(100 * 1024)
    print("\nPer detector at 100 KB (finditer + validator, ms per pass):")
    for name, detector in BUILTIN_DETECTORS.items():
        start = time.perf_counter()
        for _ in range(20):
            for m in detector.pattern.finditer(text):
                if detector.validator is not None:
                    detector.validator(m.group(0))
        print(f"  {name:<22} {(time.perf_counter() - start) * 1000 / 20:7.2f}")

    ratio = everything[1000][0] / everything[100][0]
    checks = [
        ("(a) secrets-7 100 KB p99", secrets[100][1], GATE_SECRETS_100KB_P99_MS, "ms"),
        ("(a) secrets-7 1 MB max", secrets[1000][1], GATE_SECRETS_1MB_MAX_MS, "ms"),
        ("(b) all-11 1 MB / 100 KB p50", ratio, GATE_ALL_LINEARITY, "x"),
    ]
    print("\nGate (spec Verification 7, Amendment 1):")
    for name, value, limit, unit in checks:
        print(f"  {name:<30} {value:8.2f} {unit} <= {limit:g} {unit} -> {'PASS' if value <= limit else 'FAIL'}")
    print(f"  overall -> {'PASS' if all(v <= l for _, v, l, _ in checks) else 'FAIL'}")


async def bench_e2e(base_url: str, on_slug: str, off_slug: str) -> None:
    import httpx

    print(f"\nEnd to end through {base_url} (passthrough tools/call, fixture upstream)\n")
    print(f"{'size':>8} {'off p50':>9} {'on p50':>9} {'added p50':>10}")
    async with httpx.AsyncClient(base_url=base_url, timeout=60) as client:
        for kb in (10, 100, 1000):
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "logs", "arguments": {"kind": "big", "size": kb * 1024}}}
            results = {}
            for slug in (off_slug, on_slug):
                async def call():
                    r = await client.post(f"/mcp/{slug}/mcp", json=body,
                                          headers={"Accept": "application/json, text/event-stream"})
                    r.raise_for_status()
                n = 40 if kb < 1000 else 10
                await time_call(call, 3)
                results[slug] = statistics.median(await time_call(call, n))
            print(f"{kb:>6}KB {results[off_slug]:>9.2f} {results[on_slug]:>9.2f} {results[on_slug] - results[off_slug]:>10.2f}")


if __name__ == "__main__":
    asyncio.run(main())
