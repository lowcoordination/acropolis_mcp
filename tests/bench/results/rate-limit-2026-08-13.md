# rate-limit — benchmark results

Measured 2026-08-13 with `python -m tests.bench.bench_rate_limit` (harness commit `bdc86b2af599ed3970ceb0f2234f682c6f214440`). Machine: framework-ai (Linux, x86_64), Python 3.14.6.

## Part 1 — single-check cost (memory vs Valkey, 100/second)

| memory p50 ms | memory p99 ms | valkey p50 ms | valkey p99 ms | added p50 ms |
| --- | --- | --- | --- | --- |
| 0.0004 | 0.0028 | 0.0484 | 0.1147 | 0.0479 |

## Part 2 — hot-key sweep (one bucket, 100000/second)

| concurrency | mem checks/s | mem p50 ms | mem p99 ms | val checks/s | val p50 ms | val p99 ms |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1139133.8 | 0.0 | 0.002 | 20314.3 | 0.048 | 0.067 |
| 8 | 1668453.9 | 0.0 | 0.001 | 23575.9 | 0.26 | 2.993 |
| 16 | 1744492.7 | 0.0 | 0.001 | 17102.1 | 0.503 | 22.843 |
| 32 | 1707577.3 | 0.0 | 0.001 | 26814.4 | 1.021 | 8.924 |
| 64 | 1785549.0 | 0.0 | 0.001 | 23127.3 | 2.019 | 23.935 |
| 128 | 1810051.5 | 0.0 | 0.001 | 25692.7 | 4.055 | 45.008 |

## Part 3 — cardinality sweep (one key per caller)

| concurrency | mem checks/s | mem p50 ms | mem p99 ms | val checks/s | val p50 ms | val p99 ms |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 734549.1 | 0.0 | 0.004 | 20221.9 | 0.047 | 0.079 |
| 8 | 1460024.7 | 0.0 | 0.001 | 29332.3 | 0.262 | 0.432 |
| 16 | 1703367.3 | 0.0 | 0.001 | 30401.3 | 0.516 | 0.637 |
| 32 | 1749593.8 | 0.0 | 0.001 | 31422.2 | 1.006 | 1.122 |
| 64 | 1774991.0 | 0.0 | 0.001 | 31743.5 | 1.978 | 2.316 |
| 128 | 1793409.4 | 0.0 | 0.001 | 32134.6 | 3.939 | 4.977 |

## Part 4 — degraded mode: fail-closed refusal latency

| case | refusals/total | p50 ms | p99 ms |
| --- | --- | --- | --- |
| closed port (connection refused) | 100/100 | 0.057 | 0.869 |
| paused container (hung connection) | 50/50 | 2002.874 | 2003.465 |
| default pool, 200-way burst (pool cap) | 100/200 | 13.08 | 70.351 |

## Part 5 — atomicity as a number (5/minute bucket)

| concurrency | backend | allowed per trial | theoretical |
| --- | --- | --- | --- |
| 8 | memory | 5, 5, 5, 5, 5 | 5 |
| 8 | valkey | 5, 5, 5, 5, 5 | 5 |
| 32 | memory | 5, 5, 5, 5, 5 | 5 |
| 32 | valkey | 5, 5, 5, 5, 5 | 5 |
| 128 | memory | 5, 5, 5, 5, 5 | 5 |
| 128 | valkey | 5, 5, 5, 5, 5 | 5 |

## Verdict

**The Valkey backend is cheap enough to recommend whenever shared-state correctness requires
it, and both backends' ceilings are far above realistic gateway rates.**

- **The swap costs ~0.05 ms per check** (Part 1: memory 0.0004 ms, Valkey 0.048 ms p50 on
  localhost) — roughly 1.5% of a ~3 ms bridged call (bench_otel's baseline). An operator
  going multi-replica pays effectively nothing per request for issue #31's correctness.
- **In-memory scales to ~1.8M checks/s with flat p50** to 128-way concurrency (Part 2/3).
  The per-bucket `asyncio.Lock` is not a bottleneck at any realistic rate.
- **Valkey's per-process ceiling is ~20-32k checks/s** with p50 growing ~linearly to ~4 ms
  at 128-way concurrency (Part 2/3) — server-serialized Lua script plus network round-trip.
  Fine for a gateway doing tens-hundreds of req/s; aggregate multi-replica behaviour is the
  load tier's question (#94).
- **Fail-closed holds, with one latency caveat** (Part 4): connection-refused fails in
  ~0.06 ms; a hung-but-connected server costs the full ~2.0 s socket budget per refusal.
  Monitoring should treat "backend hung" (not "backend down") as the expensive failure mode.
- **Atomicity verified as a number** (Part 5): a `5/minute` bucket admits exactly 5 of
  8/32/128 concurrent callers on both backends, every trial. No drift.

**Finding filed separately, not fixed here (measure, don't fix):** redis-py 8.x's async
connection pool defaults to `max_connections=100`, and `build_valkey_backend` does not
override it. Part 4c measured exactly 100 of 200 concurrent checks refused at a 200-way
burst — past ~100 concurrent rate-limited requests per process, requests fail closed
(`rule=rate_limit_backend_unavailable`) against a perfectly healthy backend. Refusals are
fast (~13 ms), so the fail-closed posture holds, but the cap is an undocumented production
ceiling. Filed as #97.

