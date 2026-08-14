# rate-limit — benchmark results

Measured 2026-08-14 with `python -m tests.bench.bench_rate_limit` (harness commit `f1beccb95448ab9d5d1cbdd0784980c5ac457559`). Machine: framework-ai (Linux, x86_64), Python 3.14.6.

## Part 1 — single-check cost (memory vs Valkey, 100/second)

| memory p50 ms | memory p99 ms | valkey p50 ms | valkey p99 ms | added p50 ms |
| --- | --- | --- | --- | --- |
| 0.0004 | 0.0012 | 0.0492 | 0.0785 | 0.0487 |

## Part 2 — hot-key sweep (one bucket, 100000/second)

| concurrency | mem checks/s | mem p50 ms | mem p99 ms | val checks/s | val p50 ms | val p99 ms |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1080894.6 | 0.0 | 0.002 | 16550.0 | 0.052 | 0.17 |
| 8 | 1656754.1 | 0.0 | 0.001 | 21157.0 | 0.269 | 3.669 |
| 16 | 1614084.7 | 0.0 | 0.001 | 17742.2 | 0.53 | 16.484 |
| 32 | 1722309.9 | 0.0 | 0.001 | 24848.2 | 1.029 | 9.644 |
| 64 | 1779371.3 | 0.0 | 0.001 | 20125.4 | 2.195 | 37.632 |
| 128 | 1713719.9 | 0.0 | 0.001 | 22129.6 | 4.448 | 51.038 |

## Part 3 — cardinality sweep (one key per caller)

| concurrency | mem checks/s | mem p50 ms | mem p99 ms | val checks/s | val p50 ms | val p99 ms |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 720346.9 | 0.0 | 0.004 | 16703.7 | 0.053 | 0.118 |
| 8 | 1575299.4 | 0.0 | 0.001 | 29105.0 | 0.27 | 0.303 |
| 16 | 1658921.4 | 0.0 | 0.001 | 29920.4 | 0.531 | 0.556 |
| 32 | 1627441.9 | 0.0 | 0.001 | 30681.8 | 1.033 | 1.132 |
| 64 | 1706646.6 | 0.0 | 0.001 | 30752.7 | 2.052 | 2.56 |
| 128 | 1755527.4 | 0.0 | 0.001 | 31302.4 | 4.065 | 4.283 |

## Part 4 — degraded mode: fail-closed refusal latency

| case | refusals/total | p50 ms | p99 ms |
| --- | --- | --- | --- |
| closed port (connection refused) | 100/100 | 0.059 | 0.976 |
| paused container (hung connection) | 50/50 | 2002.426 | 2003.243 |
| default pool, 200-way burst (pool cap) | 0/200 | 79.732 | 110.69 |

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

**Re-run for issue #97's fix. Confirms the pool-cap finding from `rate-limit-2026-08-13.md` is
resolved; every other part is unchanged within run-to-run noise.**

- **Part 4c: `default pool, 200-way burst (pool cap)` now shows 0/200 refusals**, was 100/200
  on 2026-08-13. `build_valkey_backend` now sets `max_connections=256` explicitly (was
  redis-py 8.x's unstated default of 100), so the 200-way burst — 2x the *old* cap, chosen
  deliberately to still exercise pool behaviour — now completes inside the new ceiling instead
  of hitting it. p50/p99 (79.7 ms / 110.7 ms) reflect 200 real connections opening against
  local Valkey, not refusal latency; compare against Part 4's other two rows, which measure
  genuine unavailability.
- **Parts 1, 2, 3, 5 are consistent with 2026-08-13's numbers** (same machine, same order of
  magnitude, no behavioural change) — the fix touches only pool sizing, not the token-bucket
  algorithm or atomicity.
- **256 is headroom, not a new hard ceiling.** The pool still has a cap; a deployment expecting
  routinely >250 concurrent rate-limited requests per process should raise `max_connections`
  further via `build_valkey_backend`'s `client_kwargs` and re-run this bench to confirm.
- Issue #97 closed by this fix; `docs/rate-limiting.md`'s Performance section updated to
  describe the new default instead of the bare finding.
