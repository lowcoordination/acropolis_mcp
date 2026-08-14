# load-multi-replica — benchmark results

Measured 2026-08-13 with `python -m tests.bench.bench_load` (harness commit `f1beccb95448ab9d5d1cbdd0784980c5ac457559`). Machine: framework-ai (Linux, x86_64), Python 3.14.6.

## Part 1 — multi-replica rate-limit verification

Configured 100/minute SHARED across 2 replicas; window 30s, 25 workers/replica.

| replica | allowed (2xx) | refused (429) | other |
| --- | --- | --- | --- |
| replica :5591 | 79 | 12556 | 0 |
| replica :5592 | 70 | 12435 | 0 |
| AGGREGATE | 149 | 24991 | 0 |

## Part 2 — connection-churn profile (hey)

```

Summary:
  Total:	2.1163 secs
  Slowest:	0.0474 secs
  Fastest:	0.0021 secs
  Average:	0.0106 secs
  Requests/sec:	4725.2587
  
  Total data:	150000 bytes
  Size/request:	15 bytes

Response time histogram:
  0.002 [1]	|
  0.007 [13]	|
  0.011 [9136]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.016 [0]	|
  0.020 [0]	|
  0.025 [0]	|
  0.029 [0]	|
  0.034 [0]	|
  0.038 [30]	|
  0.043 [734]	|■■■
  0.047 [86]	|


Latency distribution:
  10%% in 0.0074 secs
  25%% in 0.0076 secs
  50%% in 0.0078 secs
  75%% in 0.0080 secs
  90%% in 0.0089 secs
  95%% in 0.0399 secs
  99%% in 0.0428 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0000 secs, 0.0000 secs, 0.0018 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:	0.0000 secs, 0.0000 secs, 0.0010 secs
  resp wait:	0.0094 secs, 0.0020 secs, 0.0439 secs
  resp read:	0.0012 secs, 0.0001 secs, 0.0349 secs

Status code distribution:
  [200]	10000 responses




```
## Part 3 — cross-process rollup correctness

| measure | value | vs | expected | match | ? |
| --- | --- | --- | --- | --- | --- |
| usage_rollups delta | 500 | expected | 500 | match | yes |

## Verdict

**The replicas>1 rate-limit claim (issue #86) is verified empirically — and cross-process
rollup accounting is exact.**

- **Aggregate enforcement confirmed (Part 1).** 100/minute shared across two replicas →
  **149 allowed over a 30s window** from a full bucket (≈ 100 + 30s × 1.667/s refill ≈ 150).
  Per-replica enforcement would have produced ~300. The Valkey backend's shared bucket does
  exactly what #31/#86 promise: the aggregate is the configured limit, not 2× it.
- **Connection-churn profile (Part 2).** 10,000 requests at **4,725 req/s** against
  /api/v1/health, p50 7.8 ms / p99 42.8 ms, all 200 — a healthy single-replica HTTP envelope
  on this machine. (hey cannot drive the MCP path: its fixed `-d` body can't vary JSON-RPC
  ids and the streamable-http upstream keys response streams by rpc id — documented in
  bench_load's docstring; the MCP parts use a Python worker with unique ids.)
- **Cross-process rollup exactness (Part 3).** 500 known calls split across both replicas →
  usage_rollups delta **exactly 500**. The atomic upsert holds across two live app processes —
  test_postgres_races.py's SQL-level claim, verified at the HTTP level.

**Caveats (house-style honesty):** one machine, one compose stack; absolute numbers are this
devbox's envelope. This tier is a verification gate for the SHARED-STATE claims (rate-limit
aggregate, rollup exactness) — capacity and per-feature deltas are bench_pipeline's per-release
baseline, not this.

**Incidental change:** the Dockerfile now installs the `distributed` extra (redis) — the
deployment image previously lacked it and would fail at boot with
`ACROPOLIS_RATE_LIMIT_BACKEND=valkey`, the documented multi-replica configuration.

