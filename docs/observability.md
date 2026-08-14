# Observability: metrics vs. traces

Acropolis has two complementary observability surfaces. This doc covers the newer one
(distributed tracing) and how it relates to the older one (`/metrics`).

## `/metrics`: aggregate counters, no request-level detail

`GET /metrics` (see `argus/metrics.py`) exposes Prometheus text-format counters — audit event
counts by decision over the last 24h, per-server health status, and (when GitOps is enabled) the
config-drift gauge. It answers "how many calls were blocked in the last day" and "is server X
healthy right now." It does **not** answer "where did THIS call spend its time" or "which upstream
call was slow" — that's what distributed tracing exists for.

`docs/backup-and-upgrades.md` used to say per-upstream call latency "is not currently included —
no latency sample is recorded anywhere in the request path today." **That specific claim is now
out of date and has been corrected**: every audit row carries a gateway-total `latency_ms`
(`time.monotonic()`-based, wrapping the whole request). This was NOT true for forwarded
(ALLOWED) calls until issue #99's fix — `Pipeline._enforce` built the ALLOWED audit row's fields
in a template computed before rate-limit, quota, and policy evaluation ran, so `latency_ms`
truncated to 0 for every forwarded call (found by `tests/bench/bench_pipeline.py` Part 3, whose
audit-vs-client latency cross-check exists to catch exactly this). BLOCKED/error rows were
unaffected — those paths already computed `latency_ms` at their own log call site. What was
actually missing beyond that fix is two different things: a **per-stage breakdown** of that
latency (policy eval vs. DLP scan vs. secret resolution vs. bridge handshake vs. the upstream
call itself), and **trace context** (an incoming `traceparent` was neither honored nor
propagated, making Acropolis a black hole in any client's existing distributed trace).
`latency_ms` on the audit row is not replaced by any of this; traces are a complementary,
request-shaped view of the same call, not a redundant one. Note `latency_ms` is measured up to
the audit-log call, which happens before the upstream forward completes (audit rows are written
as part of the enforcement decision, not after the proxy returns) — expect it to run somewhat
below true end-to-end client latency, not to match it exactly.

## Tracing: off by default, manual spans only

Set `ACROPOLIS_OTEL_ENABLED=true` to turn tracing on. Unset (or any falsy value), Acropolis's
behavior and dependencies are **byte-identical** to a build with this feature absent entirely —
see "True no-op when off," below.

Tracing does **not** use FastAPI/httpx auto-instrumentation. Those libraries trace every request
indiscriminately — including health-poll loops and `/metrics` scrapes — which buries the signal
in noise nobody asked for. Instead, `argus/pipeline.py` and `argus/bridge.py` open exactly six
named spans, at the points that answer real questions:

| Span | Where | When |
|---|---|---|
| `request` | `Pipeline.handle` | Every incoming `/mcp/{slug}/...` call (the root span) |
| `policy.evaluate` | `Pipeline._evaluate_with_tracing` | Every `tools/call` |
| `dlp.scan` | same, nested under `policy.evaluate` | Only when the server's policy has `dlp_detectors` or `dlp_custom_patterns` configured |
| `secrets.resolve` | `Pipeline._resolve_credential` | Only when `upstream_auth_header` is a *reference* (`vault://...`, `enc:v1:...`), never for a literal credential |
| `bridge.handshake` | `ProtocolBridge.bridge_call` | Bridged (2026-generation) calls only |
| `upstream.forward` | `ProtocolBridge.bridge_call` and `Pipeline._forward` | Every call that actually reaches an upstream (bridged or passthrough) |

Nothing else is traced. The health-poll loop (`stoa/health.py`) and the audit-retention job
(`stoa/retention.py`) are explicitly **not** instrumented — they're background maintenance, not
requests a client is waiting on, and tracing them would be exactly the kind of noise manual
instrumentation is meant to avoid.

### Span tree shape

A plain bridged `tools/call`:

```
request
├── policy.evaluate
├── bridge.handshake
└── upstream.forward
```

A DLP-configured server, same call, with a detector firing:

```
request
├── policy.evaluate
│   └── dlp.scan
├── bridge.handshake
└── upstream.forward
```

A server with a `vault://`-referenced upstream credential:

```
request
├── policy.evaluate
├── secrets.resolve
├── bridge.handshake
└── upstream.forward
```

(`secrets.resolve` happens once per request, in `_resolve_credential`, which every forwarding
path — bridged `tools/call`, passthrough forward, `tools/list` — routes through; it's drawn as a
sibling of `policy.evaluate` above, not nested under it, matching call order in the code.)

## Attribute secrecy: the same discipline as the audit log and DLP

The DLP and secret-backends features both established an invariant for the audit log: the
**matched value** (a DLP detector's match, a resolved secret) never appears in any observability
surface — only metadata about what happened (which detector, which action). This feature extends
that same invariant to spans.

**Allowed span attributes**, and nothing else:

- `acropolis.server_slug`
- `acropolis.tool`
- `acropolis.decision` (`ALLOWED` / `BLOCKED`)
- `acropolis.rule`
- `acropolis.dlp_detector`, `acropolis.dlp_action`
- `acropolis.bridged` (`true`/`false`)
- `acropolis.mcp_protocol_version`
- `http.method`, `http.status_code`

**Never allowed, under any circumstance including error paths:**

- Tool call arguments, or anything derived from them (no `args_summary`, no argument values)
- Resolved secret/credential values
- Auth header values (the client's own, or the resolved upstream one)
- Matched DLP values (the detector name and action are attributes; the matched substring never is)
- Request or response bodies

This is enforced at each call site in `argus/pipeline.py` and `argus/bridge.py` — `span()`
(`argus/tracing.py`) is a generic attribute-setting context manager with no allowlist of its own,
exactly like `AuditLogger.log()` trusts its callers rather than scrubbing values itself. The
proof is `tests/integration/test_otel_secrecy.py`'s canary test: a call carrying a memorable fake
secret **value** in a tool argument and a memorable fake **resolved credential**, with every
exported span serialized (name, attributes, event bodies, status description — not just the
attribute dict) and swept for both canary strings. Neither appears anywhere.

That file also covers the specific worry a security-scan pass on this feature would raise:
`span()`'s generic `except Exception: record_exception(...)` clause fires for ANY exception that
propagates through a `with span:` block, not just the success-path attribute-setting the other
canary tests exercise. `TestExceptionPathNeverLeaksThroughRecordedSpanException` forces a real
`SecretResolutionError` to propagate through the `secrets.resolve` span (a genuine credential
resolution failure, not a mock) and proves the recorded exception is still canary-free — provable
by construction, since `SecretResolutionError`'s message is built only from the reference string
and a static reason (see `archon/secrets/__init__.py`), never a resolved plaintext, but verified
empirically here rather than left as a code-review claim.

## `traceparent`/`tracestate` propagation: a deliberate header-policy change

`argus/headers.py` exists because header forwarding was a hardened surface (see that file's
own `HOP_BY_HOP_HEADERS` comment on the prior authorization/cookie leak). Adding trace-context
propagation to this codebase was **not** allowed to be an automatic side effect of installing a
tracing library — it's an explicit addition, with its own regression tests:

- `strip_hop_by_hop` now also strips a **client-supplied** `traceparent`/`tracestate` on the raw
  passthrough forward path (`TRACE_CONTEXT_HEADERS`, alongside `HOP_BY_HOP_HEADERS`). Before this
  feature, an inbound `traceparent` passed straight through to the upstream completely
  unmediated — not a governed feature, just an accident of `strip_hop_by_hop` being a denylist.
  That's gone: no client-supplied trace-context header ever reaches an upstream unmodified.
- The **correct** `traceparent`/`tracestate` — the gateway's own span context, correctly
  parent-chained — is re-added deliberately, and only from inside the `upstream.forward` span,
  via `TracingManager.inject_headers()`. When tracing is inactive, that method returns `{}` and
  the merge is an unconditional no-op.
- An inbound `traceparent` (if tracing is active) is parsed by `TracingManager.extract_context`
  and used as the **parent context** for the root `request` span — so a trace a calling agent
  already started continues through Acropolis, rather than starting a disconnected new one.

Tests: `tests/unit/test_headers.py` (the header-stripping unit-level guard),
`tests/integration/test_otel_propagation.py` (wire-level, via a raw-socket-capturing fake
upstream — same `_HeaderCapturingUpstream` pattern `test_security_regression.py` uses to prove
what actually crosses the wire, not what a mock recorded). That file proves both directions:
tracing disabled → no `traceparent` reaches the upstream, even if the client sent one; tracing
enabled → the trace id matches the inbound header, the span id does **not** (it's the gateway's
own, freshly generated `upstream.forward` span), and that span id is verified against the real
in-memory-exported span tree for the same call.

## Sampling

Parent-based, with a configurable ratio: `ACROPOLIS_OTEL_SAMPLE_RATIO` (default `1.0`, meaning
"trace everything"). Parent-based means a caller that already sampled its own trace **out**
(a `traceparent` with the sampled flag clear) is never force-sampled back in by Acropolis — the
ratio only applies when there's no parent sampling decision to respect. This is
`opentelemetry.sdk.trace.sampling.ParentBased(TraceIdRatioBased(ratio))`, OTel's standard
composition for exactly this policy.

## Export: standard OTLP/HTTP, standard env vars

Acropolis does not invent its own configuration for the collector endpoint. The exporter is
`OTLPSpanExporter` from `opentelemetry-exporter-otlp-proto-http`, constructed with no explicit
endpoint — it reads the **standard** OpenTelemetry environment variables itself:

- `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces-specific `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`)
- `OTEL_EXPORTER_OTLP_HEADERS` (for a collector that requires an API key/auth header)
- `OTEL_EXPORTER_OTLP_PROTOCOL`

Any standard OTLP collector — Grafana Tempo, Jaeger (with its OTLP receiver enabled), Grafana
Alloy, the vanilla `otel/opentelemetry-collector` image — works with **zero** Acropolis-specific
configuration beyond `ACROPOLIS_OTEL_ENABLED=true` plus whichever of the standard vars above your
collector needs. There is no Acropolis-specific "otel endpoint" setting anywhere in `Settings`.

Minimal example, against a local collector:

```bash
export ACROPOLIS_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
python -m argus
```

A minimal collector config that accepts this and prints what it received:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
```

```bash
docker run -p 4318:4318 -v ./otel-config.yaml:/etc/otelcol-contrib/config.yaml \
  otel/opentelemetry-collector:latest
```

## True no-op when off

The OpenTelemetry packages (`opentelemetry-api`, `opentelemetry-sdk`,
`opentelemetry-exporter-otlp-proto-http`) are **not** base dependencies — they live in the `otel`
optional-dependencies group (`pip install acropolis[otel]`, or `pip install -e ".[dev,otel]"` for
a contributor). The base install stays lean, and — this is the load-bearing claim, not just an
aspiration — a base install with `ACROPOLIS_OTEL_ENABLED=true` set but the `otel` extra genuinely
absent **starts and serves requests correctly**, logging a warning and staying inert rather than
crashing:

```
ACROPOLIS_OTEL_ENABLED=true but the 'otel' optional dependency group is not installed
(pip install acropolis[otel]) — tracing stays disabled.
```

`tests/integration/test_no_otel_installed.py` proves this the honest way: it builds a real,
throwaway virtualenv containing `acropolis[dev]` but deliberately **not** `acropolis[otel]`, then
runs the app inside that venv's own interpreter via subprocess — not a mocked `ImportError`
in-process, an actual venv where `import opentelemetry` genuinely fails. It covers both the
default case (tracing disabled, no otel installed — the common case) and the "operator flipped
the gate without installing the extra" case.

With tracing disabled (the default), `argus/tracing.py` never imports `opentelemetry` at all —
proven in `tests/unit/test_tracing.py` by making the import raise if it's ever attempted.

## Overhead benchmark

Measured with `tests/bench/bench_otel.py` (`python -m tests.bench.bench_otel`), 500 iterations
per cell, at the **same representative argument sizes `tests/bench/bench_dlp.py` uses** (small:
~36 bytes, medium: ~1KB, large: ~20KB) — a full bridged `tools/call` request through the real
Acropolis app (`request` → `policy.evaluate` → `bridge.handshake` → `upstream.forward`, 4 spans),
against a real in-process FastMCP upstream, tracing on vs. off:

```
size      arg bytes   off p50   off p99    on p50    on p99  added p50  added p99
small            36    1.969ms    3.065ms    2.089ms    2.993ms     0.120ms    -0.072ms
medium         1027    2.364ms    3.259ms    3.114ms    5.708ms     0.751ms     2.449ms
large         20415    2.718ms    5.017ms    2.313ms    4.513ms    -0.405ms    -0.504ms
```

A second run, for consistency:

```
size      arg bytes   off p50   off p99    on p50    on p99  added p50  added p99
small            36    2.828ms    4.415ms    2.950ms    4.928ms     0.121ms     0.513ms
medium         1027    2.908ms    4.893ms    2.624ms    5.075ms    -0.285ms     0.182ms
large         20415    2.643ms    4.698ms    2.273ms    3.245ms    -0.371ms    -1.452ms
```

**Takeaway: span creation/export overhead is within the noise floor of a real HTTP request** — a
handful of negative "added" numbers above are measurement jitter (the off/on runs are
sequential, not interleaved), not evidence tracing makes calls faster. Nothing here is remotely
close to being user-visible against a ~2-5ms baseline bridged-call latency.

Two things make this benchmark's "on" number a deliberately **conservative** (worst-case, never
optimistic) estimate of real production overhead:

1. **The benchmark's "on" runs use `InMemorySpanExporter` with `SimpleSpanProcessor`** —
   synchronous export, on the request's own critical path. Production (`argus/app.py`) always
   wires `BatchSpanProcessor`, which batches spans and exports them off a background thread,
   entirely outside the request path. A real deployment's per-request overhead should be lower
   than what's measured here, not higher.
2. Argument size barely moves the number (large ~20KB is not meaningfully worse than small ~36B)
   — expected, since span attributes are small, fixed-shape metadata (server slug, tool name,
   decision), never the argument payload itself (see the attribute-secrecy section above). Unlike
   DLP's argument-scanning cost, tracing overhead does not scale with argument size at all.

## Live verification

Manually verified against a real, running `otel/opentelemetry-collector` Docker container (not a
mock, not a stub) — the standard vanilla OTel Collector image, OTLP/HTTP receiver on `:4318`,
`debug` + `file` exporters — receiving traces from a real Acropolis gateway instance (real
uvicorn server on a real TCP port) forwarding to a real in-process FastMCP upstream, over real
OTLP/HTTP export (`OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`, no Acropolis-specific
config beyond `ACROPOLIS_OTEL_ENABLED=true`).

Sent one `tools/call` with an inbound `traceparent` (`00-1111...1111-2222...2222-01`). The
collector's debug exporter received **exactly 4 spans, all sharing trace id
`11111111111111111111111111111111`** (matching the inbound header):

| Span | Parent ID | Own ID |
|---|---|---|
| `request` | `2222222222222222` (the CLIENT's span id — proves the root span honored the inbound traceparent) | `6804919e488e3bd0` |
| `policy.evaluate` | `6804919e488e3bd0` (the `request` span) | `f68f5751461308cc` |
| `bridge.handshake` | `6804919e488e3bd0` (the `request` span) | `6b24030cb3a685db` |
| `upstream.forward` | `6804919e488e3bd0` (the `request` span) | `5a87afac32bcc0bb` |

This confirms end-to-end trace stitching against a real collector: correct trace-id continuity
from the client's own traceparent, correct parent-chaining of every span under the root, and
correct span attributes (`acropolis.server_slug=live-check`, `acropolis.decision=ALLOWED`,
`acropolis.mcp_protocol_version=2025-06-18`, `http.status_code=200`, etc. — no argument values,
no credentials).

**What this verification does and does not prove**, stated honestly (matching the standard the
secret-backends PR set for its OpenBao verification): this used the vanilla
`otel/opentelemetry-collector` image with a `debug`+`file` exporter pipeline, inspected via the
collector's own log output — not a full trace-visualization backend (Tempo/Jaeger/Grafana UI).
The wire protocol, span shape, attribute content, and parent-chaining are the things that could
plausibly be wrong in this feature, and all of them were verified against a real collector
process actually receiving real OTLP/HTTP traffic over the network. What was *not* separately
verified is a specific downstream backend's own trace-visualization UI (e.g. clicking through a
trace in Tempo's or Jaeger's web UI) — since OTLP is a standardized wire protocol and the
collector accepted and correctly parsed the spans, there's no Acropolis-specific reason to expect
a specific UI to render them differently, but that specific rendering step was not the thing
exercised here.

## Connection pool sizing (asyncpg)

Acropolis talks to Postgres through two **separate** asyncpg pools (see `db/database.py`):
a reader pool and a writer pool. They are independent budgets, sized separately, and this is
deliberate — reads and writes have different concurrency profiles on the request path, and
separating them means a write-heavy burst cannot starve reads (or vice versa).

### Defaults and the reasoning behind them

| Pool | Default max | Why |
|---|---|---|
| Reader | 10 | Most of the request path is reads; the reader pool is the one under real traffic. |
| Writer | 5 | Writes on the request path are minimal and atomic (usage rollup upserts); the audit log is not a per-request write at all (see below). |

Both are configurable via `ACROPOLIS_DB_READER_POOL_MAX` / `ACROPOLIS_DB_WRITER_POOL_MAX`
(`archon/settings.py`, wired through `argus/__main__.py`).

### What actually touches the pool per request

The audit log does **not** consume a pool slot per request: `argus/audit.py` enqueues to an
`asyncio.Queue` and a background task flushes batched inserts every 100ms or 200 events,
whichever comes first. The realistic `tools/call` hot path is roughly **three reads on the
reader pool** (API-key verification, server policy, and — only for keys that have a quota
configured — the quota `total_since` lookup), plus one writer-pool usage-rollup upsert.
That makes the default reader pool of 10 comfortably sufficient for the vast majority of
deployments; the "5+ queries per request, audit write per request" framing from the August 2026
external review does not hold against the code (the review's correction record lives in
`docs/remediation-2026-08-antigravity-review.md`).

### When and how to raise the limits

The signal that the defaults are too small is **queueing, not errors**: asyncpg callers wait
for a free connection, so the symptom is rising p50/p99 latency on `tools/call` while Postgres
itself shows low CPU and plenty of idle capacity (i.e. the bottleneck is the pool, not the
database). Raise `ACROPOLIS_DB_READER_POOL_MAX` first — it is the pool on the hot path.

One caution if you run multiple replicas: each replica opens its own reader+writer pools, so
total connections scale with replica count. Keep `N × (reader + writer)` under your Postgres
`max_connections`.

Also switch the rate limiter to its shared backend before adding replicas — the default
in-memory backend gives each replica its own copy of every limit, multiplying the effective
limit by the replica count. See [rate limiting](rate-limiting.md).

### Why there is no read-through cache for server/policy config

A read-through cache for `ServerRepo`/`get_policy` was **considered and rejected** for now:
policy evaluation is a security-enforcement path, and a cache introduces a staleness window
between "operator changed the policy" and "enforcement honors it." The pool is the cheaper and
safer lever — at the concurrency levels this project targets, three reads on a 10-connection
pool is not the constraint, and caching enforcement state would buy throughput at the cost of
correctness. Revisit only if measurement shows pool queueing that sizing cannot fix.
