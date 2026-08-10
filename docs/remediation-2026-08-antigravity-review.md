# Remediation Plan — August 2026 external architecture review

Tracks remediation of the five findings raised in an external ("antigravity") architectural
review of Acropolis, after each was verified against the code. **Two findings were confirmed as
genuine gaps, one was confirmed as a real but lower-priority cost, one was found to be already
fixed, and one was confirmed as a deliberate, correctly-documented trade-off.**

This document is the reference for the issues that implement it. Each issue links back to its
section here rather than restating the analysis.

## Verification summary

| # | Finding as filed | Verified verdict | Action |
|---|---|---|---|
| 1 | In-memory rate limiting blocks horizontal scaling | **Confirmed**, but the review missed that the deploy manifest gates it — with a now-stale reason | R1 (urgent, 1 line) + R4 (deferred) |
| 2 | Envelope encryption has no key rotation | **Confirmed** — no rotation tooling exists anywhere | R2 |
| 3 | Subprocess ReDoS mitigation is expensive under load | **Cost confirmed**, but the proposed fix would reintroduce the bug it replaced | R5 (measure first) |
| 4 | 5+ DB queries per request may exhaust the pool | **Largely incorrect** — miscounts queries; pool limits already configurable | R3 (docs only) |
| 5 | Four auth tiers risk authorization drift | **Confirmed but overstated** — one removable tier, drift vector already closed | R6 (low) |

### Corrections to the review's premises

These matter because two of the review's recommendations were aimed at problems that do not
exist as described.

- **Quotas are not in-memory.** `argus/quotas.py` is pure period-boundary math; enforcement in
  `Pipeline._check_quota` reads `UsageRepo.total_since` from Postgres. Quotas already survive
  multi-replica deployment. Only the rate limiter holds process-local state.
- **Audit logging is not a per-request query.** `argus/audit.py` is an `asyncio.Queue` with a
  background batched-INSERT flush task; `log()` only does `await self._queue.put(event)`. It
  never touches the connection pool on the request path.
- **Reads and writes do not share a pool.** `db/database.py` creates separate reader
  (default max 10) and writer (default max 5) pools, so "exhaust pool connections" conflates
  two independent budgets.
- **Pool sizes are already configurable.** `db_reader_pool_max` / `db_writer_pool_max` exist in
  `archon/settings.py:31-32` and are wired through in `argus/__main__.py:29-30`. The review's
  recommendation here is already implemented.
- **The event loop is not blocked by regex matching.** `_wait_executor` in `argus/policy.py` is
  a dedicated `ThreadPoolExecutor` created specifically so the blocking `queue.get` cannot
  starve asyncio's shared default executor. The cost is latency and process churn, not
  event-loop starvation.

---

## R1 — Correct the stale scaling constraint in the k8s manifest

**Priority: urgent. Size: 1 line. Blocks: nothing. Do this first.**

### Problem

`deploy/k8s/deployment.yaml:9` reads:

```yaml
replicas: 1  # SQLite-backed; don't scale beyond 1 replica without moving to a shared DB first
```

The stated justification became false at commit `29077e3`, which replaced SQLite with Postgres
entirely. The constraint is still correct, but **its documented reason is now provably
satisfied** — a reader who checks the claim will find a shared DB in place, conclude the
constraint has lifted, and scale up.

Scaling up is what actually triggers finding #1: `RateLimiterRegistry` in
`argus/rate_limiter.py:63` is a process-local `dict[str, TokenBucket]` with no shared backing.
With N replicas each holding a full bucket, the effective limit becomes N× the configured value,
and which limit a given client experiences depends on load-balancer routing.

This one-line comment is currently the only control preventing a live rate-limit bypass. It is
higher-urgency than the distributed rate limiter itself (R4), which is a much larger change.

### Fix

Replace the stale reason with the true one, and name the tracking issue:

```yaml
replicas: 1  # Rate limiting is process-local (argus/rate_limiter.py) — scaling past 1 replica
             # multiplies every configured limit by the replica count. See R4 / issue #N.
```

### Acceptance criteria

- [ ] Comment states the rate limiter, not SQLite, as the constraint
- [ ] Comment references the R4 tracking issue
- [ ] `deploy/k8s/README.md` grep'd for the same stale SQLite claim; corrected if present

---

## R2 — Multi-key decryption for the `encrypted` secret provider

**Priority: highest substantive item. Size: medium. Depends on: nothing.**

### Problem

`archon/secrets/encrypted.py` supports exactly one key:

- `PREFIX = "enc:v1:"` is a fixed module constant (line 53)
- `build_key_source()` returns a single `KeySource` (env var, then file, then hard failure)
- `EncryptedSecretProvider.__init__` builds one `AESGCM` instance from that one key
- `resolve()` raises `SecretResolutionError` on `InvalidTag` — correctly fail-closed

Verified: **no rotation tooling exists.** No migration in `db/migrations/`, no re-encryption
script, no `rotate` symbol anywhere outside unrelated `archon/oidc.py` and `archon/settings.py`.

The consequence is worse than "rotation is manual." Rotating `ACROPOLIS_SECRET_KEY` does not
fail at rotation time — the app starts fine, because construction only validates key *length*.
It fails later, per-server, at the next outbound call, as a `SecretResolutionError` surfacing as
an ERROR audit decision. An operator can believe rotation succeeded and discover otherwise only
when upstream calls start failing.

For a gateway whose value proposition is credential custody, this is the gap most likely to be
hit during a real incident: key rotation is precisely what you do *after* a suspected
compromise, when you can least afford every stored upstream credential to become undecryptable.

**Note on the review's framing:** it described `v1` as a missing key ID. That is not quite right
— the module docstring explicitly reserves `v1` as a *format* version, so a future v2 (new KDF,
new AEAD, KMS-wrapped DEK) can still decrypt v1 ciphertext by dispatching on the prefix. That
design is sound and should be preserved. The gap is the absence of *multiple keys*, not a
confused version scheme.

### Fix

Keep the format version exactly as it is. Add a key **ring** behind the existing `KeySource`
seam (line 64), which was built for this:

1. Introduce a key-ring resolver: an ordered list of decryption keys plus one designated active
   key for writes. Source it from a new `ACROPOLIS_SECRET_KEYS` / `ACROPOLIS_SECRET_KEYS_FILE`
   (plural), keeping the existing singular env vars working as a one-key ring for compatibility.
2. `store()` always encrypts with the **active** key only.
3. `resolve()` tries the active key first, then each remaining decryption key in order, and
   raises `SecretResolutionError` only when **all** fail. Preserve the existing "never
   distinguish wrong-key from corrupted-ciphertext" message discipline.
4. Add an operator-facing re-encryption command that walks stored credentials, decrypts via the
   ring, and re-encrypts under the active key — making rotation completable rather than
   permanent dual-key operation.
5. Document the rotate → deploy-with-both-keys → re-encrypt → drop-old-key sequence in
   `docs/secrets.md`.

Do **not** change the ciphertext format in this issue. A key-ID-in-prefix scheme (`enc:v2:...`)
is a possible later optimization to avoid trial decryption; it is not needed for correctness and
would expand scope considerably.

### Acceptance criteria

- [ ] Multiple decryption keys configurable; exactly one active for writes
- [ ] Existing single-key env vars keep working unchanged (compatibility test)
- [ ] Existing `enc:v1:` ciphertext decrypts under a ring containing its key
- [ ] All-keys-fail still raises `SecretResolutionError`, fail-closed, message unchanged
- [ ] Re-encryption command covered by a test that rotates and verifies every credential
- [ ] Threat-model docstring at the top of `encrypted.py` updated — it must not overclaim
- [ ] `docs/secrets.md` documents the full rotation runbook

---

## R3 — Document the connection-pool sizing guidance

**Priority: low. Size: docs only. Depends on: nothing.**

### Problem

The review's claim of "5+ asyncpg queries per MCP tool call" that could "exhaust pool
connections" does not hold — see the corrections above. Audit logging is queued and batched, the
quota check is skipped entirely for keys without a quota configured, and reader/writer pools are
separate. The realistic hot path is roughly three reads on the reader pool.

The residual, legitimate observation is that a **default reader pool max of 10 is modest**. At
~3 reads per request, on the order of three concurrent in-flight requests can saturate it, after
which requests queue for a connection. That is a tuning consideration for high-throughput
deployments.

The review recommended exposing pool sizes as configuration. **This is already done** —
`db_reader_pool_max` / `db_writer_pool_max` in `archon/settings.py:31-32`, wired in
`argus/__main__.py:29-30`. No code change is required.

### Fix

Documentation only. Add a short operational note covering:

- What the defaults are and the reasoning behind them
- The approximate per-request reader-pool cost (~3 reads on the `tools/call` path)
- That audit writes are queued and batched, so they do not consume a pool slot per request
- Which settings to raise, and the signal that indicates you should

Explicitly record that a read-through cache for server/policy config was **considered and
rejected** for now: it introduces staleness on a security-enforcement path, and the pool is the
cheaper and safer lever until measurement shows otherwise.

### Acceptance criteria

- [ ] Pool-sizing guidance added to `docs/observability.md` (or a new operations section)
- [ ] Note explicitly corrects the "5+ queries, audit write per request" misconception
- [ ] Caching rejection and its reasoning recorded

---

## R4 — Distributed rate limiting (deferred until horizontal scaling is real)

**Priority: medium, deferred. Size: large. Depends on: R1 landing first.**

### Problem

`RateLimiterRegistry` (`argus/rate_limiter.py:61-106`) holds all state in a process-local dict.
`TokenBucket.consume` is atomic *within* a process via `asyncio.Lock`, which is correct for
single-replica operation and deliberately stricter than the quota path's accepted TOCTOU (see
the extended note in `Pipeline._check_quota`).

Across replicas there is no shared state, so every replica enforces the full configured limit
independently.

### Why this is deferred rather than urgent

The failure requires `replicas > 1`, which the deployment manifest currently forbids. R1 makes
that prohibition state its real reason. Until horizontal scaling is actually on the roadmap,
R1 is the control and this is the follow-up.

### Fix (when scheduled)

1. Extract a `RateLimitBackend` interface from the existing registry; make the current dict
   implementation the default `InMemoryBackend` so single-replica behaviour is bit-for-bit
   unchanged.
2. Add a Redis/Valkey backend implementing the token bucket as an atomic server-side Lua script
   — the refill-and-consume must be one atomic operation, matching the `asyncio.Lock` guarantee
   the in-memory version provides.
3. Decide and **document** the backend-unavailable posture explicitly. This is the key design
   decision: fail-open matches the quota path's soft-control precedent, fail-closed matches the
   `block_pattern` UNDETERMINED precedent. These conflict, so it must be a deliberate, written
   choice rather than an accident of implementation.
4. Re-evaluate the quota TOCTOU note in `Pipeline._check_quota` under multi-replica assumptions.
   Its "bounded overshoot" reasoning is currently justified for single-process concurrency;
   multiplying by replica count needs re-justification, not silent inheritance.
5. Only then relax `replicas: 1`, and update R1's comment again.

### Acceptance criteria

- [ ] Backend interface extracted; in-memory remains the default and is behaviourally unchanged
- [ ] Redis/Valkey backend refills and consumes atomically
- [ ] Backend-unavailable posture chosen, implemented, and documented with rationale
- [ ] Multi-replica test demonstrating a shared limit holds across processes
- [ ] Quota TOCTOU note re-reviewed for multi-replica
- [ ] `replicas: 1` constraint relaxed only as the final step

---

## R5 — Measure the ReDoS mitigation's cost before changing it

**Priority: medium. Size: small (measurement); large only if a rewrite is justified.**

### Problem

Policy evaluation runs each `block_pattern` in a forkserver child process with a hard timeout
(`argus/policy.py`, `_match_with_timeout`). The self-documented cost is ~22ms per call, bounded
by a 16-way semaphore and a dedicated 16-thread wait pool. Under a burst, request 17+ blocks on
the semaphore, so **tail latency degrades before throughput does**. The cost is real and the
finding is fair.

### Why the review's recommendation must not be applied as written

The review proposed either re2 bindings **or** "pre-validated regex AST complexity checks."

- The **AST-analysis half is unsound.** Deciding whether an arbitrary pattern backtracks
  catastrophically is not reliably answerable by static inspection. A heuristic that is wrong
  once reintroduces exactly the hang this machinery exists to prevent.
- The comment block at `argus/policy.py:22-31` records that a **thread-based timeout was tried
  and does not work**, because CPython's `re` does not release the GIL while matching — the
  timeout's own callback is starved. Any replacement must clear that bar empirically.
- The current design **fails closed** on `UNDETERMINED` (`_check_param`), which was itself the
  fix for a confirmed fail-open bypass under concurrent load. Any replacement must preserve
  this posture.

`re2` (or `regex` with a native timeout) is the viable direction, because linear-time matching
removes the need for a timeout at all. But this only pays off if the cost is actually being felt.

### Fix

Measure first, in this order:

1. Benchmark the `tools/call` path with and without `block_patterns` configured, at
   realistic concurrency, to quantify the added p50/p99 and the semaphore queueing point.
2. Establish how many real deployments configure `block_patterns` at all — the cost is zero for
   servers that do not.
3. Only if the measured impact justifies it, prototype an re2-backed matcher behind the existing
   `_match_with_timeout` interface, keeping the process-based path as fallback for patterns re2
   rejects (it does not support backreferences or lookaround).
4. Preserve fail-closed `UNDETERMINED` semantics in any implementation.

### Acceptance criteria

- [ ] Benchmark exists and is reproducible; results recorded in the issue
- [ ] Explicit go/no-go decision on re2, with the measurement as justification
- [ ] If implemented: fail-closed posture preserved, and the GIL finding re-verified, not assumed
- [ ] If not implemented: the measurement is recorded in `policy.py` so this is not re-litigated

---

## R6 — Retire the legacy session auth tier

**Priority: lowest. Size: small. Depends on: a data condition, not code.**

### Problem

`archon/admin_auth.py:require_admin` has four entry paths (documented at lines 59-74):
admin-token bearer, user-bearing session cookie, legacy user-less session cookie, and the
first-run window.

The review's risk framing is overstated:

- All paths converge on a single `Principal` return type, and `role` is **always** populated —
  the docstring at lines 24-27 explains this was done specifically so no route ever
  special-cases a missing role. That is the primary drift vector, and it is closed by design.
- The paths are ordered and mutually exclusive; the legacy path is reachable only when
  `user_id is None or user_repo is None` (line 116).
- Path 4 is the bootstrap window, not legacy debt. It cannot be removed.
- Path 1 is the documented break-glass override. It should not be removed.

So exactly **one** tier is retirable — path 3 — and only once every live session cookie carries
a `user_id`.

### Fix

1. Add a diagnostic (admin API field or CLI check) reporting whether any legacy user-less
   session could still be valid — i.e. whether `users` is populated and the global
   `session_version` has been bumped since the identity migration.
2. Once the condition is met, remove path 3 and `_LEGACY_ADMIN_PRINCIPAL`'s legacy-session use,
   keeping it for the first-run window if still referenced.
3. Bump `session_version` as part of the removal so any surviving legacy cookie is invalidated
   rather than silently rejected with a confusing error.

### Acceptance criteria

- [ ] Diagnostic reports legacy-session reachability
- [ ] Path 3 removed only after the diagnostic reports it unreachable
- [ ] `session_version` bumped in the same change
- [ ] Break-glass (path 1) and first-run (path 4) paths untouched and still tested

---

## Build order

R1 first and immediately — it is one line and is the only thing currently preventing finding #1
from being live. R2 next; it is the highest real risk and depends on nothing. R3 is a
docs-only cleanup that can land any time. R5's measurement can run in parallel with R2 since it
is investigation, not implementation. R4 is gated on horizontal scaling actually being planned.
R6 is gated on a data condition and is the lowest value of the six.

```
R1 ──► (unblocks nothing, but must land before R4 is meaningful)
R2 ──► independent, highest priority
R3 ──► independent, docs only
R5 ──► investigation, parallel with R2
R4 ──► after R1; only when multi-replica is actually planned
R6 ──► after the legacy-session diagnostic reports unreachable
```
