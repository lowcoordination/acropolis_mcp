# Refactor inventory — `argus/`, `db/`, `stoa/`

Survey date: 2026-08-12. Scope: 7,595 lines across three packages
(`argus` 4,143 · `db` 2,393 · `stoa` 1,059).

Motivation: the codebase has grown feature-by-feature (enterprise items #5–#11, two review
rounds, a Postgres cutover) without a consolidation pass. Issue #46 was a symptom — a defensive
guard written once, never revisited, silently wrong for three years of falsy ids.

Findings are ordered by **severity × blast radius**, not by size. Each says what to do and,
where relevant, what NOT to do.

**Tracked as issues #48–#56, sequenced in epic #57.**

| Finding | Issue |
|---|---|
| F1 `AuditLogger.stop()` unbounded await | [#48](../../issues/48) |
| F2 extract `BackgroundLoop` base | [#49](../../issues/49) |
| F3 strip review archaeology | [#51](../../issues/51) |
| F4 document the two forwarding paths | [#50](../../issues/50) |
| F5 dedupe enforcement prelude | [#52](../../issues/52) |
| F6 pair audit-log + response helpers | [#53](../../issues/53) |
| F7 move two record models | [#54](../../issues/54) |
| F8 document `os.environ` exceptions | [#55](../../issues/55) |
| F9 audit bare `except Exception` | [#56](../../issues/56) |

---

## F1 — `AuditLogger.stop()` can hang shutdown indefinitely  · **BUG, fix now**

`argus/audit.py:34-43` is the one background-task `stop()` of six that does **not** bound its
await:

```python
self._flush_task.cancel()
try:
    await self._flush_task          # unbounded
except asyncio.CancelledError:
    pass
self._flush_task = None
await self._flush_batch()           # unbounded DB write, also in the shutdown path
```

Every sibling — `stoa/health.py`, `retention.py`, `proposals.py`, `gitops.py`, `webhooks.py` —
uses `await asyncio.wait_for(self._task, timeout=5.0)` with a `TimeoutError` branch that logs
and abandons. `health.py`'s comment states the reason directly: under real uvicorn shutdown with
in-flight MCP sessions, cancellation has been observed to stall well past instant.

Blast radius is larger than it looks: `audit.stop()` is awaited in `argus/app.py:277`, and
everything after it in the `finally` block — `http_client.aclose()`, the secret provider's
`aclose()`, `tracing.shutdown()` — is blocked behind it.

**Fix:** adopt the sibling shape, and bound `_flush_batch()` too (it is a DB write during
shutdown, exactly when the pool may be contended).

**This is the strongest argument for F2.** The pattern was correct in five places and wrong in
the sixth because it was hand-copied six times.

---

## F2 — Six hand-rolled copies of the same background-task lifecycle  · **high value**

`stoa/health.py`, `stoa/retention.py`, `stoa/proposals.py`, `stoa/gitops.py`,
`stoa/webhooks.py`, `argus/audit.py` each independently implement:

```python
self._task: asyncio.Task | None = None
def start(self):  if self._task is None: self._task = asyncio.create_task(self._loop())
async def stop(self): cancel → wait_for(5.0) → except CancelledError/TimeoutError → None
```

They have already drifted (F1). Four are near-byte-identical; `gitops` adds `_started` plus HTTP
cleanup, `webhooks` adds queue unsubscribe and debounce-task cleanup.

**Do:** extract a small `PeriodicTask` / `BackgroundLoop` base (or mixin) owning
`start`/`stop`/cancel-with-timeout, with a `_loop()` hook and an overridable `_on_stop()` for the
extra teardown `gitops`/`webhooks` need.

**Don't:** force the debounce-task management in `webhooks.py` into the base. It is genuinely
different; leave it in the subclass.

Removes ~90 lines and makes the next timeout fix land in one place.

---

## F3 — Review-artifact comments as archaeology  · **high value, low risk**

106 comments across the three packages carry markers like `F13 fix (review 2026-08-04)`,
`§26 fix`, `Enterprise #9`, `F2/F10 fix`. Prose is **~31% of the codebase**, and in the worst
spots the ratio inverts entirely:

| File | lines | prose % |
|---|---|---|
| `db/database.py` | 310 | 43.5% |
| `db/repo.py` | 1,789 | 38.6% |
| `argus/policy.py` | 387 | 34.9% |
| `argus/app.py` | 386 | 32.9% |
| `argus/pipeline.py` | 964 | 30.9% |

`_check_rate_limits` (`pipeline.py:631`) is the specimen: **33 lines of comment before 4 lines
of code**, narrating three superseded implementations.

The distinction that matters:

- **Keep** comments explaining *why the current code is the way it is* and what breaks if
  changed — the SECURITY notes in `headers.py`, the fail-open rationale in `_check_quota`, the
  forkserver choice in `policy.py`, the `AppStatus.should_exit` note in the FastMCP fixture.
  These encode knowledge that is expensive to rediscover.
- **Cut** narration of what the code *used to* do and which review round changed it. Git holds
  that, and it is stale the moment the code moves.

**Do:** strip the review-round framing, keep the invariant. `F8 fix (review 2026-08-04): this
used to be X — a bucket was built once and never refreshed…` becomes `Re-register only when the
spec string changed: always-register would reset consumed state and defeat rate limiting.`

**Don't:** mass-delete comments. This needs judgment per comment; a scripted strip would destroy
the load-bearing ones. Budget it as a real pass over ~5 files, not a regex.

---

## F4 — Two forwarding paths, unnamed and asymmetric  · **high value**

`Pipeline._forward` (passthrough, streams via `StreamingResponse` + `BackgroundTask(r.aclose)`)
and `ProtocolBridge.bridge_call` (bridged, buffers and re-envelopes) handle the same conceptual
job with different semantics. Which one a request takes is decided at `pipeline.py:349` by
`detect_client_generation`, which keys on the presence of the `Mcp-Method` header
(`argus/generation.py:24`).

Nothing names this. Reading `pipeline.py` top-to-bottom, `_forward` looks like *the* forwarding
path — the bridge branch is easy to miss. **This cost a full probe cycle during the #46 hunt**
(instrumented `_forward`, reproduced the hang, got zero hits), and the issue carried a wrong
explanation of the branch condition for half a day.

**Do:** document the fork at the top of `_process` — a short block naming both paths, the
deciding header, and the behavioral differences (streaming vs buffered, response-header
filtering vs re-enveloping). Add `bridged` to the tracing/log context so a request's path is
visible in observability rather than inferred.

**Don't:** merge them. They are legitimately different (one proxies bytes, one translates
protocol generations). The problem is discoverability, not duplication.

---

## F5 — `Pipeline._process` and `_handle_bridged` duplicate the enforcement ordering  · **medium**

Both implement auth → rate limit → quota → policy → record-usage, separately
(`pipeline.py:376-407` and `pipeline.py:532-561`), each with its own `_record_usage` call — six
call sites total. Both carry a comment asserting the ordering is "non-negotiable", which is
precisely the kind of invariant that should be structural rather than commented twice.

They have already drifted: the bridged path passes `bridged=True` to `_audit.log`, the
passthrough path does not, and the `dlp_redacted_arguments` re-serialization exists only in
`_process`.

**Do:** extract the common prelude into one `_enforce(...)` returning either a blocking
`Response` or an enforcement result, called by both. The paths diverge *after* enforcement,
which is exactly where the split should be.

**Don't:** attempt this before F4 is documented — merging the shared part is much safer once the
two paths are explicitly named.

---

## F6 — 12 hand-built JSON-RPC error responses  · **medium**

`pipeline.py` constructs `Response(content=rpc_error(...), status_code=N,
media_type="application/json")` twelve times, and `_audit.log(...)` is called 13 times in
`pipeline.py` plus 5 in `aggregate_pipeline.py`, each repeating the same six-to-ten keyword
arguments.

**Do:** a small `_blocked(rpc_id, message, *, status, rule, ...)` helper that logs the audit row
and returns the response together — they are always paired, and pairing them structurally makes
"blocked without an audit row" unrepresentable.

**Don't:** over-abstract into a generic response factory. Two or three named helpers matching the
actual decision shapes (blocked / error / refused) beat one parameterized builder.

---

## F7 — Record models split across two modules  · **low**

`db/models.py` holds 9 model classes; `AdminEventRecord` (`db/repo.py:1159`) and
`ProposalRecord` (`db/repo.py:1612`) live in the repo module beside their repos.

**Do:** move both to `db/models.py` for one obvious home.

**Don't:** treat this as urgent. It is tidiness, not risk — and `db/repo.py`'s `_PoolAccess`
base with 11 focused repos is otherwise **the best-factored part of the codebase**. Leave that
structure alone.

---

## F8 — Environment reads outside `Settings`  · **low**

`archon/settings.py` centralizes ~20 settings, but `argus/tracing.py:52,260` and
`archon/secrets/encrypted.py:100,123,126` read `os.environ` directly.

Both have defensible reasons (tracing must decide before the SDK loads; the secret provider
bootstraps before settings exist), so this is **documentation, not relocation**: note at each
site why it bypasses `Settings`, so the next reader does not "fix" it into a circular import.

---

## F9 — 14 bare `except Exception` handlers  · **low, audit only**

Spread across the three packages. Several are deliberate fail-open behavior with logging
(`_check_quota`, `_record_usage`) and are correct and documented. Others may be silent.

**Do:** one pass confirming each either logs with `exc_info=True` or has a comment explaining the
swallow. **Don't:** convert them wholesale to typed exceptions — the fail-open ones are load-
bearing, and narrowing them would change data-plane behavior under DB trouble.

---

## Suggested sequencing

1. **F1** — real bug, ~10 lines, fix independently and immediately.
2. **F4** — pure documentation, zero behavioral risk, and it de-risks F5.
3. **F2** — mechanical, well-tested by existing lifecycle tests, and prevents F1 recurring.
4. **F3** — the big readability win; do it file-by-file, highest prose-ratio first.
5. **F5**, **F6** — real code motion in the hottest path; do them last, with the burst test and
   full suite green before and after each.
6. **F7**, **F8**, **F9** — opportunistic.

Each step should end with the full suite (`764 passed, 7 skipped` as of `11ee267`) and the #46
burst test run 10× consecutively, since that test is the codebase's best concurrency canary.

## Explicitly not recommended

- **Splitting `db/repo.py`** despite being the largest file. It is 11 cohesive repos on a shared
  base; the size is inherent to the schema, and splitting adds import churn for no clarity gain.
- **Merging the two forwarding paths** (see F4).
- **A framework-level rewrite of the pipeline.** The enforcement ordering is correct and
  well-tested; the problems here are duplication and discoverability, not architecture.
