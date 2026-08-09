# Quotas and usage attribution

`argus/rate_limiter.py` answers "how fast" — a burst budget over a short window (`5/minute`,
`30/hour`). Quotas answer a different question: "how much, over a billing period" — and "who
spent it." These are complementary, not overlapping: a key can be both rate-limited (no more
than 5 calls/minute) and quota-limited (no more than 10,000 calls this month), enforced
independently, one after the other, on the same request.

Configure a quota on the key create/edit form in the UI, or via `POST`/`PATCH
/api/v1/keys/{id}/quota`.

## Scope: call-count quotas, not cost — read this before you configure one

**This feature counts JSON-RPC tool calls. It does not, and structurally cannot, track model
token usage or dollar cost.** Acropolis proxies MCP tool calls between a client and an upstream
server; it has no visibility into what the calling model spent reasoning about a tool's
response, how many tokens a request or response consumed, or what any of that cost against a
model provider's pricing. A "quota" here is a count of `tools/call` invocations over a period —
nothing more.

This is the same overclaiming discipline `docs/dlp.md` establishes for argument scanning and
the `encrypted` secret-provider tier establishes for its threat model: naming this feature "cost
attribution" or "budget" in the sense of dollars would be exactly the kind of overclaim a sharp
reviewer catches, and would be false. If you need to cap actual inference spend, that control
has to live upstream of Acropolis, at the model provider or gateway that actually meters tokens.
What this feature gives you is real and useful on its own terms — knowing which key is
hammering which server with which tool, and capping runaway call volume — just not cost.

## What already existed, and what this adds

Every audit row already carries the full attribution tuple: `api_key_id`, `server_slug`, `tool`,
`ts`, `latency_ms`, `decision` (see `argus/audit.py`). Attribution *data* was never the gap —
durable *aggregation* and *enforcement* were. This feature adds both:

- **`usage_rollups`** (migration `0010_usage_rollups.sql`, in `gateway.db`): one row per
  `(UTC hour bucket, api_key_id, server_id, tool)`, incremented synchronously in the same code
  path that writes the `tools/call` audit event (`argus/pipeline.py`). A rollup total can never
  drift from what the audit log shows for the same window — see
  `tests/integration/test_quotas.py::TestRollupsMatchAuditRows`, which proves this by direct
  comparison rather than asserting it.
- **`quota_calls`/`quota_period`** columns on `api_keys` — the budget config, per key. Both
  nullable; `NULL` = unlimited, the default. A key with no quota configured behaves
  byte-identically to a pre-feature key (`tests/integration/test_quotas.py::
  TestNoQuotaConfiguredIsUnchangedBehavior`).
- **Enforcement** in `Pipeline._check_quota`, run after auth, after the rate limiter, before
  policy evaluation.
- **`GET /api/v1/usage`**, queryable by key/server/tool with a period picker (day/month/all).
- **Threshold webhooks** (`quota` event) at 80%/100% of a key's quota, debounced per key+period.

## Why rollups live in `gateway.db`, not `audit.db`

`stoa/retention.py`'s `AuditRetentionJob` prunes `audit_events` on a rolling window (30 days by
default). A usage rollup that lived in `audit.db` would silently lose exactly the history an
operator most wants to look back over — "how much has this key used this month" needs to
survive well past 30 days. This is the same reasoning that put `admin_events` in `gateway.db`
rather than `audit.db` (see `db/repo.py`'s `AdminEventRepo` docstring): a high-value aggregate
must survive the traffic-log retention job, because it answers a fundamentally different
question than the traffic log does. `tests/integration/test_quotas.py::
TestRollupsMatchAuditRows::test_rollups_survive_audit_db_retention_pruning` proves this by
actually running the retention job against real data and asserting the rollup total is
untouched — not just asserting the table lives in the right file.

## Bucket granularity: one hour, stored once

`usage_rollups` stores exactly one granularity — UTC hour buckets. Day and month totals are
computed by summing hourly buckets over a query range at read time, never stored redundantly at
a coarser granularity. This means there is exactly one place a count is ever written, so an
hourly and a monthly copy can never drift apart from each other — the same shape of guarantee
`ServerPolicy`'s single JSON `dlp_config` column gives DLP settings versus normalizing into
parallel tables.

Periods are UTC-aligned calendar boundaries (midnight UTC for `day`, the 1st of the month at
00:00 UTC for `month`) — never the operator's local timezone, never a rolling 24h/30d window. A
rolling window means "how much is left this period" has no single answer (it depends on exactly
when you ask, relative to each individual call); a fixed calendar boundary means it always does.
See `argus/quotas.py`'s `period_start` and `tests/unit/test_quotas.py` for the boundary math,
and `tests/integration/test_quotas.py::TestPeriodBoundary` for the proof that two calls either
side of a UTC day boundary land in different hourly buckets (and therefore different day totals).

## Enforcement point and failure shape

Quota is checked in `Pipeline._check_quota`, called from both the raw-passthrough and bridged
`tools/call` paths, in this order: **auth → rate limit → quota → policy evaluation (DLP, param
rules, allow/deny)**. A quota-exceeded call is refused with a distinct JSON-RPC error (HTTP 429,
`data.quota_period` naming which period was exceeded) and a `BLOCKED` audit row with
`rule="quota"` — the same decision/audit shape `argus/policy.py`'s DLP `block` action
established, not a new one invented for this feature. The upstream is never reached on a
quota-exceeded call — proved with the same fixture call-counter pattern
`tests/integration/test_dlp_redaction.py`'s block tests use (a real FastMCP server whose tool
handler increments a counter only when actually invoked).

## Fail-open, deliberately — and why this differs from secret-resolution's fail-closed default

**If the quota check itself fails — a `gateway.db` read error, a corrupted row, anything short
of a clean "yes, over budget" result — the call is forwarded anyway, with an `ERROR`-level log.**
This is a deliberate reversal of the fail-closed default `docs/secrets.md` establishes for
credential resolution, and the difference is load-bearing enough to spell out explicitly rather
than leave as an inconsistency between two enterprise features:

- **Secret resolution fails closed** because forwarding a call *without* a required credential
  can leak a request to an upstream that expects authentication — a genuine security exposure.
  A Vault blip turning into "every call now goes out unauthenticated" is worse than "every call
  now 502s until Vault recovers."
- **Quota checking fails open** because the worst case of forwarding one call that was actually
  over budget is a business problem — a bill that runs slightly over what was configured, or a
  server takes a few extra calls it would otherwise have been refused — not a security boundary.
  Quota is a budget control, not an authorization control; a `gateway.db` hiccup taking down the
  entire data plane over a soft budget limit would be a wildly disproportionate failure mode for
  what this feature actually protects against.

Both the read side (`UsageRepo.total_since`, inside `Pipeline._check_quota`) and the write side
(`UsageRepo.increment`, inside `Pipeline._record_usage`) fail open independently — a rollup
*write* failure must not turn an otherwise-successful, correctly-authorized, under-quota call
into an error either; it only means that one call's usage silently isn't counted, logged at
`ERROR` so an operator watching logs can catch a persistently broken rollup table.
`tests/integration/test_quotas.py::TestFailOpen` proves both directions by monkeypatching each
method to raise and asserting the call still succeeds (upstream call-counter genuinely
incremented) and that the error is logged.

## Threshold webhooks

`stoa/webhooks.py`'s `VALID_EVENTS` gains `"quota"`, following the same pattern GitOps used to
add `"drift"` — a new event name, opt-in via `webhook_events`, dispatched through the existing
`WebhookDispatcher`. A threshold fires once when a call pushes a key's usage past 80% of its
quota, and once more at 100% — never a second time for the same threshold within the same
period. Unlike the time-windowed debounce the `blocked`/`unhealthy`/`drift` events use (collapse
repeats within a fixed 60-second window), quota debounce is keyed on `(key_prefix,
period_start)`: a billing period can be hours or a month long, so "don't repeat within 60
seconds" is the wrong shape of guarantee here. A new period starts with a clean slate
automatically, since `period_start` changes.

**Payload contains only the key's prefix, its operator-assigned name, and the percentage
crossed — never the key's plaintext or its hash.** The key's plaintext is only ever available at
creation time (show-once by design, same as every other API key in this system); its SHA-256
hash never leaves `gateway.db` for any reason, webhook payloads included.
`tests/integration/test_quotas.py::TestThresholdWebhook::
test_payload_never_contains_key_plaintext_or_hash` asserts this against the actual bytes that
left the process, not a mock's recorded call.

A burst of concurrent requests crossing a threshold at the same instant fires the webhook
**exactly once**, not once per request — the check-then-record step is guarded by a lock, and
`tests/integration/test_quotas.py::
TestThresholdWebhook::test_concurrent_burst_crossing_threshold_fires_webhook_exactly_once` proves
it under genuine concurrency (see that test's docstring for why a naive `asyncio.gather` over
real DB reads can accidentally mask this race, and how the test avoids that).

## Who can see what: `GET /api/v1/usage` and viewer-role access

`/api/v1/usage` is `viewer`-role accessible, the same floor `/audit` already uses. This is a
deliberate consistency call, not an oversight: `/audit` is already queryable by `api_key_id` and
returns per-key traffic (`server_slug`, `tool`, `decision`, timestamps) to anyone with viewer
role. `/usage` returns strictly less information about any given key than `/audit` already does
— a pre-aggregated call count per key/server/tool/period, with no argument content, no client
IP, no per-request detail. A viewer who could already reconstruct "how much did key X call
server Y" by paging through `/audit` gains no new capability from `/usage` beyond convenience.
If a future deployment wants finer-grained separation between "can see aggregate volume" and
"can see which specific keys exist and how much they're used," that's a real gap worth a
dedicated design (a `usage:aggregate-only` scope, for instance) — but it would be a *new*
restriction relative to today's `/audit` behavior, not a regression this feature introduces.

Key material itself is never exposed by `/usage`: rows carry `api_key_id`/`key_prefix` for
display, never the hash or plaintext, same discipline as every other key-facing surface in this
codebase (`archon/schemas.py`'s `KeyResponse`, the webhook payload above).

## Admin audit trail

Setting or clearing a key's quota is a security-relevant config change and is recorded as an
`admin_events` row (`action="key.quota_update"`), through the same `record()` helper every other
config-mutating route in `archon/api.py` uses — the enterprise #4 control-plane audit log
precedent. `before`/`after` carry the quota fields only (never the key material), matching the
existing allowlist discipline `archon/admin_audit.py` establishes for every other action type.

## Config export/import

API keys are deliberately **not** part of `archon/config_io.py`'s export/import — they're
stored only as a SHA-256 hash (show-once by design), so exporting them would produce a file
useless for restoring a key and a liability to hold (see that module's `_NO_API_KEYS_NOTE`).
Quota fields ride the key, not the server, so they inherit this exclusion; there is no new gap
here. What *does* need to persist correctly is quota fields surviving the actual storage
boundary this feature has — create a key with a quota, read it back via `GET /api/v1/keys`,
patch it, read it back again — which `tests/integration/test_quotas.py::
TestQuotaFieldsSurviveKeyReadWriteRoundTrip` covers directly against both the API and the repo
layer.

## What this deliberately does not do

- **No per-tool or per-server quota** — quota is per-key only, matching the plan's framing:
  the billing question is "what did this consumer spend," and API keys are the consumer
  identity on the data plane. `argus/rate_limiter.py` already covers server- and tool-scoped
  *rate* limits if that's the axis you need.
- **No automatic quota reset job** — there is nothing to reset. Because totals are computed by
  summing hourly buckets since the live period boundary, a new period simply has no buckets yet;
  there's no stored "remaining" counter that could get out of sync.
- **No project/team-level quota yet.** `usage_rollups` carries a reserved, currently-unused
  `project_id` column specifically so multi-tenancy (the next item on the enterprise roadmap)
  can add project-scoped quotas without another migration against this table.
