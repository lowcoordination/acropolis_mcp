# Audit and Compliance

Acropolis maintains two separate audit logs, each serving a distinct purpose:

## 1. Data-Plane Audit (`audit.db`)

**What it records:** Every tool call through the gateway — which tool was called, what the policy decided, which API key was used.

**Volume:** High (every proxied request).

**Retention:** 30 days by default, configurable via `audit_retention_days`. Pruned by the background `AuditRetentionJob`.

**Purpose:** Traffic analysis, debugging, understanding agent behavior.

### Local execution decisions

Not every row in the data-plane log came over HTTP. `POST /api/v1/policy/evaluate` (see [the
policy cookbook](policy-cookbook.md#evaluating-a-call-without-making-it)) lets a local agent
guard ask whether a proposed command would be blocked *before* it runs, and each answer is
recorded here. Two columns distinguish those rows:

| Column | Gateway traffic | Local evaluation |
|---|---|---|
| `endpoint` | `per-server`, `aggregate` | `policy-evaluate` |
| `origin` | `NULL` (real traffic), `test` (Try-it) | `local:…` |

### The `origin` scheme

`origin` is `<class>` or `<class>:<detail>` — the class is everything before the first colon:

| Value | Meaning |
|---|---|
| `NULL` | real gateway traffic |
| `test` | admin "Try it" tool tester |
| `local:<key-name>` | a local evaluation |
| `local:<key-name>/<harness>@<host>` | …with a caller-asserted harness and host |

**The derived half comes first, and the caller cannot influence it.** `<key-name>` is the
gateway's own record of which API key was presented. The `<harness>@<host>` suffix *is* asserted
by the caller — the gateway is HTTP-remote from the agent harness and cannot observe either; it
sees only a `client_ip`, which is already its own column. So a forged assertion always sits next
to a derived prefix that contradicts it. That is what keeps "the record that proves enforcement
wasn't silently lowered and raised back" honest for local rows: you can always tell which
credential actually asked, whatever the caller claims about itself.

Assertions are validated at the API boundary (422 on failure, never silently rewritten) with a
charset that excludes `:`, `/`, `@`, whitespace and newlines, so they cannot forge extra
structure.

### Filtering

`GET /api/v1/audit?origin_class=gateway|local|test` filters on the class, so "every local
evaluation" doesn't require enumerating the key names and hostnames in the detail half. The same
parameter works on `/audit/export.csv`, and the Audit page has a matching control. An unknown
class is a `400`, not an empty result — a typo should not read as "no such traffic".

The older `include_test=true` still works but is superseded: it has only two states (everything,
or real traffic only) and its name is now misleading, since it widens to *every* non-NULL origin
rather than only Try-it calls.

Because `origin` is non-NULL for both, evaluations and Try-it calls are excluded from `/stats`
automatically. An evaluation is a question, not traffic. Retention treats these rows exactly like
any other data-plane row (30 days by default, prunable), and rows predating the column render
normally with `origin` NULL — no backfill needed.

> `origin` values are **not** a stable API contract, and there is no CHECK constraint on the
> column. Treat the *class* as the stable part; the detail half may gain fields.

**Known gap (#125):** `args_summary` redacts argument values by **key name**. A secret inline in a
command string (`--from-literal=password=hunter2`) is truncated at 120 characters but **not**
redacted, so it can appear in a data-plane audit row. This is true of any `tools/call` carrying
the same argument, not only of evaluations — but a local guard sends command strings on every
call, so it meets the gap far more often.

## 2. Control-Plane Audit (`gateway.db`)

**What it records:** Administrative actions — server created/updated/deleted, policy changed, API key minted/disabled/revoked, settings modified, config imported.

**Volume:** Low (human-initiated changes only).

**Retention:** **Never pruned.** These are the compliance records an auditor wants.

**Purpose:** Answering "who changed what, and when" — the record that proves enforcement wasn't silently lowered and raised back.

## Why two logs?

The data-plane log is documented as expendable — you can lose 30 days of traffic history and still operate. The control-plane log is the opposite: it's the record that matters when you're asked "did anyone disable the allowlist last Tuesday?"

Keeping them separate means:
- `audit.db` can be treated as ephemeral (backup docs tell operators to prioritize `gateway.db`).
- The control-plane log isn't silently destroyed by the 30-day retention window.
- A `gateway.db` restore brings its own change history with it.

## What gets recorded

| Action | Target | Summary example |
|--------|--------|---------------|
| `server.create` | server | `created server 'shell'` |
| `server.update` | server | `updated server 'shell' (name: Old -> New)` |
| `server.delete` | server | `deleted server 'shell'` |
| `server.secret_reference_change` | server | `credential externalized to a reference` (enterprise #5 — see [docs/secrets.md](secrets.md); never the value, on either side of the change) |
| `policy.update` | server | `mode: allowlist -> passthrough; denied 4 -> 0 tool(s)` |
| `key.create` | key | `created API key 'ci-automation'` |
| `key.disable` | key | `disabled API key 'ci-automation'` |
| `key.delete` | key | `deleted API key 'ci-automation'` |
| `settings.update` | settings | `updated settings (auth_mode: keyed -> open)` |
| `config.import` | config | `import applied: 3 change(s); updated server 'x'; ...` |

## Secret exclusion

The `before`/`after` JSON columns only ever contain **allowlisted fields** — never secrets:

- `upstream_auth_header` is never recorded (it's a live plaintext credential, or — since
  enterprise #5 — potentially a reference; the VALUE is withheld either way, see
  [docs/secrets.md](secrets.md)). Only `server.secret_reference_change`'s dedicated event records
  that this field changed, as a shape classification only (configured? a reference?), never the
  string itself.
- `webhook_secret`, `admin_password_hash`, `session_secret` are never recorded.

This is enforced by `_filter_server_fields()` and `_filter_settings_keys()` in `archon/admin_audit.py`, which enumerate what MAY be recorded rather than what may NOT.

## Querying

```bash
# All admin events
GET /api/v1/admin-events

# Filter by action
GET /api/v1/admin-events?action=server.update

# Filter by target type
GET /api/v1/admin-events?target_type=settings

# Since a timestamp
GET /api/v1/admin-events?since=2026-08-01T00:00:00+00:00
```

## The `actor` column

Currently records the **source** of the change:
- `admin-session` — someone logged into the web UI
- `admin-token` — the static automation/CI token
- `cli` — a direct database write (rare)

After the identity milestone (Enterprise #1), this will carry a real user ID.

## Config imports are one event

A config import that creates 3 servers and updates 9 policies writes **one** `admin_events` row summarizing the operation, not 12 individual rows. This keeps the log legible.
