# Postgres

Acropolis requires Postgres (enterprise #7, issue #8) — there is no SQLite fallback and no
embedded default. This page covers what you need to run it: getting an instance, the connection
string, pool sizing, minimum version, and backup/restore.

## Getting a Postgres instance

Three ways, in order of how most people will actually run this:

- **`docker compose up`** (the [quickstart](quickstart.md) path). `deploy/docker-compose.yml`
  bundles a `postgres:17-alpine` service and wires `ACROPOLIS_DATABASE_URL` for you — set
  `ACROPOLIS_DB_PASSWORD` in a `.env` file next to the compose file (there is no default; compose
  refuses to start without it, deliberately, so you can't end up running a real deployment on a
  copy-pasted throwaway password) and everything else follows.
- **A managed instance** (RDS, Cloud SQL, or equivalent) if you're deploying to Kubernetes or
  anywhere else outside `docker compose`. See [deploy/k8s/README.md](../deploy/k8s/README.md) —
  the k8s manifests deliberately don't bundle a Postgres StatefulSet; point
  `ACROPOLIS_DATABASE_URL` at whatever you run.
- **A Postgres you already run** elsewhere on your network (another container, a bare-metal
  install) — same connection string requirement either way.

## `ACROPOLIS_DATABASE_URL`

Standard `postgresql://` DSN:

```
postgresql://acropolis:password@host:5432/acropolis
```

If it's unset (or the app can't reach it), you'll see `DatabaseNotConfiguredError` at boot —
that's the intended fail-loud behavior (see `db/database.py`'s docstring): a misconfigured data
store must not present as an empty-but-working gateway.

## Splitting the workload across databases (issue #108)

Both options below are **opt-in** — unset, everything shares `ACROPOLIS_DATABASE_URL` exactly as
before, byte-for-byte.

### `ACROPOLIS_AUDIT_DATABASE_URL` — a separate audit store

The audit log (`audit_events`) is the one genuinely high-churn table: a row per proxied call,
plus periodic batched retention `DELETE`s. Pointing it at its own Postgres database lets you put
it on storage sized for churn while keeping the config store small and heavily backed up, keeps
retention pruning's I/O off the instance serving policy lookups on the request path, and lets the
two be backed up on different schedules (a config dump is small and precious; the audit log is
large and time-boxed by `audit_retention_days`). This is the opt-in revival of the pre-cutover
split, where `gateway.db` and `audit.db` were separate SQLite files (see `db/migrations/0001_init.sql`'s
header for the history and the one-database decision this option restores the choice about).

How it works:

- On startup, Acropolis runs a small, dedicated migration sequence on the audit database
  (`db/migrations/audit/0001_audit_init.sql`), creating `audit_events` and its indexes with their
  own `schema_migrations` bookkeeping — the same forward-only, advisory-lock-protected runner the
  config database uses. The audit database needs no other schema.
- Every audit read and write routes through `AuditRepo` (the `AuditLogger` queue-flush, `/stats`,
  `/metrics`, the Audit page, and the retention job), which targets the audit store when it's
  split. No SQL crosses the two stores — project-scoped audit queries resolve their slug set in
  Python and pass it as an IN-list.
- If the audit store is down, `/metrics` and `/stats` degrade gracefully (issue #109): the
  audit-derived counters/fields are omitted or nulled while the config-sourced gauges keep
  rendering, and the request path is unaffected (audit logging is queued and non-blocking).

**For a NEW deployment**: point `ACROPOLIS_AUDIT_DATABASE_URL` at a fresh database and the audit
schema is created there on first boot. Done.

**For an EXISTING deployment with audit history**: the switch moves the audit log wholesale —
from the moment the env var is set, new rows land in the new database and the config store's old
`audit_events` table (still created by migration 0001, now inert) is no longer queried. To keep
history, `pg_dump -t audit_events` from the old database and `pg_restore` it into the new audit
database **before** switching, then flip the env var. This change deliberately does not automate
the move — a data migration between live databases is an operator decision, not something an env
var should trigger implicitly.

### `ACROPOLIS_READER_URL` — a read replica

The reader/writer pool split (see pool sizing below) always had a seam for pointing `reader` at a
read replica; this env var is that seam made real. The reader pool (which serves every read on the
request path — key lookup, policy fetch, audit queries, `/stats`, `/metrics`) connects to this DSN
instead of the primary when set; all writes stay on the primary.

The control-plane write paths that RETURN the row they just wrote use read-your-writes semantics
(`db/repo.py`'s `_fetch_written_row`): they read the fresh row back from the write connection, so
a replica lagging behind the primary can never make a just-created/updated record look missing or
stale. The replica must have the schema — a real replica replicates DDL from the primary
automatically; if you're testing with a manually-provisioned replica, point the migration runner
at it once first. Reads that happen much later than the write (the `/stats`, `/metrics`, audit
page queries) can see replica lag by nature; that is the point of a replica, and the tradeoff
that lets read traffic off the primary.

## Minimum Postgres version

**Postgres 12+.** The schema uses `GENERATED ALWAYS AS IDENTITY` (standard since PG 10) and a
session-scoped advisory lock (`pg_advisory_lock`, available since PG 9.1) for coordinating
concurrent migrations across instances (`db/database.py`'s `_apply_migrations`) — nothing here
needs a recent feature. The test suite and CI both run against `postgres:17-alpine`
(`tests/conftest.py`), and the bundled compose service matches that version, so 17 is what's
actually verified end-to-end; anything 12+ should work but hasn't been exercised the same way.

## Connection pool sizing

Two separate pools, sized independently (`db/database.py`):

| Pool | Default max | Env var |
|---|---|---|
| Writer | 5 | `ACROPOLIS_DB_WRITER_POOL_MAX` |
| Reader | 10 | `ACROPOLIS_DB_READER_POOL_MAX` |

Each running instance opens up to `writer_max + reader_max` connections — if you run more than
one replica, keep `replica_count × (writer_max + reader_max)` comfortably under Postgres's own
`max_connections` (default 100 on a stock install).

> **Before running more than one replica:** rate limiting is process-local
> (`argus/rate_limiter.py`), so every replica enforces its own independent copy of each
> configured limit. Postgres removed the *database* reason to cap replicas at 1; it did not
> remove this one. See `deploy/k8s/README.md` and
> [issue #31](https://github.com/lowcoordination/acropolis_mcp/issues/31).

**What actually hits these pools per request**: an external architecture review claimed 5+
sequential queries per tool call could exhaust the pool under load. Verified against the code,
that overstates it — audit logging is queued, not synchronous on the request path (`log()` does
a `queue.put`, not a blocking write), and a quota-configured key skips straight through when no
quota is set. The real hot path is closer to **~3 reads per call**. At that rate the default
reader pool (max 10) comfortably covers several concurrent requests before saturating — a reader
pool of 10 is modest, not undersized, for the traffic this app actually generates per call. Raise
`ACROPOLIS_DB_READER_POOL_MAX` if you're running at genuinely high concurrency (many simultaneous
tool calls against one instance), not as a routine tuning step.

## Backup and restore

See [Backups, restores, and upgrades](backup-and-upgrades.md) — `pg_dump`/`pg_restore` replaced
the old `sqlite3 .backup` procedure entirely as part of the Postgres cutover.
