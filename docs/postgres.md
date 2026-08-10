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
