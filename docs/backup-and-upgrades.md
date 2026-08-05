# Backups, restores, and upgrades

Acropolis keeps all state in two SQLite files under `ACROPOLIS_DATA_DIR` (`/data` in the
Docker image and the k8s manifests):

- `gateway.db` — registered servers, policies, API keys, settings
- `audit.db` — the audit log

Both run in WAL mode. That has one consequence you need to know before you back anything up:
**do not `cp` or `tar` the data directory while Acropolis is running.** A plain file copy of a
WAL-mode database taken mid-write can capture `gateway.db` without its `-wal`/`-shm` sidecar
files in a consistent state, producing a backup that looks fine and is silently missing the
most recent writes (or, rarely, won't open at all).

## Taking a backup

Use SQLite's own online backup command, which is WAL-safe and doesn't require stopping the
container:

```bash
docker exec acropolis sqlite3 /data/gateway.db ".backup /data/gateway.db.backup"
docker exec acropolis sqlite3 /data/audit.db ".backup /data/audit.db.backup"
docker cp acropolis:/data/gateway.db.backup ./gateway.db.backup
docker cp acropolis:/data/audit.db.backup ./audit.db.backup
docker exec acropolis rm /data/gateway.db.backup /data/audit.db.backup
```

For a k8s deployment, run the same `sqlite3 ... ".backup"` command via `kubectl exec` against
the running pod, then `kubectl cp` the result out. Either way, put this on a schedule — a
cron job or a k8s CronJob — rather than relying on remembering to run it by hand.

The audit log is high-volume and lower-value than the config in `gateway.db` — if you need to
choose what to prioritize, back up `gateway.db` (servers, policies, keys, settings) first.

## Restoring

1. Stop Acropolis.
2. Replace `gateway.db` and/or `audit.db` in the data directory with the backed-up copies.
   Remove any stale `-wal`/`-shm` sidecar files left over from the previous run — they belong
   to the database file they were sitting next to, not the one you just restored.
3. Start Acropolis. It applies any pending migrations on startup, same as a normal boot.

## Upgrading

Acropolis tracks its own schema version in a `schema_migrations` table in each database, and
applies new migrations automatically on startup — there's no separate migration command to run.

**Take a backup before upgrading across more than a patch version.** Migrations are forward-only
by design (see `db/migrations/`) — there is no `down` migration to undo one.

**Do not downgrade the binary/image against a database a newer version already migrated.**
`Database.connect()` checks the migration versions actually applied in the database against the
versions the running binary knows about, and refuses to start (raising `SchemaTooNewError`) if
the database is ahead of the code. This is deliberate: an older binary silently running against a
schema it doesn't fully understand is a data-corruption risk, not a compatibility question, and a
loud startup failure is a far better failure mode than that. If you hit this, either upgrade the
binary to match, or restore the backup you took before the newer version ran.

## Monitoring

`GET /metrics` (no authentication, same posture as `/api/v1/health` — it's meant for a scraper,
not a human) exposes Prometheus text-format counters: audit event counts by decision over the
last 24h, and per-server health status. Point a Prometheus scrape config or equivalent at it.

Per-upstream call latency is not currently included — no latency sample is recorded anywhere in
the request path today, so there's nothing yet to expose there. If you need it, that's a real gap
to file, not a metrics-endpoint bug.
