# Backups, restores, and upgrades

Acropolis keeps all state — registered servers, policies, API keys, settings, and the audit
log — in **Postgres** (enterprise #7, issue #8; there is no SQLite fallback). See
[docs/postgres.md](postgres.md) for getting an instance and the connection string; this page
covers backing it up, restoring it, and upgrading Acropolis itself.

> **Backup vs. config export.** This page covers *disaster recovery*: a complete database
> snapshot, including API keys' hashes, upstream credentials, and the whole audit log. That is
> what you restore from when the database is lost or corrupted. It is not something you can read
> in a code review.
>
> For *configuration as reviewable text* — servers, policies and gateway settings in a single
> YAML file you can diff in git or replay onto a fresh instance — use the config export instead
> (Settings → Configuration in the UI, or `python -m argus export`). It deliberately contains no
> API keys and, by default, no upstream credentials, so it is **not** a substitute for a backup.
> See [Exporting and importing configuration](#exporting-and-importing-configuration) below.

## Taking a backup

Use `pg_dump` against the same database Acropolis is configured with
(`ACROPOLIS_DATABASE_URL`). It's online-safe — no need to stop Acropolis first, Postgres's MVCC
gives you a consistent snapshot of a running database the way SQLite's WAL mode never could
without the file-copy caveats that used to live on this page.

```bash
pg_dump "$ACROPOLIS_DATABASE_URL" -Fc -f acropolis-backup.dump
```

`-Fc` (custom format) is compressed and restorable with `pg_restore`, including selectively —
prefer it over plain SQL output unless you specifically want a human-readable `.sql` file.

If Postgres runs in its own container (the bundled `docker compose` service, or a `kubectl exec`
into a Postgres pod you manage), run `pg_dump` from wherever `psql`/the Postgres client tools are
available and reachable — from the `postgres` container itself:

```bash
docker exec acropolis-postgres pg_dump -U acropolis -Fc acropolis > acropolis-backup.dump
```

or from any host with `pg_dump` installed and network access to the database, pointed at
`ACROPOLIS_DATABASE_URL` directly — that's usually simpler for a managed instance (RDS, Cloud
SQL) where there's no container to exec into. Either way, put this on a schedule — a cron job or
a k8s CronJob — rather than relying on remembering to run it by hand. Most managed Postgres
providers also offer automated snapshots; if yours does, that likely covers this need without a
separate `pg_dump` job at all — check before building your own.

## Restoring

1. Stop Acropolis (or at minimum, be aware writes during a restore can be lost — a full stop is
   the safe default).
2. Restore into a Postgres database Acropolis will point at:
   ```bash
   pg_restore -d "$ACROPOLIS_DATABASE_URL" --clean --if-exists acropolis-backup.dump
   ```
   `--clean --if-exists` drops existing objects before recreating them, so this is safe to run
   against a database that already has (older or partial) Acropolis tables in it.
3. Start Acropolis. It applies any pending migrations on startup, same as a normal boot — a
   backup taken on an older schema version upgrades in place exactly like a live database would.

## Upgrading

Acropolis tracks its own schema version in a `schema_migrations` table and applies new
migrations automatically on startup — there's no separate migration command to run.

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

Every audit row carries a gateway-total `latency_ms` (the whole request, wall-clock), but
`/metrics` itself doesn't currently expose that as an aggregate counter/histogram, and it has no
per-stage breakdown (policy eval vs. DLP scan vs. secret resolution vs. bridge handshake vs. the
upstream call itself). For that level of detail, and for propagating/honoring a client's own
`traceparent`, see **[distributed tracing](observability.md)** — `ACROPOLIS_OTEL_ENABLED=true`
exports OTLP spans with exactly that per-stage breakdown to any standard collector (Tempo,
Jaeger, Alloy). `/metrics` and tracing are complementary: the former for aggregate dashboards and
alerting, the latter for "where did THIS specific call spend its time."

## Exporting and importing configuration

A config export is a single YAML file describing your servers, their policies, and the four
gateway settings worth carrying (`auth_mode`, `aggregate_enabled`, `default_ttl_ms`,
`audit_retention_days`). It's meant for reviewing a policy change in a pull request, or moving a
working setup onto a new instance (compose → k8s, say).

```bash
python -m argus export -o acropolis-config.yaml
```

or **Settings → Configuration → Export configuration** in the UI.

### What is deliberately not in it

- **API keys.** Stored only as hashes and show-once by design, so exporting them would be
  useless for restoring and a liability to hold. Recreate keys after importing.
- **`admin_password_hash` and `session_secret`.** Never exported, on either path.
- **Upstream credentials** (`upstream_auth_header`), when stored as a **literal**. Omitted by
  default; the export names which servers had one so you know the file is incomplete.
  `--include-credentials` (CLI) or the checkbox in the UI opts in, and stamps a prominent warning
  into the file itself — at that point the file is a secret, so don't commit it.

  A `vault://` or `enc:v1:` **reference** (enterprise #5 — see [docs/secrets.md](secrets.md)) is
  the exception: it's not a secret on its own, so it's always included, with no warning, on
  every export. This is what makes a committed config export practical with real credentials —
  the same file with the same reference works when imported onto another instance pointed at the
  same Vault.

Because of the first three, **an export is not a backup.** Use the `pg_dump` procedure above for
disaster recovery.

### Importing

Import previews by default and writes only when you ask it to:

```bash
python -m argus import-config acropolis-config.yaml           # dry run, prints the diff
python -m argus import-config acropolis-config.yaml --apply   # actually writes
```

The dry run prints a per-server diff — what would be created, what would change (including which
policy fields), and what is already identical. The UI does the same thing and requires a second
click to apply.

Two behaviors worth knowing:

- **Servers not in the file are left alone, never deleted.** An import means "make these exist as
  described", not "make the world match this file exactly" — so a hand-trimmed file can't wipe
  the rest of your gateway. Anything present locally but absent from the file is called out as a
  warning.
- **A file with any invalid entry is rejected whole.** No partial application, so you can't end
  up with three of five servers imported and no clear way back. Imported upstream URLs go through
  the same validation the API uses, so an edited file can't register an upstream the API itself
  would refuse.
