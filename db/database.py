from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

import asyncpg

logger = logging.getLogger("db.database")

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

# ONE forward-only migration sequence for ONE database. The pre-cutover SQLite schema had two
# independent series (gateway.db's and audit.db's), which is why the originals contained two
# 0001s and two 0008s — a version collision that only worked because each file had its own
# schema_migrations table. See 0001_init.sql's header for the full one-database decision.
MIGRATIONS = [
    "0001_init.sql",
    "0002_upstream_credential.sql",
    "0003_audit_api_key_index.sql",
    "0004_audit_origin.sql",
    "0005_admin_events.sql",
    "0006_users.sql",
    "0007_dlp.sql",
    "0008_server_health_reason.sql",
    "0009_usage_rollups.sql",
    "0010_projects.sql",
    "0011_proposals.sql",
    "0012_proposals_project_scope.sql",
]


# Fixed application-wide id for the migration advisory lock (see _apply_migrations). Arbitrary
# but must never change: it is the rendezvous point two concurrently-starting instances use to
# agree on who applies migrations, so a different value in a future release would let an old and
# a new instance migrate simultaneously during a rolling upgrade.
_MIGRATION_LOCK_ID = 0x4143_524F  # "ACRO"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class SchemaTooNewError(Exception):
    """Raised when the database has migrations applied that this binary doesn't know about —
    e.g. an operator rolled back to an older image after a newer one already migrated the data.
    Running anyway risks the old code silently misinterpreting (or dropping writes into)
    columns/tables it was never taught about; refusing to start is the safe failure mode."""


class DatabaseNotConfiguredError(Exception):
    """Raised at startup when no Postgres connection URL is configured.

    Postgres is a HARD REQUIREMENT as of enterprise #7 — there is no SQLite fallback and no
    embedded/default backend to silently degrade to. Failing loudly at boot matches the posture
    archon/settings.py already takes for a misconfigured secret provider or webhook URL: a
    misconfigured data store must not present as an empty-but-working gateway."""


class PoolExhaustedError(Exception):
    """Raised when a connection pool is exhausted and a connection cannot be acquired within the timeout."""


@contextlib.asynccontextmanager
async def acquire_with_timeout(pool: asyncpg.Pool, timeout: float) -> AsyncIterator[asyncpg.Connection]:
    """Acquire a pooled connection, converting acquisition timeout into PoolExhaustedError.

    The try/except deliberately wraps ONLY the acquisition, not the caller's body. An earlier
    shape wrapped the `yield` too, which meant an asyncio.TimeoutError raised for any unrelated
    reason INSIDE the caller's `async with` block (a wait_for around a slow query, a cancelled
    upstream call) came back out as "pool exhausted, check for a connection leak" — sending
    whoever debugs it at entirely the wrong subsystem. Only a timeout from pool.acquire() itself
    is evidence of exhaustion.
    """
    acquisition = pool.acquire(timeout=timeout)
    try:
        conn = await acquisition.__aenter__()
    except asyncio.TimeoutError as e:
        raise PoolExhaustedError(
            f"pool exhausted after {timeout}s, check for a connection leak"
        ) from e
    try:
        yield conn
    finally:
        await acquisition.__aexit__(*sys.exc_info())


def _version_from_filename(filename: str) -> int:
    m = re.match(r"^(\d+)_", filename)
    if not m:
        raise ValueError(f"migration filename must start with a numeric version: {filename}")
    return int(m.group(1))


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Per-connection setup, run by the pool for every new connection.

    This is where the SQLite PRAGMAs used to be, and it is deliberately much smaller:
      - `journal_mode=WAL` — GONE, not translated. It existed to buy cross-connection snapshot
        isolation (a reader on a second connection seeing only committed state). Postgres gives
        that unconditionally via MVCC; there is no equivalent knob and none is needed.
      - `busy_timeout=5000` — GONE. It existed because SQLite's single-writer lock made
        "database is locked" a routine, retryable condition. Postgres has row-level locking, so
        the failure mode it papered over does not exist. Statement-level timeouts are an
        operator concern (postgresql.conf / the connection URL), not something this app forces.
      - `foreign_keys=ON` — GONE. SQLite needed this because it enforces FK constraints only
        when explicitly asked, per connection. Postgres always enforces them.

    What IS set here: JSON/JSONB codecs. asyncpg returns JSONB as a raw `str` by default rather
    than decoded Python objects. The repo layer round-trips these values through json.dumps /
    json.loads explicitly (it did so under SQLite too, where the columns were TEXT), and several
    public shapes deliberately expose the RAW STRING to callers — AdminEventRecord.before/after
    are Optional[str] with explicit parse_before()/parse_after() helpers, and
    ApiKeyRecord.server_scopes is decoded by the repo. Registering an identity codec (str in,
    str out) keeps that contract byte-identical to the pre-cutover behaviour instead of
    silently handing callers dicts where they used to get strings.
    """
    await conn.set_type_codec(
        "jsonb", encoder=lambda v: v, decoder=lambda v: v, schema="pg_catalog", format="text"
    )
    await conn.set_type_codec(
        "json", encoder=lambda v: v, decoder=lambda v: v, schema="pg_catalog", format="text"
    )


async def _applied_versions(conn: asyncpg.Connection) -> set[int]:
    try:
        rows = await conn.fetch("SELECT version FROM schema_migrations")
        return {r["version"] for r in rows}
    except asyncpg.UndefinedTableError:
        return set()


async def _apply_migrations(
    conn: asyncpg.Connection, filenames: list[str] | None = None
) -> None:
    """Forward-only migration runner.

    `filenames` defaults to the full MIGRATIONS list and is only ever passed explicitly by tests
    that need to simulate a database stopped at an older schema version (see
    tests/integration/test_users_migration.py, which applies everything up to but excluding the
    users migration, seeds a legacy admin_password_hash, then applies the rest — the real upgrade
    path an existing instance takes).

    Two things differ from the SQLite version beyond dialect. First, each migration runs inside
    an explicit TRANSACTION together with its own schema_migrations bookkeeping row — Postgres
    has transactional DDL, so a migration that fails halfway leaves NOTHING applied, rather than
    SQLite's executescript() behaviour where a failure could leave some statements committed and
    the version row unwritten (a state that then needed manual repair). Second, a SESSION-level
    advisory lock serializes the whole migration pass across processes: with Postgres, two app
    instances can now genuinely start at the same moment against the same database, and both
    would otherwise race to apply the same migration.

    The lock is taken with pg_advisory_lock (session-scoped) rather than pg_advisory_xact_lock
    (transaction-scoped) because the pass spans SEVERAL transactions — one per migration file, so
    that each file's DDL and its schema_migrations row commit together. A transaction-scoped lock
    would be released the moment the first file committed, re-opening the race for every
    subsequent file. It is released in a `finally` so a failure mid-pass cannot wedge migrations
    for other instances; a hard process death releases it too, since Postgres drops session
    advisory locks when the backend connection goes away.
    """
    filenames = MIGRATIONS if filenames is None else filenames
    await conn.execute("SELECT pg_advisory_lock($1)", _MIGRATION_LOCK_ID)
    try:
        applied = await _applied_versions(conn)
        known_versions = {_version_from_filename(f) for f in filenames}
        unknown = applied - known_versions
        if unknown:
            raise SchemaTooNewError(
                f"database has migration version(s) {sorted(unknown)} applied that this binary "
                f"does not recognize (it knows up to {max(known_versions, default=0)}). This "
                f"usually means the database was used by a newer version of Acropolis. Upgrade "
                f"the binary/image to match, or restore from a backup taken before the newer "
                f"version ran — do not downgrade against a migrated database."
            )

        for filename in filenames:
            version = _version_from_filename(filename)
            if version in applied:
                continue
            sql = (MIGRATIONS_DIR / filename).read_text()
            # Transactional DDL: the file's statements and its bookkeeping row commit together,
            # or neither does. There is no half-applied migration state to repair by hand.
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)",
                    version,
                    utcnow(),
                )
            logger.info("applied migration %s", filename)
    finally:
        await conn.execute("SELECT pg_advisory_unlock($1)", _MIGRATION_LOCK_ID)


class Database:
    """Owns the asyncpg connection pools for the single Acropolis Postgres database.

    POST-CUTOVER (enterprise #7). This class used to hold three long-lived aiosqlite connections
    — a dedicated gateway.db WRITER, a separate gateway.db READER, and one for audit.db — plus an
    `asyncio.Lock` (`gateway_write_lock`) that serialized every write in the process. All four are
    gone. What replaced them, and why:

    `gateway_write_lock` is DELETED, not made a no-op. It existed to work around SQLite's
    single-writer model: within one process, every write had to be serialized because SQLite
    could not do it. That lock was also precisely what made running more than one replica
    impossible — being per-PROCESS, a second pod would not have contended for it at all, so the
    invariants it protected would simply have stopped holding. Postgres enforces the same
    invariants in the database, where they belong and where they hold across processes. Every one
    of its call sites was converted individually (see db/repo.py — each carries a comment naming
    the shape that replaced it), not blanket-removed: several guarded multi-statement
    read-modify-write sequences (check-slug-then-insert, read-before-then-write-after for audit
    diffs) that need a real transaction or SELECT ... FOR UPDATE, and dropping the lock without
    supplying one would have shipped a TOCTOU this code never had to survive before.

    The reader/writer SPLIT is kept, now as two pools rather than two connections. Under SQLite it
    was load-bearing for correctness (see the pre-cutover docstring: a reader sharing the writer's
    connection could observe an uncommitted DELETE-then-reinsert mid-gap and transiently see an
    empty denylist — the gateway failing open on every policy save). Under Postgres, MVCC makes
    that impossible on ANY connection, so the split is no longer a correctness requirement. It is
    kept for two operational reasons: it bounds how many connections write traffic can consume so
    a burst of data-plane writes cannot starve the control plane's reads, and it leaves a seam for
    pointing `reader` at a read replica later without touching a single repo method. Recorded
    explicitly so the next reader knows this is now a resource-isolation choice, not the
    correctness crutch it used to be.

    audit_events is no longer a separate database — it is a table in this one (see
    0001_init.sql's header for that decision).
    """

    # Pool sizing. Deliberately modest defaults: the writer pool is small because writes are
    # short and the control plane is low-volume, the reader pool larger because every data-plane
    # request does at least one read (key lookup, policy fetch). Both are overridable so an
    # operator running many replicas can keep total connections under Postgres' max_connections
    # (see docs/postgres.md's sizing guidance).
    DEFAULT_WRITER_POOL_MIN = 1
    DEFAULT_WRITER_POOL_MAX = 5
    DEFAULT_READER_POOL_MIN = 1
    DEFAULT_READER_POOL_MAX = 10
    
    POOL_ACQUIRE_TIMEOUT = 10.0  # seconds

    def __init__(
        self,
        dsn: Optional[str] = None,
        *,
        writer_pool_max: int = DEFAULT_WRITER_POOL_MAX,
        reader_pool_max: int = DEFAULT_READER_POOL_MAX,
    ):
        if not dsn:
            raise DatabaseNotConfiguredError(
                "No Postgres connection URL configured. Acropolis requires Postgres — set "
                "ACROPOLIS_DATABASE_URL, e.g. "
                "postgresql://acropolis:password@localhost:5432/acropolis. "
                "See docs/postgres.md."
            )
        self.dsn = dsn
        self._writer_pool_max = writer_pool_max
        self._reader_pool_max = reader_pool_max
        self.writer: asyncpg.Pool | None = None
        self.reader: asyncpg.Pool | None = None

    async def connect(self) -> None:
        self.writer = await asyncpg.create_pool(
            self.dsn,
            min_size=self.DEFAULT_WRITER_POOL_MIN,
            max_size=self._writer_pool_max,
            init=_init_connection,
        )
        self.reader = await asyncpg.create_pool(
            self.dsn,
            min_size=self.DEFAULT_READER_POOL_MIN,
            max_size=self._reader_pool_max,
            init=_init_connection,
        )
        # Migrations run on the writer pool, under the advisory lock in _apply_migrations, so
        # concurrently-starting instances cannot race to apply the same file.
        async with acquire_with_timeout(self.writer, self.POOL_ACQUIRE_TIMEOUT) as conn:
            await _apply_migrations(conn)

    async def close(self) -> None:
        # Close both pools even if the first raises — a half-closed Database would leak
        # connections for the remaining pool's lifetime.
        try:
            if self.writer is not None:
                await self.writer.close()
        finally:
            if self.reader is not None:
                await self.reader.close()
