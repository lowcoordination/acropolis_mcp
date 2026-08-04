from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_GATEWAY_MIGRATIONS = ["0001_init.sql"]
_AUDIT_MIGRATIONS = ["0001_init_audit.sql"]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _connect(path: Path) -> aiosqlite.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(path)
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA busy_timeout=5000")
    await conn.execute("PRAGMA foreign_keys=ON")
    return conn


async def _applied_versions(conn: aiosqlite.Connection) -> set[int]:
    try:
        cur = await conn.execute("SELECT version FROM schema_migrations")
        rows = await cur.fetchall()
        return {r[0] for r in rows}
    except aiosqlite.OperationalError:
        return set()


def _version_from_filename(filename: str) -> int:
    m = re.match(r"^(\d+)_", filename)
    if not m:
        raise ValueError(f"migration filename must start with a numeric version: {filename}")
    return int(m.group(1))


async def _apply_migrations(conn: aiosqlite.Connection, filenames: list[str]) -> None:
    applied = await _applied_versions(conn)
    for filename in filenames:
        version = _version_from_filename(filename)
        if version in applied:
            continue
        sql = (MIGRATIONS_DIR / filename).read_text()
        await conn.executescript(sql)
        await conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (version, utcnow()),
        )
        await conn.commit()


class Database:
    """Holds the SQLite connections: gateway.db (config, split reader/writer) and audit.db
    (events, single connection).

    SECURITY/CORRECTNESS (review finding F7, 2026-08-04): gateway.db used to be ONE connection
    shared by every repo method. sqlite3 opens an implicit transaction on the first DML
    statement, and every `await` inside a multi-statement repo method yields the event loop —
    so two coroutines sharing that connection could interleave, and a query on that SAME
    connection during another coroutine's uncommitted transaction sees the UNCOMMITTED state
    (SQLite gives no snapshot isolation within a single connection — confirmed directly:
    querying mid-transaction on the same connection that opened it returns the in-progress
    result, not the last-committed one). Concretely: ServerRepo.set_policy does
    DELETE-then-reinsert across three tables; a concurrent get_policy() on the same shared
    connection could observe the gap and see an empty denylist — the gateway transiently fails
    open on every policy save.

    Fix: `gateway` is now a DEDICATED WRITER connection, used only by write paths (all of them
    now serialize through `gateway_write_lock`, not just the multi-statement ones — a
    single-statement write is atomic against other writers on the same connection, but not
    against a concurrent reader on a DIFFERENT connection without WAL's cross-connection
    isolation, which is exactly what splitting the connections buys). `gateway_read` is a
    separate connection used by every read path. Because both run under `journal_mode=WAL`, a
    reader on `gateway_read` sees only the last-committed state of `gateway` — confirmed
    directly: a separate WAL connection querying during another connection's uncommitted
    transaction returns the pre-transaction row count, not the in-progress one. This is real
    SQLite snapshot isolation, not an app-level lock trying to fake it on one connection.

    audit.db keeps a single connection: AuditLogger's batched flush is its only writer, already
    serialized by its own queue, and nothing reads audit.db during that writer's transaction in
    a way that matters for correctness (audit queries are eventually-consistent by design)."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.gateway: aiosqlite.Connection | None = None
        self.gateway_read: aiosqlite.Connection | None = None
        self.audit: aiosqlite.Connection | None = None
        self.gateway_write_lock = asyncio.Lock()

    async def connect(self) -> None:
        self.gateway = await _connect(self.data_dir / "gateway.db")
        self.gateway_read = await _connect(self.data_dir / "gateway.db")
        self.audit = await _connect(self.data_dir / "audit.db")
        await _apply_migrations(self.gateway, _GATEWAY_MIGRATIONS)
        await _apply_migrations(self.audit, _AUDIT_MIGRATIONS)

    async def close(self) -> None:
        if self.gateway is not None:
            await self.gateway.close()
        if self.gateway_read is not None:
            await self.gateway_read.close()
        if self.audit is not None:
            await self.audit.close()
