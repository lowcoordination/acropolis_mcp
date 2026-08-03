from __future__ import annotations

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
    """Holds the two SQLite connections: gateway.db (config) and audit.db (events)."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.gateway: aiosqlite.Connection | None = None
        self.audit: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self.gateway = await _connect(self.data_dir / "gateway.db")
        self.audit = await _connect(self.data_dir / "audit.db")
        await _apply_migrations(self.gateway, _GATEWAY_MIGRATIONS)
        await _apply_migrations(self.audit, _AUDIT_MIGRATIONS)

    async def close(self) -> None:
        if self.gateway is not None:
            await self.gateway.close()
        if self.audit is not None:
            await self.audit.close()
