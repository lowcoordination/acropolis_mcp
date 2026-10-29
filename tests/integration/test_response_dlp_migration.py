"""Issue #165: 0016_response_dlp_audit.sql (config series) and audit/0002_response_dlp_audit.sql
(the separate audit store, issue #108) against the REAL migration runner: a fresh database, a
database stopped at 0015 with existing rows, and the split audit store end to end."""
from __future__ import annotations

import asyncpg

from db.database import AUDIT_MIGRATIONS, MIGRATIONS, Database, _apply_migrations, _init_connection, utcnow
from db.repo import AuditRepo

from .test_audit_store_split import _fresh_database

_NEW_COLUMNS = {
    "response_dlp_detectors_fired": "text",
    "response_dlp_match_count": "integer",
    "response_truncated": "boolean",
}


async def _conn(dsn: str) -> asyncpg.Connection:
    conn = await asyncpg.connect(dsn)
    await _init_connection(conn)
    return conn


async def _columns(conn: asyncpg.Connection) -> dict[str, str]:
    rows = await conn.fetch(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'audit_events'"
    )
    return {r["column_name"]: r["data_type"] for r in rows}


def test_both_series_register_the_new_migration():
    assert MIGRATIONS[-1] == "0016_response_dlp_audit.sql"
    assert AUDIT_MIGRATIONS[-1] == "audit/0002_response_dlp_audit.sql"


async def test_fresh_database_reaches_0016(pg_dsn):
    conn = await _conn(pg_dsn)
    try:
        await _apply_migrations(conn)
        assert max(r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")) == 16
        cols = await _columns(conn)
        for name, dtype in _NEW_COLUMNS.items():
            assert cols[name] == dtype
    finally:
        await conn.close()


async def test_database_at_0015_upgrades_and_old_rows_read_null(pg_dsn):
    conn = await _conn(pg_dsn)
    try:
        await _apply_migrations(conn, MIGRATIONS[:-1])
        assert "response_truncated" not in await _columns(conn)
        await conn.execute(
            "INSERT INTO audit_events (ts, server_slug, decision) VALUES ($1, 'old', 'ALLOWED')", utcnow()
        )
        await _apply_migrations(conn)
        row = await conn.fetchrow("SELECT * FROM audit_events WHERE server_slug = 'old'")
        assert row["response_dlp_detectors_fired"] is None
        assert row["response_dlp_match_count"] is None
        assert row["response_truncated"] is None
    finally:
        await conn.close()


async def test_split_audit_store_reaches_audit_0002_and_stores_the_fields(postgres_admin_dsn, tmp_path):
    async with _fresh_database(postgres_admin_dsn) as config_dsn, \
               _fresh_database(postgres_admin_dsn) as audit_dsn:
        # Stop the audit store at audit/0001 first: the real upgrade path for an existing split.
        conn = await _conn(audit_dsn)
        try:
            await _apply_migrations(conn, AUDIT_MIGRATIONS[:1])
            assert "response_truncated" not in await _columns(conn)
        finally:
            await conn.close()

        db = Database(config_dsn, audit_dsn=audit_dsn)
        await db.connect()
        try:
            await AuditRepo(db).insert_many([{
                "ts": utcnow(), "server_slug": "split", "decision": "ALLOWED",
                "response_dlp_detectors_fired": "jwt", "response_dlp_match_count": 2,
                "response_truncated": False,
            }])
            rows = await AuditRepo(db).query(server_slug="split")
            assert rows[0]["response_dlp_detectors_fired"] == "jwt"
            assert rows[0]["response_dlp_match_count"] == 2
        finally:
            await db.close()

        conn = await _conn(audit_dsn)
        try:
            versions = {r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")}
            assert versions == {1, 2}
        finally:
            await conn.close()
