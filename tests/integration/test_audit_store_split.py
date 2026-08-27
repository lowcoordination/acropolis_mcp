"""
Issue #108: the audit log and the read path can target separate Postgres databases.

Before this change, Settings.database_url was a single DSN and Database.connect() built both
the writer and reader pools from it — every workload (config, the high-churn audit log, all
reads) pinned to one Postgres instance. #108 restores the pre-cutover gateway.db/audit.db split
as an OPT-IN: Database(audit_dsn=...) points the traffic log at its own database, and
Database(reader_dsn=...) points the reader pool at a read replica. Both default to the primary
DSN, so a single-database deployment is byte-identical to before.

The seam that makes the audit split possible is that AuditRepo is the ONLY code path to
audit_events (AuditLogger's queue-flush, /stats and /metrics via count_since/query, the Audit
page, and the retention job) — routing its _read/_write to the audit pool when one exists
separates the stores without touching a single query. Cross-store queries don't exist:
AuditRepo.query/count_since take a Python-resolved server_slug_in list, so no SQL crosses the
boundary. #109 (degraded /metrics + /stats when audit reads fail) is the runtime complement:
an audit-store outage now degrades the audit-derived numbers instead of 500ing.

These tests provision TWO fresh databases per test (the config store and the audit/reader
store) and drive the real Database/AuditRepo/app code against them — same no-mocks convention
as the rest of the suite.
"""
from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import MIGRATIONS, Database, _version_from_filename, utcnow
from db.repo import AuditRepo, ServerRepo

from .fastmcp_fixture import run_fastmcp_server


@contextlib.asynccontextmanager
async def _fresh_database(postgres_admin_dsn: str):
    """Create + drop one uniquely-named empty database on the suite's Postgres server.

    The conftest's pg_dsn fixture only yields ONE fresh database; these tests need a second
    one (the audit store / read replica) alongside it, so they provision their own. The admin
    DSN points at the maintenance database where CREATE/DROP DATABASE are allowed.
    """
    name = f"acropolis_test_{uuid.uuid4().hex[:16]}"
    conn = await asyncpg.connect(postgres_admin_dsn)
    try:
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()
    dsn = f"{postgres_admin_dsn.rsplit('/', 1)[0]}/{name}"
    try:
        yield dsn
    finally:
        conn = await asyncpg.connect(postgres_admin_dsn)
        try:
            await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            await conn.close()


def _audit_event(server_slug: str, decision: str = "ALLOWED") -> dict:
    return {"ts": utcnow(), "server_slug": server_slug, "decision": decision}


async def _table_count(dsn: str, table: str) -> int:
    conn = await asyncpg.connect(dsn)
    try:
        return await conn.fetchval(f"SELECT count(*) FROM {table}")
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# Default (single database) — the regression that must never move
# ---------------------------------------------------------------------------

async def test_default_single_database_is_unchanged(pg_dsn):
    """No audit_dsn/reader_dsn: db.audit is None, the reader pool targets the same DSN, and
    audit + config rows live in ONE database — today's behaviour exactly."""
    db = Database(pg_dsn)
    await db.connect()
    try:
        assert db.audit is None
        assert db.reader_dsn == pg_dsn
        await ServerRepo(db).create(slug="s", name="S", upstream_url="http://127.0.0.1:1/mcp")
        await AuditRepo(db).insert_many([_audit_event("s")])
        assert await _table_count(pg_dsn, "servers") == 1
        assert await _table_count(pg_dsn, "audit_events") == 1
        # The audit read path still works against the shared database.
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        assert await AuditRepo(db).count_since(since) == 1
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Split audit store
# ---------------------------------------------------------------------------

async def test_split_audit_store_routes_writes_and_reads(postgres_admin_dsn, tmp_path):
    """With audit_dsn set: audit rows land in the AUDIT database while config rows land in the
    config database (whose copy of audit_events sits inert), the audit READ path (count_since,
    which backs /stats and /metrics) serves from the audit database, and each database keeps
    its own independent migration bookkeeping."""
    async with _fresh_database(postgres_admin_dsn) as config_dsn, \
               _fresh_database(postgres_admin_dsn) as audit_dsn:
        db = Database(config_dsn, audit_dsn=audit_dsn)
        await db.connect()
        try:
            assert db.audit is not None
            server_repo = ServerRepo(db)
            audit_repo = AuditRepo(db)
            await server_repo.create(slug="s", name="S", upstream_url="http://127.0.0.1:1/mcp")
            await audit_repo.insert_many([_audit_event("s")])

            # The audit row landed in the audit database...
            assert await _table_count(audit_dsn, "audit_events") == 1
            # ...and the config database's audit_events (created by config 0001) is inert.
            assert await _table_count(config_dsn, "audit_events") == 0
            assert await _table_count(config_dsn, "servers") == 1

            # The audit READ path routes to the audit database.
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            assert await audit_repo.count_since(since) == 1

            # Independent migration bookkeeping: the audit database has its own schema_migrations
            # (version 1 = audit/0001_audit_init.sql); the config database keeps 0001..0012.
            conn = await asyncpg.connect(audit_dsn)
            try:
                audit_versions = {r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")}
            finally:
                await conn.close()
            conn = await asyncpg.connect(config_dsn)
            try:
                config_versions = {r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")}
            finally:
                await conn.close()

            assert audit_versions == {1}
            assert config_versions == {_version_from_filename(f) for f in MIGRATIONS}
        finally:
            await db.close()


async def test_split_audit_store_end_to_end_pipeline(postgres_admin_dsn, tmp_path):
    """The full app with a split audit store: a real proxied call writes its audit row (via
    AuditLogger's queue-flush) into the AUDIT database, and /stats + /metrics — the #109
    hardened endpoints — read their counters back from it."""
    async with _fresh_database(postgres_admin_dsn) as config_dsn, \
               _fresh_database(postgres_admin_dsn) as audit_dsn:
        db = Database(config_dsn, audit_dsn=audit_dsn)
        await db.connect()
        settings = Settings(
            data_dir=str(tmp_path), auth_mode="open",
            health_poll_enabled=False, audit_retention_enabled=False,
        )
        app = create_app(settings, db, probe_on_create=False)
        transport = httpx.ASGITransport(app=app)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
                async with run_fastmcp_server() as upstream:
                    await ServerRepo(db).create(
                        slug="split", name="Split", upstream_url=f"{upstream.url}/mcp"
                    )
                    # Direct /mcp/{slug} is a raw byte proxy (Pipeline._forward): the client
                    # performs the 2025 initialize handshake itself and echoes the upstream
                    # session id — the proven test_bridged_e2e shape.
                    _headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
                    init = await client.post(
                        "/mcp/split",
                        json={
                            "jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "acropolis-test-client", "version": "0.0.1"},
                            },
                        },
                        headers=_headers,
                    )
                    assert init.status_code == 200, f"initialize failed: {init.text[:300]}"
                    session_id = init.headers.get("mcp-session-id")
                    assert session_id, "initialize did not return mcp-session-id"

                    call = await client.post(
                        "/mcp/split",
                        json={
                            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                            "params": {"name": "echo", "arguments": {"message": "hi"}},
                        },
                        headers={**_headers, "Mcp-Session-Id": session_id},
                    )
                    assert call.status_code == 200, f"tools/call failed: {call.text[:300]}"
                    # Let the background flush task land (FLUSH_INTERVAL_SECONDS = 0.1).
                    await asyncio.sleep(0.5)

                    # #109-hardened endpoints must read their counters from the audit store.
                    stats = await client.get("/api/v1/stats")
                    assert stats.status_code == 200, stats.text
                    assert stats.json()["requests_24h"] >= 1

                    metrics = await client.get("/metrics")
                    assert metrics.status_code == 200
                    assert 'acropolis_audit_events_total{decision="ALLOWED"}' in metrics.text

        # After lifespan teardown (AuditLogger's _on_stop drains its queue), the rows are
        # guaranteed flushed — into the audit database, never the config database.
        assert await _table_count(audit_dsn, "audit_events") >= 1
        assert await _table_count(config_dsn, "audit_events") == 0


# ---------------------------------------------------------------------------
# Split reader pool
# ---------------------------------------------------------------------------

async def test_split_reader_pool_targets_reader_dsn(postgres_admin_dsn, tmp_path):
    """With reader_dsn set: the reader pool serves reads from the replica (which must carry the
    schema — a real replica replicates DDL from the primary), while writes go to the primary.
    The replica's own data is what the read path sees; a write through the split Database is
    invisible to its own reader pool, exactly as with a real replica."""
    async with _fresh_database(postgres_admin_dsn) as primary, \
               _fresh_database(postgres_admin_dsn) as replica:
        # Provision the replica's schema the way a real read replica would have it (replicated
        # DDL), then seed it with one row "replicated" from the primary.
        seed = Database(replica)
        await seed.connect()
        try:
            await ServerRepo(seed).create(
                slug="replica-only", name="Replica", upstream_url="http://127.0.0.1:1/mcp"
            )
        finally:
            await seed.close()

        db = Database(primary, reader_dsn=replica)
        await db.connect()
        try:
            assert db.reader_dsn == replica
            server_repo = ServerRepo(db)
            # A write goes to the primary...
            await server_repo.create(
                slug="primary-only", name="Primary", upstream_url="http://127.0.0.1:1/mcp"
            )
            # ...and reads are served from the replica pool, which knows nothing of it.
            slugs = [s.slug for s in await server_repo.list()]
            assert slugs == ["replica-only"]
            assert await _table_count(primary, "servers") == 1
        finally:
            await db.close()
