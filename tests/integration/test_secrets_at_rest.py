"""Verification-bar tests for enterprise #5's core promise: what actually lands in the database.

Every assertion here reads the RAW stored bytes directly (not through the API, not through
ServerRepo) — the plan's bar is explicit that "the API doesn't return it" is not sufficient; the
plaintext must not appear in the actual stored bytes either.

POSTGRES CUTOVER (enterprise #7). Pre-cutover this opened `gateway.db` with stdlib sqlite3 and,
crucially, also scanned the WHOLE FILE's bytes — belt-and-suspenders against the plaintext turning
up anywhere else in storage (a different table, a WAL remnant, a stale page). Both halves are
preserved against the new engine, and the second one deliberately so:

  - Column-level: read the column with a bare asyncpg connection, outside the repo layer.
  - Storage-level: read the `servers` table's actual HEAP FILE off the Postgres server's disk via
    pg_read_binary_file(pg_relation_filepath('servers')) and scan those bytes. This is the honest
    Postgres analogue of reading gateway.db's bytes — it is the real on-disk page data, including
    any dead tuples left by an UPDATE, not a re-serialization of a query result. A CHECKPOINT is
    forced first so pages sitting in shared buffers are actually written out; without it the scan
    could pass simply because nothing had been flushed yet, which would make this test a
    comfortable no-op rather than a guarantee.

pg_read_binary_file is superuser-restricted; the test Postgres runs as a superuser, which is fine
for a disposable test container. If it is ever unavailable the helper raises rather than silently
skipping — a canary test that quietly stops checking is worse than no canary test.
"""
from __future__ import annotations

import os
from pathlib import Path

import asyncpg
import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo

CANARY_SECRET = "Bearer sk-CANARY-9f3a7c21e88b4d5fa001-do-not-leak"


async def _raw_upstream_auth_header(dsn: str, slug: str) -> str:
    """Read the stored column with a bare connection, bypassing the repo layer entirely."""
    conn = await asyncpg.connect(dsn)
    try:
        value = await conn.fetchval(
            "SELECT upstream_auth_header FROM servers WHERE slug = $1", slug
        )
    finally:
        await conn.close()
    assert value is not None
    return value


async def _raw_table_file_bytes(dsn: str, table: str) -> bytes:
    """The real on-disk heap bytes for `table`, including dead tuples.

    The Postgres analogue of the pre-cutover `gateway.db.read_bytes()` check. CHECKPOINT first so
    dirty pages in shared buffers reach disk — otherwise this could pass vacuously.
    """
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("CHECKPOINT")
        path = await conn.fetchval("SELECT pg_relation_filepath($1)", table)
        assert path, f"could not resolve a relation filepath for {table!r}"
        # pg_read_binary_file reads relative to the data directory, on the SERVER's filesystem —
        # which is why this works against a containerized Postgres without a shared volume.
        return await conn.fetchval("SELECT pg_read_binary_file($1)", path)
    finally:
        await conn.close()


@pytest.fixture
def secret_key_env(monkeypatch):
    key_hex = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    return key_hex


async def test_encrypted_provider_raw_db_bytes_never_contain_plaintext(pg_dsn, secret_key_env):
    """The plan's exact bar: assert on the raw stored bytes, not just 'the API doesn't return
    it'. Creates a server through the REAL API with secret_provider='encrypted' selected, then
    reads the column AND the table's on-disk heap file directly."""
    settings = Settings(
        auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted",
    )
    db = Database(pg_dsn)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            resp = await client.post("/api/v1/servers", json={
                "slug": "canary-server", "name": "Canary", "upstream_url": "http://127.0.0.1:1/mcp",
                "upstream_auth_header": CANARY_SECRET,
            })
            assert resp.status_code == 201
            assert resp.json()["has_upstream_auth_header"] is True

    await db.close()

    # Column-level check.
    stored = await _raw_upstream_auth_header(pg_dsn, "canary-server")
    assert stored != CANARY_SECRET
    assert stored.startswith("enc:v1:")
    assert CANARY_SECRET not in stored
    assert CANARY_SECRET.encode() not in stored.encode()

    # Storage-level check — belt and suspenders against the plaintext showing up ANYWHERE in the
    # table's real on-disk pages, including dead tuples an UPDATE left behind. Same guarantee the
    # pre-cutover whole-gateway.db-file scan provided.
    heap = await _raw_table_file_bytes(pg_dsn, "servers")
    assert heap, "read zero bytes from the servers heap file — the scan proved nothing"
    assert CANARY_SECRET.encode() not in heap


async def test_encrypted_provider_resolves_correctly_through_the_real_pipeline(pg_dsn, secret_key_env):
    """Companion to the raw-bytes test above: the ciphertext that ends up on disk must still
    resolve back to the exact original credential when the real Pipeline forwards a call —
    proving the write and read paths agree, not just that SOMETHING unreadable got stored."""
    from tests.integration.fastmcp_fixture import run_fastmcp_server

    async with run_fastmcp_server() as upstream:
        settings = Settings(
            auth_mode="open", health_poll_enabled=False,
            audit_retention_enabled=False, secret_provider="encrypted",
        )
        db = Database(pg_dsn)
        await db.connect()
        app = create_app(settings, db)
        transport = httpx.ASGITransport(app=app)

        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
                create_resp = await client.post("/api/v1/servers", json={
                    "slug": "encrypted-live", "name": "Encrypted Live",
                    "upstream_url": f"{upstream.url}/mcp",
                    "upstream_auth_header": CANARY_SECRET,
                })
                assert create_resp.status_code == 201

                # tools/list is the simplest read path that resolves the credential — F23's own
                # probe doesn't check the Authorization value FastMCP received, but this proves
                # resolution succeeds end to end (a resolution failure would 502, not 200).
                resp = await client.post(
                    "/mcp/encrypted-live",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                )
                assert resp.status_code == 200, resp.text

        await db.close()


async def test_encrypted_provider_wrong_key_after_restart_fails_cleanly_not_silently(pg_dsn, monkeypatch):
    """Simulates the operational failure mode of losing/rotating the key without re-encrypting
    existing data: a server started with key A, restarted with key B, must fail LOUDLY on the
    next resolution — never silently forward with corrupted/garbage credentials, never crash the
    whole app in a way that masks what happened."""
    key_a = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_a)

    settings = Settings(
        auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted",
    )
    db = Database(pg_dsn)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            resp = await client.post("/api/v1/servers", json={
                "slug": "will-lose-key", "name": "Will Lose Key",
                "upstream_url": "http://127.0.0.1:1/mcp",
                "upstream_auth_header": CANARY_SECRET,
            })
            assert resp.status_code == 201
    await db.close()

    # "Restart" with a DIFFERENT key.
    key_b = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_b)

    # "Restart" against the SAME database — the point is that the stored ciphertext survives
    # while the key does not.
    db2 = Database(pg_dsn)
    await db2.connect()
    settings2 = Settings(
        auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted",
    )
    app2 = create_app(settings2, db2)
    transport2 = httpx.ASGITransport(app=app2)
    async with app2.router.lifespan_context(app2):
        async with httpx.AsyncClient(transport=transport2, base_url="http://argus.test") as client:
            resp = await client.post(
                "/mcp/will-lose-key",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            )
            # Must be a clean, explicit failure — not a 200 with garbage forwarded, not an
            # unhandled 500 with a stack trace.
            assert resp.status_code == 502
            body = resp.json()
            assert "secret resolution failed" in body["error"]["message"].lower()
    await db2.close()
