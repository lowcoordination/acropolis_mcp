"""Tests for db/migrations/0006_users.sql — the single highest-risk migration in the enterprise
roadmap (see that file's header comment). A broken version of this migration locks an operator
out of their own gateway with no recovery flow, since migrations are forward-only.

Two scenarios matter, and both are covered here against the REAL migration runner
(db.database._apply_migrations), not a hand-rolled reimplementation of it:

1. POPULATED database — an existing instance with a real admin_password_hash already set,
   upgrading past the users migration. The seeded `users` row must carry the EXACT SAME hash, so
   the operator's existing password keeps authenticating with zero action on their part.
2. FRESH database — no admin_password_hash yet (pre-first-run-setup). `users` must end up
   empty, and first-run setup (POST /api/v1/setup) must still complete normally.

POSTGRES CUTOVER (enterprise #7): ported from raw aiosqlite connections against a gateway.db
file to asyncpg connections against a real Postgres database, and renumbered (0007_users.sql ->
0006_users.sql) per the unified migration sequence. The GUARANTEE under test is unchanged and is
the whole reason this file survived the port intact rather than being rewritten: an operator's
existing password must still work after upgrading, byte-for-byte the same hash.
"""
from __future__ import annotations

import asyncpg
import httpx
import pytest

from archon.passwords import hash_password, verify_password
from archon.settings import Settings
from argus.app import create_app
from db.database import Database, _apply_migrations, _init_connection

# The exact migration list the schema had BEFORE the users migration landed — used to simulate
# "an existing instance that upgraded to everything through 0005, nothing newer."
_PRE_USERS_MIGRATIONS = [
    "0001_init.sql", "0002_upstream_credential.sql", "0003_audit_api_key_index.sql",
    "0004_audit_origin.sql", "0005_admin_events.sql",
]
_THROUGH_USERS_MIGRATIONS = _PRE_USERS_MIGRATIONS + ["0006_users.sql"]


async def _raw_conn(dsn: str) -> asyncpg.Connection:
    """A bare asyncpg connection with the app's JSON codecs registered — the Postgres analogue
    of the old `_connect(path)` helper, used to drive the migration runner directly without
    standing up a full Database/pool."""
    conn = await asyncpg.connect(dsn)
    await _init_connection(conn)
    return conn


async def test_migration_seeds_users_from_existing_admin_password_hash(pg_dsn):
    """THE most important test in this plan (per both vault docs and the GitHub issues): an
    operator's existing password must keep authenticating after the upgrade, using the exact
    same hash, with zero action on their part."""
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_USERS_MIGRATIONS)

    real_hash = hash_password("the-operators-real-password-99")
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)", real_hash
    )

    # This is the actual upgrade: apply the users migration on top of the already-migrated,
    # already-populated database, exactly as Database.connect() would on a real restart.
    await _apply_migrations(conn, _THROUGH_USERS_MIGRATIONS)

    rows = await conn.fetch("SELECT * FROM users")
    assert len(rows) == 1, f"expected exactly one seeded user, got {len(rows)}"

    seeded = dict(rows[0])
    assert seeded["username"] == "admin"
    assert seeded["role"] == "admin"
    assert seeded["auth_source"] == "local"
    assert seeded["password_hash"] == real_hash, "seeded hash must be a VERBATIM copy"
    # The seeded hash must actually verify the operator's real password — not just be byte-equal
    # in the abstract, but functionally correct as a working credential.
    assert verify_password("the-operators-real-password-99", seeded["password_hash"])

    # Non-negotiable: settings.admin_password_hash is NOT deleted by this migration.
    value = await conn.fetchval("SELECT value FROM settings WHERE key = 'admin_password_hash'")
    assert value == real_hash

    await conn.close()


async def test_migration_on_fresh_database_leaves_users_empty(pg_dsn):
    """No admin_password_hash exists yet (pre-first-run-setup) — the SELECT the migration's
    INSERT reads from returns zero rows, so users stays empty. This is the state
    archon/admin_auth.py's legacy-fallback path is designed to keep working under."""
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _THROUGH_USERS_MIGRATIONS)

    assert await conn.fetchval("SELECT COUNT(*) FROM users") == 0

    await conn.close()


async def test_migration_is_idempotent_on_already_migrated_db(pg_dsn):
    """Applying the full migration list twice (e.g. two connect() calls, or a restart) must not
    re-seed or duplicate the admin row — _apply_migrations already guards this via
    schema_migrations, but this proves it end to end for the users migration specifically."""
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_USERS_MIGRATIONS)
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', 'somehash')"
    )
    await _apply_migrations(conn, _THROUGH_USERS_MIGRATIONS)
    await _apply_migrations(conn, _THROUGH_USERS_MIGRATIONS)  # second call, no-op

    assert await conn.fetchval("SELECT COUNT(*) FROM users") == 1
    await conn.close()


async def test_fresh_install_first_run_setup_still_works_after_migration(pg_dsn):
    """End-to-end, through the real app: a brand-new database (the users migration runs as part
    of normal Database.connect(), users starts empty) must still let first-run setup complete and
    immediately log the new admin in — the identity milestone must not require any special-cased
    bootstrapping."""
    settings = Settings(auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(pg_dsn)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            status = await client.get("/api/v1/setup/status")
            assert status.json()["setup_complete"] is False

            resp = await client.post("/api/v1/setup", json={"admin_password": "brand-new-password-1"})
            assert resp.status_code == 200
            assert "acropolis_session" in resp.cookies

            # The session issued by first-run setup must carry a real user_id, not fall back
            # to the legacy user-less path — setup runs strictly after the migration, so
            # there's no reason for it to use the pre-identity-milestone shape.
            me = await client.get("/api/v1/me")
            assert me.status_code == 200
            body = me.json()
            assert body["username"] == "admin"
            assert body["role"] == "admin"
            assert body["user_id"] is not None
    await db.close()


async def test_populated_upgrade_end_to_end_existing_password_still_logs_in(pg_dsn):
    """The full end-to-end version of the most important test: hand-craft a pre-users database
    with a real admin_password_hash (simulating an existing deployed instance), then boot the
    REAL app against it (which runs Database.connect() -> _apply_migrations, applying the users
    migration for the first time), and confirm the operator's existing password logs them in."""
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_USERS_MIGRATIONS)
    real_password = "correct-horse-battery-staple-7"
    real_hash = hash_password(real_password)
    session_secret = "test-secret-from-before-the-upgrade"
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1)", real_hash
    )
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('session_secret', $1)", session_secret
    )
    await conn.execute("INSERT INTO settings (key, value) VALUES ('auth_mode', 'keyed')")
    await conn.close()

    # Now boot the real app against this same database — Database.connect() runs the rest.
    settings = Settings(health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(pg_dsn)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            # The pre-upgrade credential must still work, unmodified.
            login = await client.post("/api/v1/login", json={"admin_password": real_password})
            assert login.status_code == 200, f"existing password rejected after migration: {login.text}"
            assert "acropolis_session" in login.cookies

            # And the resulting session must resolve through the NEW users-table path, proving
            # login is reading the seeded row (not merely falling back to the legacy check).
            me = await client.get("/api/v1/me")
            assert me.status_code == 200
            assert me.json()["username"] == "admin"
            assert me.json()["user_id"] is not None

            # A wrong password is still correctly rejected — the seeded hash isn't a bypass.
            async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as fresh:
                bad = await fresh.post("/api/v1/login", json={"admin_password": "wrong"})
                assert bad.status_code == 401
    await db.close()


async def test_seeded_admin_created_at_is_utc_iso8601_like_every_other_timestamp(pg_dsn):
    """Self-review fix (pre-cutover, preserved): the migration originally wrote created_at via
    bare SQL datetime('now') ('YYYY-MM-DD HH:MM:SS', no timezone marker) while every other
    created_at in the app (written by db/database.py's utcnow()) is ISO 8601 with an explicit UTC
    offset. The frontend renders these with `new Date(...)`, which parses a timezone-less string
    as LOCAL time — the migration-seeded admin's created_at would silently mis-render relative to
    every other timestamp in the UI.

    The Postgres port had to re-derive this property with a different function
    (to_char(now() AT TIME ZONE 'utc', ...) rather than strftime), so this test is exactly the
    guard that proves the port didn't lose it."""
    from datetime import datetime

    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_USERS_MIGRATIONS)
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', 'somehash')"
    )
    await _apply_migrations(conn, _THROUGH_USERS_MIGRATIONS)

    created_at = await conn.fetchval("SELECT created_at FROM users WHERE username = 'admin'")

    assert created_at.endswith("Z"), f"expected a 'Z'-suffixed UTC timestamp, got {created_at!r}"
    # Must actually parse as a valid UTC-aware timestamp, not just happen to end in the letter Z.
    parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None

    await conn.close()
