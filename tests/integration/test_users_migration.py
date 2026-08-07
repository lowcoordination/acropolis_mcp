"""Tests for db/migrations/0007_users.sql — the single highest-risk migration in the
enterprise roadmap (see that file's header comment). A broken version of this migration locks
an operator out of their own gateway with no recovery flow, since migrations are forward-only.

Two scenarios matter, and both are covered here against the REAL migration runner
(db.database._apply_migrations), not a hand-rolled reimplementation of it:

1. POPULATED database — an existing instance with a real admin_password_hash already set,
   upgrading past 0007. The seeded `users` row must carry the EXACT SAME hash, so the operator's
   existing password keeps authenticating with zero action on their part.
2. FRESH database — no admin_password_hash yet (pre-first-run-setup). `users` must end up
   empty, and first-run setup (POST /api/v1/setup) must still complete normally.
"""
from __future__ import annotations

from pathlib import Path

import aiosqlite
import httpx
import pytest

from archon.passwords import hash_password, verify_password
from archon.settings import Settings
from argus.app import create_app
from db.database import Database, _apply_migrations, _connect

# The exact migration list gateway.db had BEFORE 0007_users.sql landed — used to simulate
# "an existing instance that upgraded to every migration through 0006, nothing newer."
_PRE_0007_MIGRATIONS = [
    "0001_init.sql", "0002_tighten_slug_check.sql", "0003_add_upstream_credential.sql",
    "0006_admin_events.sql",
]
_ALL_GATEWAY_MIGRATIONS = _PRE_0007_MIGRATIONS + ["0007_users.sql"]


async def test_migration_seeds_users_from_existing_admin_password_hash(tmp_path: Path):
    """THE most important test in this plan (per both vault docs and the GitHub issues): an
    operator's existing password must keep authenticating after the upgrade, using the exact
    same hash, with zero action on their part."""
    path = tmp_path / "gateway.db"
    conn = await _connect(path)
    await _apply_migrations(conn, _PRE_0007_MIGRATIONS, "gateway.db")

    real_hash = hash_password("the-operators-real-password-99")
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)", (real_hash,)
    )
    await conn.commit()

    # This is the actual upgrade: apply 0007 on top of the already-migrated, already-populated
    # database, exactly as db.database.Database.connect() would on a real restart.
    await _apply_migrations(conn, _ALL_GATEWAY_MIGRATIONS, "gateway.db")

    conn.row_factory = aiosqlite.Row
    cur = await conn.execute("SELECT * FROM users")
    rows = await cur.fetchall()
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
    cur = await conn.execute("SELECT value FROM settings WHERE key = 'admin_password_hash'")
    row = await cur.fetchone()
    assert row["value"] == real_hash

    await conn.close()


async def test_migration_on_fresh_database_leaves_users_empty(tmp_path: Path):
    """No admin_password_hash exists yet (pre-first-run-setup) — the SELECT the migration's
    INSERT reads from returns zero rows, so users stays empty. This is the state
    archon/admin_auth.py's legacy-fallback path is designed to keep working under."""
    path = tmp_path / "gateway.db"
    conn = await _connect(path)
    await _apply_migrations(conn, _ALL_GATEWAY_MIGRATIONS, "gateway.db")

    conn.row_factory = aiosqlite.Row
    cur = await conn.execute("SELECT COUNT(*) as n FROM users")
    row = await cur.fetchone()
    assert row["n"] == 0

    await conn.close()


async def test_migration_is_idempotent_on_already_migrated_db(tmp_path: Path):
    """Applying the full migration list twice (e.g. two connect() calls, or a restart) must not
    re-seed or duplicate the admin row — _apply_migrations already guards this via
    schema_migrations, but this proves it end to end for 0007 specifically."""
    path = tmp_path / "gateway.db"
    conn = await _connect(path)
    await _apply_migrations(conn, _PRE_0007_MIGRATIONS, "gateway.db")
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', 'somehash')"
    )
    await conn.commit()
    await _apply_migrations(conn, _ALL_GATEWAY_MIGRATIONS, "gateway.db")
    await _apply_migrations(conn, _ALL_GATEWAY_MIGRATIONS, "gateway.db")  # second call, no-op

    conn.row_factory = aiosqlite.Row
    cur = await conn.execute("SELECT COUNT(*) as n FROM users")
    row = await cur.fetchone()
    assert row["n"] == 1
    await conn.close()


async def test_fresh_install_first_run_setup_still_works_after_migration(tmp_path: Path):
    """End-to-end, through the real app: a brand-new data directory (0007_users.sql runs as
    part of normal Database.connect(), users starts empty) must still let first-run setup
    complete and immediately log the new admin in — the identity milestone must not require any
    special-cased bootstrapping."""
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
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


async def test_populated_upgrade_end_to_end_existing_password_still_logs_in(tmp_path: Path):
    """The full end-to-end version of the most important test: hand-craft a pre-0007 database
    with a real admin_password_hash (simulating an existing deployed instance), then boot the
    REAL app against it (which runs Database.connect() -> _apply_migrations, applying 0007 for
    the first time), and confirm the operator's existing password logs them in successfully."""
    gateway_path = tmp_path / "gateway.db"
    conn = await _connect(gateway_path)
    await _apply_migrations(conn, _PRE_0007_MIGRATIONS, "gateway.db")
    real_password = "correct-horse-battery-staple-7"
    real_hash = hash_password(real_password)
    session_secret = "test-secret-from-before-the-upgrade"
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)", (real_hash,)
    )
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('session_secret', ?)", (session_secret,)
    )
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('auth_mode', 'keyed')"
    )
    await conn.commit()
    await conn.close()

    # Now boot the real app against this same data directory — Database.connect() runs 0007.
    settings = Settings(data_dir=str(tmp_path), health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
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


async def test_seeded_admin_created_at_is_utc_iso8601_like_every_other_timestamp(tmp_path: Path):
    """Self-review fix: the migration originally wrote created_at via bare SQL datetime('now')
    ('YYYY-MM-DD HH:MM:SS', no timezone marker) while every other created_at in the app (written
    by db/database.py's utcnow()) is ISO 8601 with an explicit UTC offset. The frontend renders
    these with `new Date(...)`, which parses a timezone-less string as LOCAL time — the
    migration-seeded admin's created_at would silently mis-render relative to every other
    timestamp in the UI. Fixed to emit a 'Z'-suffixed string that both `new Date()` and Python's
    fromisoformat (post-3.11) parse as UTC."""
    from datetime import datetime

    path = tmp_path / "gateway.db"
    conn = await _connect(path)
    await _apply_migrations(conn, _PRE_0007_MIGRATIONS, "gateway.db")
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', 'somehash')"
    )
    await conn.commit()
    await _apply_migrations(conn, _ALL_GATEWAY_MIGRATIONS, "gateway.db")

    conn.row_factory = aiosqlite.Row
    cur = await conn.execute("SELECT created_at FROM users WHERE username = 'admin'")
    row = await cur.fetchone()
    created_at = row["created_at"]

    assert created_at.endswith("Z"), f"expected a 'Z'-suffixed UTC timestamp, got {created_at!r}"
    # Must actually parse as a valid UTC-aware timestamp, not just happen to end in the letter Z.
    parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None

    await conn.close()
