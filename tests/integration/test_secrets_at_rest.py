"""Verification-bar tests for enterprise #5's core promise: what actually lands in the database.

Every assertion here reads the RAW `gateway.db` file bytes directly via sqlite3 (not through the
API, not through ServerRepo) — the plan's bar is explicit that "the API doesn't return it" is not
sufficient; the plaintext must not appear in the actual stored column bytes either. This mirrors
tests/integration/test_security_regression.py's existing pattern of reading gateway.db directly
with sqlite3 for security-critical claims.
"""
from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo

CANARY_SECRET = "Bearer sk-CANARY-9f3a7c21e88b4d5fa001-do-not-leak"


def _raw_upstream_auth_header(data_dir: Path, slug: str) -> str:
    conn = sqlite3.connect(data_dir / "gateway.db")
    try:
        row = conn.execute(
            "SELECT upstream_auth_header FROM servers WHERE slug = ?", (slug,)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    return row[0]


def _whole_db_file_bytes(data_dir: Path) -> bytes:
    return (data_dir / "gateway.db").read_bytes()


@pytest.fixture
def secret_key_env(monkeypatch):
    key_hex = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    return key_hex


async def test_encrypted_provider_raw_db_bytes_never_contain_plaintext(tmp_path: Path, secret_key_env):
    """The plan's exact bar: assert on the raw column bytes, not just 'the API doesn't return
    it'. Creates a server through the REAL API with secret_provider='encrypted' selected, then
    reads gateway.db directly off disk."""
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted",
    )
    db = Database(tmp_path)
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
    stored = _raw_upstream_auth_header(tmp_path, "canary-server")
    assert stored != CANARY_SECRET
    assert stored.startswith("enc:v1:")
    assert CANARY_SECRET not in stored
    assert CANARY_SECRET.encode() not in stored.encode()

    # Whole-file check — belt and suspenders against the plaintext showing up ANYWHERE else in
    # the database file (a different table, a WAL remnant merged into the main file, etc.).
    whole_file = _whole_db_file_bytes(tmp_path)
    assert CANARY_SECRET.encode() not in whole_file


async def test_encrypted_provider_resolves_correctly_through_the_real_pipeline(tmp_path: Path, secret_key_env):
    """Companion to the raw-bytes test above: the ciphertext that ends up on disk must still
    resolve back to the exact original credential when the real Pipeline forwards a call —
    proving the write and read paths agree, not just that SOMETHING unreadable got stored."""
    from tests.integration.fastmcp_fixture import run_fastmcp_server

    async with run_fastmcp_server() as upstream:
        settings = Settings(
            data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
            audit_retention_enabled=False, secret_provider="encrypted",
        )
        db = Database(tmp_path)
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


async def test_encrypted_provider_wrong_key_after_restart_fails_cleanly_not_silently(tmp_path: Path, monkeypatch):
    """Simulates the operational failure mode of losing/rotating the key without re-encrypting
    existing data: a server started with key A, restarted with key B, must fail LOUDLY on the
    next resolution — never silently forward with corrupted/garbage credentials, never crash the
    whole app in a way that masks what happened."""
    key_a = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_a)

    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted",
    )
    db = Database(tmp_path)
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

    db2 = Database(tmp_path)
    await db2.connect()
    settings2 = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
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
