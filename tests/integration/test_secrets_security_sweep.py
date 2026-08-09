"""Final security-sweep test for enterprise #5, matching the plan's explicit bar: grep the DB,
the logs, and a config export for a real secret value used during testing — it must appear in
NONE of them. Covers both the `encrypted` tier (ciphertext-adjacent surfaces) and the `openbao`
reference surface (a `vault://` string is never a secret itself, but this proves nothing about
its resolution — e.g. no accidental caching of a resolved plaintext into a log line — leaks it
either).
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
from pathlib import Path

import httpx
import pytest
import yaml

from archon.settings import Settings
from argus.app import create_app
from db.database import Database

from .openbao_fixture import has_real_server, run_dev_server

CANARY = "Bearer sk-SWEEP-CANARY-4b7e91a02c88ff33-must-not-leak"


_TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _all_gateway_db_text(data_dir: Path) -> str:
    """Reads every row of every table in gateway.db as text, for a substring sweep.

    Table names come from sqlite_master itself (never attacker- or network-controlled — this is
    a local test fixture's own schema), but interpolating them into SQL still goes through an
    identifier allowlist check first rather than directly, per this repo's own f-string-in-SQL
    convention (see archon/secrets/openbao.py's docstring on why SQL identifiers can't be
    parameterized the way values can — the same reasoning applies here)."""
    conn = sqlite3.connect(data_dir / "gateway.db")
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        chunks = []
        for table in tables:
            assert _TABLE_NAME_RE.match(table), f"unexpected table name shape: {table!r}"
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()  # nosec: identifier allowlisted above
            chunks.append(str(rows))
        return "\n".join(chunks)
    finally:
        conn.close()


async def test_encrypted_tier_canary_absent_from_db_export_and_logs(tmp_path: Path, monkeypatch, caplog):
    key_hex = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)

    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted", admin_token="sweep-admin-token",
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)

    with caplog.at_level(logging.DEBUG):
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=transport, base_url="http://argus.test",
                headers={"Authorization": "Bearer sweep-admin-token"},
            ) as client:
                create_resp = await client.post("/api/v1/servers", json={
                    "slug": "sweep-encrypted", "name": "Sweep Encrypted",
                    "upstream_url": "http://127.0.0.1:1/mcp",
                    "upstream_auth_header": CANARY,
                })
                assert create_resp.status_code == 201

                # Trigger a resolution (tools/list) AND a resolution failure path (probe against
                # an unreachable upstream) — the canary must not leak via either.
                await client.post(
                    "/mcp/sweep-encrypted",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                )
                await client.post("/api/v1/servers/sweep-encrypted/probe")

                export_resp = await client.get("/api/v1/config/export", params={"include_credentials": True})
                export_text = export_resp.text

                get_resp = await client.get("/api/v1/servers/sweep-encrypted")
                api_response_text = get_resp.text

    await db.close()

    db_text = _all_gateway_db_text(tmp_path)
    log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert CANARY not in db_text, "canary plaintext leaked into gateway.db"
    assert CANARY not in export_text, "canary plaintext leaked into a config export"
    assert CANARY not in api_response_text, "canary plaintext leaked into an API response"
    assert CANARY not in log_text, "canary plaintext leaked into a log line"

    # Also sweep the key material itself — it must never be logged or returned via any endpoint.
    assert key_hex not in db_text
    assert key_hex not in export_text
    assert key_hex not in api_response_text
    assert key_hex not in log_text


@pytest.mark.skipif(not has_real_server(), reason="neither 'bao' nor 'vault' binary available on PATH")
async def test_openbao_tier_canary_absent_from_db_export_and_logs(tmp_path: Path, monkeypatch, caplog):
    async with run_dev_server() as vault:
        # Seed the secret in Vault directly (as an operator would via `vault kv put`), then
        # register the server with a vault:// reference — the reference is what Acropolis ever
        # stores; the canary itself never passes through server_repo.create at all here.
        from archon.secrets.openbao import OpenBaoSecretProvider

        seed_provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token)
        try:
            await seed_provider.store("vault://secret/acropolis/sweep-openbao#token", CANARY)
        finally:
            await seed_provider.aclose()

        monkeypatch.setenv("ACROPOLIS_VAULT_ADDR", vault.url)
        monkeypatch.setenv("ACROPOLIS_VAULT_TOKEN", vault.token)

        settings = Settings(
            data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
            audit_retention_enabled=False, secret_provider="openbao",
            vault_addr=vault.url, vault_token=vault.token, admin_token="sweep-admin-token",
        )
        db = Database(tmp_path)
        await db.connect()
        app = create_app(settings, db)
        transport = httpx.ASGITransport(app=app)

        with caplog.at_level(logging.DEBUG):
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://argus.test",
                    headers={"Authorization": "Bearer sweep-admin-token"},
                ) as client:
                    create_resp = await client.post("/api/v1/servers", json={
                        "slug": "sweep-openbao", "name": "Sweep OpenBao",
                        "upstream_url": "http://127.0.0.1:1/mcp",
                        "upstream_auth_header": "vault://secret/acropolis/sweep-openbao#token",
                    })
                    assert create_resp.status_code == 201

                    await client.post(
                        "/mcp/sweep-openbao",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                    )
                    await client.post("/api/v1/servers/sweep-openbao/probe")

                    export_resp = await client.get(
                        "/api/v1/config/export", params={"include_credentials": True}
                    )
                    export_text = export_resp.text

                    get_resp = await client.get("/api/v1/servers/sweep-openbao")
                    api_response_text = get_resp.text

        await db.close()

        db_text = _all_gateway_db_text(tmp_path)
        log_text = "\n".join(record.getMessage() for record in caplog.records)

        assert CANARY not in db_text
        assert CANARY not in export_text
        assert CANARY not in api_response_text
        assert CANARY not in log_text
        # The reference itself is fine everywhere — it's not a secret.
        assert "vault://secret/acropolis/sweep-openbao#token" in export_text
