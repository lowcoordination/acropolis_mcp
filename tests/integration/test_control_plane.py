"""Integration tests for Archon's /api/v1 control-plane routes, against a real app instance
(no upstream MCP server needed here — these routes never touch upstreams directly)."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database


@pytest.fixture
async def api_client(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client
    await db.close()


async def test_health(api_client):
    resp = await api_client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_create_and_list_server(api_client):
    resp = await api_client.post(
        "/api/v1/servers",
        json={"slug": "shell", "name": "Shell", "upstream_url": "http://localhost:8010/mcp"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["slug"] == "shell"
    # Server creation probes immediately (see stoa/health.py HealthPoller.poll_one) rather than
    # leaving health_status at "unknown" for up to a full poll interval. This upstream is
    # unreachable in the test, so the immediate probe correctly reports "unhealthy".
    assert body["health_status"] == "unhealthy"

    resp = await api_client.get("/api/v1/servers")
    assert resp.status_code == 200
    slugs = [s["slug"] for s in resp.json()]
    assert "shell" in slugs


async def test_create_duplicate_slug_conflicts(api_client):
    payload = {"slug": "dup", "name": "Dup", "upstream_url": "http://localhost:1/mcp"}
    first = await api_client.post("/api/v1/servers", json=payload)
    assert first.status_code == 201
    second = await api_client.post("/api/v1/servers", json=payload)
    assert second.status_code == 409


async def test_get_unknown_server_404(api_client):
    resp = await api_client.get("/api/v1/servers/does-not-exist")
    assert resp.status_code == 404


async def test_update_server(api_client):
    await api_client.post(
        "/api/v1/servers", json={"slug": "u", "name": "U", "upstream_url": "http://x/mcp"}
    )
    resp = await api_client.put("/api/v1/servers/u", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


async def test_delete_server(api_client):
    await api_client.post(
        "/api/v1/servers", json={"slug": "d", "name": "D", "upstream_url": "http://x/mcp"}
    )
    resp = await api_client.delete("/api/v1/servers/d")
    assert resp.status_code == 204
    resp = await api_client.get("/api/v1/servers/d")
    assert resp.status_code == 404


async def test_get_and_set_policy(api_client):
    await api_client.post(
        "/api/v1/servers", json={"slug": "p", "name": "P", "upstream_url": "http://x/mcp"}
    )
    resp = await api_client.get("/api/v1/servers/p/policy")
    assert resp.status_code == 200
    assert resp.json()["mode"] == "passthrough"

    resp = await api_client.put(
        "/api/v1/servers/p/policy",
        json={"mode": "allowlist", "allowed": ["read_file"], "denied": [], "param_rules": {}},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "allowlist"
    assert resp.json()["allowed"] == ["read_file"]

    resp = await api_client.get("/api/v1/servers/p/policy")
    assert resp.json()["mode"] == "allowlist"


async def test_set_policy_unknown_server_404(api_client):
    resp = await api_client.put(
        "/api/v1/servers/nope/policy",
        json={"mode": "passthrough", "allowed": [], "denied": [], "param_rules": {}},
    )
    assert resp.status_code == 404


async def test_create_key_returns_plaintext_once(api_client):
    resp = await api_client.post("/api/v1/keys", json={"name": "friend-key"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["plaintext"].startswith("argus_")

    list_resp = await api_client.get("/api/v1/keys")
    assert "plaintext" not in list_resp.text


async def test_list_keys_does_not_leak_plaintext_or_hash(api_client):
    await api_client.post("/api/v1/keys", json={"name": "k1"})
    resp = await api_client.get("/api/v1/keys")
    assert resp.status_code == 200
    body = resp.json()[0]
    assert "plaintext" not in body
    assert "key_hash" not in body
    assert "key_prefix" in body


async def test_disable_and_enable_key(api_client):
    create = await api_client.post("/api/v1/keys", json={"name": "k2"})
    key_id = create.json()["id"]

    resp = await api_client.patch(f"/api/v1/keys/{key_id}", params={"enabled": "false"})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    resp = await api_client.patch(f"/api/v1/keys/{key_id}", params={"enabled": "true"})
    assert resp.json()["enabled"] is True


async def test_delete_key(api_client):
    create = await api_client.post("/api/v1/keys", json={"name": "k3"})
    key_id = create.json()["id"]
    resp = await api_client.delete(f"/api/v1/keys/{key_id}")
    assert resp.status_code == 204
    remaining_ids = [k["id"] for k in (await api_client.get("/api/v1/keys")).json()]
    assert key_id not in remaining_ids


async def test_admin_auth_enforced_when_token_set(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", admin_token="secret123", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            unauthed = await client.get("/api/v1/servers")
            assert unauthed.status_code == 401

            wrong = await client.get("/api/v1/servers", headers={"Authorization": "Bearer wrong"})
            assert wrong.status_code == 401

            authed = await client.get(
                "/api/v1/servers", headers={"Authorization": "Bearer secret123"}
            )
            assert authed.status_code == 200
    await db.close()
