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
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
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


async def test_security_headers_present_on_every_response(api_client):
    """F20 regression (review 2026-08-04): no CSP, X-Frame-Options, or X-Content-Type-Options
    existed anywhere. Checked on a plain API response — the middleware is app-wide, not
    route-specific, so any endpoint is representative."""
    resp = await api_client.get("/api/v1/health")
    assert resp.headers.get("content-security-policy") == "default-src 'self'"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("x-content-type-options") == "nosniff"
    # HSTS is deliberately NOT set by Acropolis itself — see docs/tls-and-reverse-proxy.md.
    assert "strict-transport-security" not in {k.lower() for k in resp.headers}


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


async def test_create_server_rejects_non_http_scheme(api_client):
    """F17 regression (review 2026-08-04): the API path had no scheme/host validation at all,
    unlike the YAML importer's identical check. file:// against a local path is a plausible
    SSRF/LFI-adjacent target even without touching the network at all."""
    resp = await api_client.post(
        "/api/v1/servers",
        json={"slug": "bad", "name": "Bad", "upstream_url": "file:///etc/passwd"},
    )
    assert resp.status_code == 422


async def test_create_server_rejects_link_local_metadata_endpoint(api_client):
    """F17: the cloud-provider instance-metadata endpoint is the textbook SSRF target — no
    homelab deployment has a legitimate reason to register it, unlike RFC1918/loopback targets
    which are this product's normal documented operating mode and are deliberately still
    allowed (see docs/quickstart.md's own http://localhost:8010/mcp example)."""
    resp = await api_client.post(
        "/api/v1/servers",
        json={"slug": "metadata", "name": "Metadata", "upstream_url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert resp.status_code == 422


async def test_create_server_still_allows_documented_localhost_and_lan_targets(api_client):
    """F17 must not break the product's own documented quickstart flow."""
    cases = [
        ("lan-localhost", "http://localhost:8010/mcp"),
        ("lan-192", "http://192.168.1.50:8000/mcp"),
        ("lan-loopback", "http://127.0.0.1:9000/mcp"),
    ]
    for slug, url in cases:
        resp = await api_client.post(
            "/api/v1/servers", json={"slug": slug, "name": "LAN", "upstream_url": url},
        )
        assert resp.status_code == 201, f"{url} should be allowed, got {resp.status_code}: {resp.text}"


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
    assert body["plaintext"].startswith("acropolis_")

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


async def test_delete_server_unregisters_its_rate_limit_bucket(tmp_path: Path):
    """F8 regression: a server's rate-limit bucket is keyed on the SLUG STRING, not the DB row
    id. If deleting a server didn't unregister its bucket, recreating the same slug with a
    different (or no) rate_limit would inherit the old bucket's stale consumed-token state
    instead of starting fresh."""
    from argus.rate_limiter import server_key

    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post(
                "/api/v1/servers",
                json={"slug": "shell", "name": "Shell", "upstream_url": "http://localhost:8010/mcp"},
            )
            await client.put(
                "/api/v1/servers/shell/policy",
                json={"mode": "passthrough", "rate_limit": "1/hour", "allowed": [], "denied": [], "param_rules": {}},
            )
            rate_limiter = app.state.rate_limiter
            # Manually register + exhaust the bucket the way a real tools/call would, since
            # this fixture has no live upstream to route a real tools/call through.
            rate_limiter.ensure_current(server_key("shell"), "1/hour")
            assert await rate_limiter.check(server_key("shell")) is True  # consumes the 1 token
            assert rate_limiter.is_registered(server_key("shell"))

            resp = await client.delete("/api/v1/servers/shell")
            assert resp.status_code == 204
            assert not rate_limiter.is_registered(server_key("shell")), (
                "deleting a server did not unregister its rate-limit bucket"
            )
    await db.close()


async def test_admin_auth_enforced_when_token_set(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", admin_token="secret123", health_poll_enabled=False, audit_retention_enabled=False)
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
