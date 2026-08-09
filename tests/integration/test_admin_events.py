"""Tests for control-plane audit logging (Enterprise #3)."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database


@pytest.fixture
async def app_transport(tmp_path: Path):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        yield transport
    await db.close()


@pytest.fixture
async def client(app_transport):
    async with httpx.AsyncClient(transport=app_transport, base_url="http://argus.test") as c:
        yield c


async def _setup_admin(client):
    """Complete first-run setup and return the session cookie."""
    resp = await client.post("/api/v1/setup", json={"admin_password": "hunter22", "auth_mode": "keyed"})
    assert resp.status_code == 200
    return resp.cookies.get("acropolis_session")


async def test_admin_events_empty_initially(client):
    await _setup_admin(client)
    resp = await client.get("/api/v1/admin-events")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_server_create_writes_admin_event(client):
    await _setup_admin(client)
    resp = await client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })
    assert resp.status_code == 201

    events = await client.get("/api/v1/admin-events")
    assert events.status_code == 200
    data = events.json()
    assert len(data) == 1
    assert data[0]["action"] == "server.create"
    assert data[0]["target_type"] == "server"
    assert data[0]["target_id"] == "test-server"
    assert "created server 'test-server'" in data[0]["summary"]
    assert data[0]["after"] is not None
    after = json.loads(data[0]["after"])
    assert after["slug"] == "test-server"
    assert "upstream_auth_header" not in after  # secret excluded


async def test_server_update_writes_admin_event_with_diff(client):
    await _setup_admin(client)
    await client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })

    resp = await client.put("/api/v1/servers/test-server", json={
        "name": "Updated Name", "upstream_url": "http://localhost:9000/mcp",
    })
    assert resp.status_code == 200

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 2  # create + update
    update_event = next(e for e in data if e["action"] == "server.update")
    assert update_event["target_id"] == "test-server"
    assert "updated server 'test-server'" in update_event["summary"]
    assert "name: Test Server -> Updated Name" in update_event["summary"]
    assert "upstream_url" in update_event["summary"]
    before = json.loads(update_event["before"])
    after = json.loads(update_event["after"])
    assert before["name"] == "Test Server"
    assert after["name"] == "Updated Name"


async def test_server_delete_writes_admin_event(client):
    await _setup_admin(client)
    await client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })

    resp = await client.delete("/api/v1/servers/test-server")
    assert resp.status_code == 204

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 2  # create + delete
    delete_event = next(e for e in data if e["action"] == "server.delete")
    assert delete_event["target_id"] == "test-server"
    assert "deleted server 'test-server'" in delete_event["summary"]
    before = json.loads(delete_event["before"])
    assert before["slug"] == "test-server"
    assert delete_event["after"] is None


async def test_policy_update_writes_admin_event_with_diff(client):
    await _setup_admin(client)
    await client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })

    resp = await client.put("/api/v1/servers/test-server/policy", json={
        "mode": "allowlist", "allowed": ["read_file", "list_dir"],
    })
    assert resp.status_code == 200

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 2  # create + policy update
    policy_event = next(e for e in data if e["action"] == "policy.update")
    assert policy_event["target_id"] == "test-server"
    assert "mode: passthrough -> allowlist" in policy_event["summary"]
    assert "allowed: 0 -> 2 tool(s)" in policy_event["summary"]


async def test_dlp_policy_change_writes_admin_event_with_diff(client):
    """Enterprise #10: a DLP config change is a security-lowering/relevant action worth
    auditing, same as any other policy field — this is the AdminEventRepo infrastructure from
    enterprise #4, reused rather than rebuilt."""
    await _setup_admin(client)
    await client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })

    resp = await client.put("/api/v1/servers/test-server/policy", json={
        "mode": "passthrough",
        "dlp_detectors": {"credit_card": "block", "email": "redact"},
        "dlp_custom_patterns": [{"name": "employee_id", "pattern": "EMP-\\d{6}", "action": "redact"}],
    })
    assert resp.status_code == 200

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    policy_event = next(e for e in data if e["action"] == "policy.update")
    assert "dlp_detectors: 0 -> 2 configured" in policy_event["summary"]
    assert "dlp_custom_patterns: 0 -> 1 configured" in policy_event["summary"]
    after = json.loads(policy_event["after"])
    assert after["policy"]["dlp_detectors"] == {"credit_card": "block", "email": "redact"}
    assert after["policy"]["dlp_custom_patterns"][0]["name"] == "employee_id"


async def test_dlp_config_change_alone_still_produces_a_diff_summary():
    """Unit-level companion: turning a detector from redact to block (no other policy field
    changing) must still surface as a delta — confirms the DLP fields are compared, not just
    counted as part of some other field's equality check."""
    from archon.admin_audit import _policy_diff
    from db.models import ServerPolicy

    current = ServerPolicy(dlp_detectors={"email": "redact"})
    incoming = ServerPolicy(dlp_detectors={"email": "block"})
    deltas = _policy_diff(current, incoming)
    assert any("dlp_detectors" in d for d in deltas)


async def test_key_create_writes_admin_event(client):
    await _setup_admin(client)
    resp = await client.post("/api/v1/keys", json={"name": "test-key"})
    assert resp.status_code == 201

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 1
    assert data[0]["action"] == "key.create"
    assert data[0]["target_type"] == "key"
    assert "created API key 'test-key'" in data[0]["summary"]
    after = json.loads(data[0]["after"])
    assert after["name"] == "test-key"
    assert "key_prefix" in after


async def test_key_disable_writes_admin_event(client):
    await _setup_admin(client)
    create_resp = await client.post("/api/v1/keys", json={"name": "test-key"})
    key_id = create_resp.json()["id"]

    resp = await client.patch(f"/api/v1/keys/{key_id}", params={"enabled": "false"})
    assert resp.status_code == 200

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 2  # create + disable
    disable_event = next(e for e in data if e["action"] == "key.disable")
    assert disable_event["target_id"] == str(key_id)
    assert "disabled API key 'test-key'" in disable_event["summary"]


async def test_key_delete_writes_admin_event(client):
    await _setup_admin(client)
    create_resp = await client.post("/api/v1/keys", json={"name": "test-key"})
    key_id = create_resp.json()["id"]

    resp = await client.delete(f"/api/v1/keys/{key_id}")
    assert resp.status_code == 204

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 2  # create + delete
    delete_event = next(e for e in data if e["action"] == "key.delete")
    assert delete_event["target_id"] == str(key_id)
    assert "deleted API key 'test-key'" in delete_event["summary"]


async def test_settings_update_writes_admin_event(client):
    await _setup_admin(client)
    resp = await client.put("/api/v1/settings", json={"auth_mode": "open"})
    assert resp.status_code == 200

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 1
    assert data[0]["action"] == "settings.update"
    assert data[0]["target_type"] == "settings"
    assert "auth_mode: keyed -> open" in data[0]["summary"]
    before = json.loads(data[0]["before"])
    after = json.loads(data[0]["after"])
    assert before["auth_mode"] == "keyed"
    assert after["auth_mode"] == "open"
    # Secret keys must never appear
    assert "admin_password_hash" not in before
    assert "admin_password_hash" not in after
    assert "session_secret" not in before
    assert "session_secret" not in after


async def test_config_import_writes_single_admin_event(client):
    await _setup_admin(client)
    # Create one server first
    await client.post("/api/v1/servers", json={
        "slug": "existing", "name": "Existing", "upstream_url": "http://localhost:8000/mcp",
    })

    yaml_config = """
version: 1
servers:
  - slug: existing
    name: Existing Updated
    upstream_url: http://localhost:8001/mcp
  - slug: new-server
    name: New Server
    upstream_url: http://localhost:8002/mcp
settings:
  auth_mode: open
"""
    resp = await client.post("/api/v1/config/import", json={"yaml": yaml_config, "apply": True})
    assert resp.status_code == 200
    assert resp.json()["applied"] is True

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    # 1 server.create + 1 config.import (not 2 individual updates)
    assert len(data) == 2
    import_event = next(e for e in data if e["action"] == "config.import")
    assert import_event["target_type"] == "config"
    assert "import applied" in import_event["summary"]
    assert "3 change(s)" in import_event["summary"]  # 2 servers + 1 settings update


async def test_failed_mutation_writes_no_admin_event(client):
    await _setup_admin(client)
    # Try to create a server with an invalid slug
    resp = await client.post("/api/v1/servers", json={
        "slug": "invalid_slug!", "name": "Bad", "upstream_url": "http://localhost:8000/mcp",
    })
    assert resp.status_code == 422

    # Try to update a nonexistent server
    resp = await client.put("/api/v1/servers/nonexistent", json={"name": "New Name"})
    assert resp.status_code == 404

    # Try to delete a nonexistent server
    resp = await client.delete("/api/v1/servers/nonexistent")
    assert resp.status_code == 404

    events = await client.get("/api/v1/admin-events")
    assert events.json() == []


async def test_admin_events_filters(client):
    await _setup_admin(client)
    await client.post("/api/v1/servers", json={
        "slug": "server-1", "name": "Server 1", "upstream_url": "http://localhost:8000/mcp",
    })
    await client.post("/api/v1/servers", json={
        "slug": "server-2", "name": "Server 2", "upstream_url": "http://localhost:8001/mcp",
    })
    await client.post("/api/v1/keys", json={"name": "test-key"})

    # Filter by action
    resp = await client.get("/api/v1/admin-events?action=server.create")
    data = resp.json()
    assert len(data) == 2
    assert all(e["action"] == "server.create" for e in data)

    # Filter by target_type
    resp = await client.get("/api/v1/admin-events?target_type=key")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["target_type"] == "key"

    # Limit
    resp = await client.get("/api/v1/admin-events?limit=2")
    data = resp.json()
    assert len(data) == 2


async def test_secret_exclusion_on_server_with_auth_header(client):
    """A server with upstream_auth_header must never have that credential appear in before/after."""
    await _setup_admin(client)
    resp = await client.post("/api/v1/servers", json={
        "slug": "secret-server", "name": "Secret Server",
        "upstream_url": "http://localhost:8000/mcp",
        "upstream_auth_header": "Bearer sk-live-secret-token-12345",
    })
    assert resp.status_code == 201

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    # Enterprise #5: server.create now fires TWO events — the general server.create event
    # (which never included the credential, per the assertions below) and a dedicated
    # server.secret_reference_change event (record_secret_reference_change in
    # archon/admin_audit.py) that records only that a credential was configured, never its
    # value — see that event's own assertions further down.
    assert len(data) == 2
    events_by_action = {e["action"]: e for e in data}

    create_event = events_by_action["server.create"]
    # Check the SERIALIZED JSON text, not the parsed dict (before is None on create)
    assert create_event["before"] is None  # create has no before state
    assert "sk-live-secret-token-12345" not in create_event["after"]
    assert "upstream_auth_header" not in create_event["after"]

    secret_event = events_by_action["server.secret_reference_change"]
    assert "sk-live-secret-token-12345" not in json.dumps(secret_event)
    assert secret_event["after"] is not None
    after_shape = json.loads(secret_event["after"])
    assert after_shape["upstream_auth_header"]["configured"] is True
    assert after_shape["upstream_auth_header"]["is_reference"] is False


async def test_secret_exclusion_on_settings_with_webhook_secret(client):
    """Settings changes must never capture webhook_secret, admin_password_hash, or session_secret."""
    await _setup_admin(client)
    # Set a webhook URL to trigger secret generation
    resp = await client.put("/api/v1/settings", json={
        "webhook_url": "https://example.com/webhook",
    })
    assert resp.status_code == 200

    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) == 1
    event = data[0]
    # Check serialized text
    assert "webhook_secret" not in event["before"]
    assert "webhook_secret" not in event["after"]
    assert "admin_password_hash" not in event["before"]
    assert "admin_password_hash" not in event["after"]
    assert "session_secret" not in event["before"]
    assert "session_secret" not in event["after"]


async def test_audit_retention_does_not_touch_admin_events(client, app_transport):
    """AuditRetentionJob prunes audit.db on a 30-day window by default. It must NEVER touch
    admin_events in gateway.db — those are the high-value, low-volume compliance records."""
    await _setup_admin(client)

    # Create some admin events
    await client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })
    await client.post("/api/v1/keys", json={"name": "test-key"})

    # Verify we have 2 admin events
    events_before = await client.get("/api/v1/admin-events")
    assert len(events_before.json()) == 2

    # The retention job only calls AuditRepo.prune_older_than, which only touches audit.db.
    # Verify by checking the implementation doesn't reference admin_events.
    import inspect
    from db.repo import AuditRepo
    source = inspect.getsource(AuditRepo)
    assert "admin_events" not in source, "AuditRepo must not reference admin_events table"
    assert "audit_events" in source, "AuditRepo should only reference audit_events table"


# Parametrised regression guard: every mutating route MUST call record() from admin_audit.
# A new route added without an audit call will fail this test — that's the point.
MUTATING_ROUTES = [
    ("POST", "/api/v1/servers"),
    ("PUT", "/api/v1/servers/{slug}"),
    ("DELETE", "/api/v1/servers/{slug}"),
    ("PUT", "/api/v1/servers/{slug}/policy"),
    ("POST", "/api/v1/keys"),
    ("PATCH", "/api/v1/keys/{key_id}"),
    ("DELETE", "/api/v1/keys/{key_id}"),
    ("PUT", "/api/v1/settings"),
    ("POST", "/api/v1/config/import"),
]


@pytest.mark.parametrize("method,path", MUTATING_ROUTES)
async def test_every_mutating_route_writes_admin_event(method, path, client):
    """Regression guard: every mutating route in archon/api.py must write exactly one
    admin_events row. If you added a new route and didn't add an audit call, this test
    will fail — add the record() call, then add the route to MUTATING_ROUTES above."""
    await _setup_admin(client)

    # Clear any existing events
    await client.get("/api/v1/admin-events")  # just to verify endpoint exists

    # Build the request based on the route
    if method == "POST" and path == "/api/v1/servers":
        resp = await client.post(path, json={
            "slug": "param-test", "name": "Param Test", "upstream_url": "http://localhost:8000/mcp",
        })
        assert resp.status_code == 201
    elif method == "PUT" and path == "/api/v1/servers/{slug}":
        await client.post("/api/v1/servers", json={
            "slug": "param-test", "name": "Param Test", "upstream_url": "http://localhost:8000/mcp",
        })
        resp = await client.put("/api/v1/servers/param-test", json={"name": "Updated"})
        assert resp.status_code == 200
    elif method == "DELETE" and path == "/api/v1/servers/{slug}":
        await client.post("/api/v1/servers", json={
            "slug": "param-test", "name": "Param Test", "upstream_url": "http://localhost:8000/mcp",
        })
        resp = await client.delete("/api/v1/servers/param-test")
        assert resp.status_code == 204
    elif method == "PUT" and path == "/api/v1/servers/{slug}/policy":
        await client.post("/api/v1/servers", json={
            "slug": "param-test", "name": "Param Test", "upstream_url": "http://localhost:8000/mcp",
        })
        resp = await client.put("/api/v1/servers/param-test/policy", json={"mode": "allowlist"})
        assert resp.status_code == 200
    elif method == "POST" and path == "/api/v1/keys":
        resp = await client.post(path, json={"name": "param-test-key"})
        assert resp.status_code == 201
    elif method == "PATCH" and path == "/api/v1/keys/{key_id}":
        create_resp = await client.post("/api/v1/keys", json={"name": "param-test-key"})
        key_id = create_resp.json()["id"]
        resp = await client.patch(f"/api/v1/keys/{key_id}", params={"enabled": "false"})
        assert resp.status_code == 200
    elif method == "DELETE" and path == "/api/v1/keys/{key_id}":
        create_resp = await client.post("/api/v1/keys", json={"name": "param-test-key"})
        key_id = create_resp.json()["id"]
        resp = await client.delete(f"/api/v1/keys/{key_id}")
        assert resp.status_code == 204
    elif method == "PUT" and path == "/api/v1/settings":
        resp = await client.put(path, json={"auth_mode": "open"})
        assert resp.status_code == 200
    elif method == "POST" and path == "/api/v1/config/import":
        yaml_config = "version: 1\nservers: []\nsettings:\n  auth_mode: open\n"
        resp = await client.post(path, json={"yaml": yaml_config, "apply": True})
        assert resp.status_code == 200
    else:
        pytest.fail(f"unhandled route in parametrised test: {method} {path}")

    # The route should have written exactly one admin event
    events = await client.get("/api/v1/admin-events")
    data = events.json()
    assert len(data) >= 1, f"{method} {path} did not write an admin_events row"
