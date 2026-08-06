"""M3 control-plane additions: settings, stats, audit query + live tail."""
from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from pathlib import Path

import httpx
import pytest
import uvicorn

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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.asynccontextmanager
async def _run_real_server(tmp_path: Path):
    """A real uvicorn server, not ASGITransport — needed for the SSE tail test, since
    ASGITransport blocks a request until the ASGI app's response is fully "complete," which
    never happens for a genuinely long-lived stream running concurrently with other requests
    in the same test process."""
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("test server did not start in time")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task
        await db.close()


async def test_get_settings_defaults(api_client):
    resp = await api_client.get("/api/v1/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth_mode"] == "keyed"
    assert body["aggregate_enabled"] is True
    assert body["setup_complete"] is False


async def test_update_settings(api_client):
    resp = await api_client.put("/api/v1/settings", json={"auth_mode": "open", "audit_retention_days": 7})
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth_mode"] == "open"
    assert body["audit_retention_days"] == 7

    # Persisted — a fresh GET reflects it.
    resp2 = await api_client.get("/api/v1/settings")
    assert resp2.json()["auth_mode"] == "open"


async def test_update_settings_rejects_invalid_auth_mode(api_client):
    resp = await api_client.put("/api/v1/settings", json={"auth_mode": "bogus"})
    assert resp.status_code == 400


async def test_stats_empty_state(api_client):
    resp = await api_client.get("/api/v1/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["requests_24h"] == 0
    assert body["servers_total"] == 0


async def test_stats_reflects_registered_servers(api_client):
    await api_client.post(
        "/api/v1/servers", json={"slug": "s1", "name": "S1", "upstream_url": "http://x/mcp"}
    )
    resp = await api_client.get("/api/v1/stats")
    body = resp.json()
    assert body["servers_total"] == 1
    assert len(body["server_health"]) == 1
    assert body["server_health"][0]["slug"] == "s1"


async def test_audit_query_empty(api_client):
    resp = await api_client.get("/api/v1/audit")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_audit_query_after_a_blocked_call(api_client):
    await api_client.post(
        "/api/v1/servers", json={"slug": "s2", "name": "S2", "upstream_url": "http://127.0.0.1:1/mcp"}
    )
    await api_client.put(
        "/api/v1/servers/s2/policy",
        json={"mode": "allowlist", "allowed": [], "denied": [], "param_rules": {}},
    )
    # Hit the data plane directly (same client, same app) to generate a BLOCKED audit event.
    await api_client.post(
        "/mcp/s2",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "echo", "arguments": {}}},
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )

    await asyncio.sleep(0.3)  # audit flush interval

    resp = await api_client.get("/api/v1/audit", params={"decision": "BLOCKED"})
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) == 1
    assert events[0]["server_slug"] == "s2"
    assert events[0]["rule"] == "allowlist"


async def test_audit_query_accepts_new_filter_params(api_client):
    # A pure passthrough smoke test: confirms the route accepts the new query params without
    # erroring (FastAPI would 422 an unrecognized/mistyped param) and the response shape is
    # unaffected when they filter out everything.
    resp = await api_client.get(
        "/api/v1/audit",
        params={"api_key_id": 999, "after": "2020-01-01T00:00:00Z", "before": "2030-01-01T00:00:00Z", "search": "nope"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_audit_export_csv_empty(api_client):
    resp = await api_client.get("/api/v1/audit/export.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=" in resp.headers["content-disposition"]
    lines = resp.text.strip("\r\n").split("\r\n")
    assert lines == ["id,ts,server_slug,api_key_id,client_ip,endpoint,rpc_method,tool,decision,rule,matched,reason,args_summary,bridged,status_code,latency_ms,origin"]


async def test_audit_export_csv_includes_matching_rows_and_respects_filters(api_client):
    await api_client.post(
        "/api/v1/servers", json={"slug": "s3", "name": "S3", "upstream_url": "http://127.0.0.1:1/mcp"}
    )
    await api_client.put(
        "/api/v1/servers/s3/policy",
        json={"mode": "allowlist", "allowed": [], "denied": [], "param_rules": {}},
    )
    await api_client.post(
        "/mcp/s3",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "echo", "arguments": {}}},
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    await asyncio.sleep(0.3)

    resp = await api_client.get("/api/v1/audit/export.csv", params={"decision": "BLOCKED"})
    assert resp.status_code == 200
    rows = resp.text.strip("\r\n").split("\r\n")
    assert len(rows) == 2  # header + 1 event
    assert "s3" in rows[1]

    resp_none = await api_client.get("/api/v1/audit/export.csv", params={"decision": "ALLOWED"})
    rows_none = resp_none.text.strip("\r\n").split("\r\n")
    assert len(rows_none) == 1  # header only


async def test_audit_export_csv_defuses_formula_injection(tmp_path: Path):
    from db.repo import AuditRepo

    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    audit_repo = AuditRepo(db)
    await audit_repo._conn.execute(
        "INSERT INTO audit_events (ts, server_slug, decision, reason, args_summary) "
        "VALUES (?, 'x', 'BLOCKED', ?, ?)",
        ("2026-01-01T00:00:00Z", "=cmd(calc)", "@SUM(1,1)"),
    )
    await audit_repo._conn.commit()

    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            resp = await client.get("/api/v1/audit/export.csv")
    await db.close()

    assert resp.status_code == 200
    rows = resp.text.strip("\r\n").split("\r\n")
    assert len(rows) == 2
    data_row = rows[1]
    assert "'=cmd(calc)" in data_row
    assert "'@SUM(1,1)" in data_row


async def test_audit_tail_receives_live_event(tmp_path: Path):
    async with _run_real_server(tmp_path) as base_url:
        async with httpx.AsyncClient(base_url=base_url) as client:
            await client.post(
                "/api/v1/servers",
                json={"slug": "s3", "name": "S3", "upstream_url": "http://127.0.0.1:1/mcp"},
            )
            await client.put(
                "/api/v1/servers/s3/policy",
                json={"mode": "allowlist", "allowed": [], "denied": [], "param_rules": {}},
            )

            async def fire_blocked_call():
                await asyncio.sleep(0.3)
                async with httpx.AsyncClient(base_url=base_url) as data_client:
                    await data_client.post(
                        "/mcp/s3",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "echo", "arguments": {}}},
                        headers={"Content-Type": "application/json",
                                 "Accept": "application/json, text/event-stream"},
                    )

            fire_task = asyncio.create_task(fire_blocked_call())

            async def read_first_data_line():
                async with client.stream("GET", "/api/v1/audit/tail") as resp:
                    assert resp.status_code == 200
                    async for line in resp.aiter_lines():
                        if line.startswith("data:"):
                            return json.loads(line[len("data:"):].strip())
                return None

            received = await asyncio.wait_for(read_first_data_line(), timeout=10.0)
            await fire_task

    assert received is not None
    assert received["server_slug"] == "s3"
    assert received["decision"] == "BLOCKED"
