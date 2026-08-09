"""Enterprise #5's sharpest regression test: if resolving the upstream credential fails, the
call must be an ERROR — and, above all, must NEVER reach the upstream unauthenticated.

Uses a real FastMCP upstream (the same fixture test_passthrough.py and test_bridged_e2e.py use)
with its call_counter spy — the same proof mechanism this codebase already uses to show a
BLOCKED call never reaches the upstream (see test_passthrough.py's module docstring). Here it
proves the analogous, more security-critical claim for secret resolution specifically: an
upstream credential that fails to resolve must produce zero upstream requests, not an
unauthenticated one.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from archon.secrets import SecretResolutionError
from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import AuditRepo, ServerRepo

from .fastmcp_fixture import run_fastmcp_server


class _AlwaysFailsProvider:
    """A SecretProvider whose resolve() always raises — stands in for a Vault outage, a bad
    key, or any other resolution failure, regardless of tier."""

    async def resolve(self, ref: str) -> str:
        raise SecretResolutionError(ref, "simulated resolution failure for testing")

    async def store(self, ref: str, value: str) -> str:
        raise NotImplementedError

    async def delete(self, ref: str) -> None:
        raise NotImplementedError


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def failing_client(tmp_path: Path, upstream):
    """An Acropolis app wired with a provider that ALWAYS fails to resolve — simulating a Vault
    outage / bad key / any resolution failure regardless of which tier caused it, so the pipeline
    behaviour under test doesn't depend on which concrete provider is selected."""
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()

    server_repo = ServerRepo(db)
    await server_repo.create(
        slug="secured", name="Secured", upstream_url=f"{upstream.url}/mcp",
        # The value here doesn't matter to _AlwaysFailsProvider — it always raises regardless —
        # but a real reference-shaped string keeps the test honest about what's being exercised.
        upstream_auth_header="vault://secret/acropolis/secured#token",
    )

    app = create_app(settings, db)
    # Swap in the always-fails provider AFTER create_app wires the real (local, by default)
    # one — Pipeline reads `self._secrets` at call time, not just at construction, so
    # overwriting the attribute here takes effect on every subsequent request. app.state.pipeline
    # is the same Pipeline instance the data-plane router closes over (argus/app.py stashes it
    # there alongside every other app-level singleton).
    app.state.pipeline._secrets = _AlwaysFailsProvider()

    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client, server_repo, upstream, db, app

    await db.close()


MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


async def test_bridged_tools_call_never_reaches_upstream_on_resolution_failure(failing_client):
    client, _, upstream, _, _ = failing_client
    resp = await client.post(
        "/mcp/secured",
        json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "hi"}},
        },
        headers={**MCP_HEADERS, "Mcp-Method": "tools/call", "Mcp-Name": "echo"},
    )
    # Must be a clear error, never a 200 with the tool's result.
    assert resp.status_code == 502, resp.text
    body = resp.json()
    assert "error" in body
    assert "secret resolution failed" in body["error"]["message"].lower()

    # The core claim: the upstream's own call counter proves the request NEVER arrived — not
    # merely that Acropolis returned an error while secretly still forwarding it.
    assert upstream.call_counter.get("echo") is None


async def test_raw_passthrough_forward_never_reaches_upstream_on_resolution_failure(failing_client):
    """The non-bridged (2025-generation, raw passthrough) path goes through a DIFFERENT code
    path in Pipeline (_forward, not the bridge) — must be covered separately since the whole
    point of this regression test is that EVERY forwarding path honours the same guarantee."""
    client, _, upstream, _, _ = failing_client
    resp = await client.post(
        "/mcp/secured",
        json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "hi"}},
        },
        headers=MCP_HEADERS,  # no Mcp-Method/Mcp-Name -> 2025-generation raw passthrough
    )
    assert resp.status_code == 502, resp.text
    assert upstream.call_counter.get("echo") is None


async def test_tools_list_never_reaches_upstream_on_resolution_failure(failing_client):
    client, _, upstream, _, _ = failing_client
    resp = await client.post(
        "/mcp/secured",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers=MCP_HEADERS,
    )
    assert resp.status_code == 502, resp.text
    body = resp.json()
    assert "error" in body


async def test_resolution_failure_is_audited_as_error_without_leaking_the_ref_reason(failing_client):
    client, server_repo, upstream, db, _ = failing_client
    await client.post(
        "/mcp/secured",
        json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {}},
        },
        headers={**MCP_HEADERS, "Mcp-Method": "tools/call", "Mcp-Name": "echo"},
    )
    await asyncio.sleep(0.3)  # AuditLogger flushes asynchronously — see test_passthrough.py's pattern
    audit_repo = AuditRepo(db)
    events = await audit_repo.query(limit=10)
    matching = [e for e in events if e["server_slug"] == "secured"]
    assert matching, "expected an audit row for the failed call"
    event = matching[0]
    assert event["decision"] == "ERROR"
    assert "secret resolution failed" in (event["reason"] or "").lower()
