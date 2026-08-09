"""Integration tests for enterprise #10 (DLP redaction on tool arguments).

Two upstream fixtures are used, deliberately for different claims:

- `_BodyCapturingUpstream` — a minimal raw TCP listener (same style as
  test_security_regression.py's `_HeaderCapturingUpstream`) that captures the EXACT request
  body Acropolis forwards. Used to prove what actually crosses the wire on `redact`, not what
  a mock was told to expect.
- `run_fastmcp_server` (shared fixture) — a real FastMCP upstream whose `echo` tool reflects
  back whatever argument it actually received, AND exposes a `call_counter` — used to prove a
  `block` decision never reaches the upstream at all.
"""
from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Optional

import httpx
import pytest
import yaml

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import AuditRepo, ServerRepo

from .fastmcp_fixture import run_fastmcp_server


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _BodyCapturingUpstream:
    """Raw TCP listener standing in for an MCP upstream — captures the exact request BODY
    Acropolis forwards (not just headers, unlike test_security_regression.py's
    _HeaderCapturingUpstream). Proves what crosses the wire, honestly, rather than asserting
    against a mock's recorded call args."""

    def __init__(self) -> None:
        self.received_bodies: list[bytes] = []
        self.call_count = 0
        self._server: Optional[asyncio.AbstractServer] = None
        self.url = ""

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.call_count += 1
        head = await reader.readuntil(b"\r\n\r\n")
        content_length = 0
        for line in head.decode(errors="replace").split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
        body = await reader.readexactly(content_length) if content_length else b""
        self.received_bodies.append(body)

        response_body = b'{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}}'
        writer.write(
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(response_body)}\r\n\r\n"
            ).encode()
            + response_body
        )
        await writer.drain()
        writer.close()

    async def start(self) -> None:
        port = _free_port()
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


@pytest.fixture
async def body_capturing_upstream():
    upstream = _BodyCapturingUpstream()
    await upstream.start()
    try:
        yield upstream
    finally:
        await upstream.stop()


@pytest.fixture
async def app_and_db(tmp_path: Path, body_capturing_upstream):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="dlp-test", name="DLP Test", upstream_url=body_capturing_upstream.url)

    app = create_app(settings, db)
    async with app.router.lifespan_context(app):
        yield app, db, server_repo
    await db.close()


async def _post_tools_call(app, slug: str, tool: str, arguments: dict, rpc_id: int = 1) -> httpx.Response:
    """Sends a plain 2025-generation (no Mcp-Method header) tools/call — Pipeline._process
    routes this straight to raw passthrough forwarding, a direct 1:1 request with no MCP
    handshake round-trips first. Used against the raw-socket _BodyCapturingUpstream, where a
    minimal fixed-response listener can't participate in a real initialize/notifications
    handshake — passthrough is the correct generation for proving what a single forwarded
    request's body looks like on the wire."""
    transport = httpx.ASGITransport(app=app)
    body = {
        "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        return await client.post(f"/mcp/{slug}/mcp", json=body)


async def _post_2026_tools_call(app, slug: str, tool: str, arguments: dict, rpc_id: int = 1) -> httpx.Response:
    """Sends a 2026-generation stateless tools/call (Mcp-Method/Mcp-Name headers on every
    request, no prior initialize) — same shape as test_bridged_e2e.py's working pattern.
    Used against the real FastMCP upstream fixture, which correctly answers the bridge's
    handshake round-trips."""
    transport = httpx.ASGITransport(app=app)
    body = {
        "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    headers = {
        "Content-Type": "application/json", "Accept": "application/json",
        "Mcp-Method": "tools/call", "Mcp-Name": tool,
    }
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        return await client.post(f"/mcp/{slug}", json=body, headers=headers)


# ---------------------------------------------------------------------------
# redact — the wire-level claim: the UPSTREAM actually received the redacted body
# ---------------------------------------------------------------------------

class TestRedactActuallyMutatesForwardedBody:
    async def test_upstream_receives_redacted_argument_not_original(self, app_and_db, body_capturing_upstream):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"email": "redact"}))

        resp = await _post_tools_call(
            app, "dlp-test", "echo", {"message": "contact nick@example.com for details"}
        )
        assert resp.status_code == 200

        assert body_capturing_upstream.call_count == 1
        raw_body = body_capturing_upstream.received_bodies[0]
        # The actual claim under test: the raw bytes that left the process do not contain the
        # secret, and do contain the redaction placeholder — not the client's response, not a
        # mock's recorded call, the literal bytes read off the socket on the upstream side.
        assert b"nick@example.com" not in raw_body
        assert b"[REDACTED:email]" in raw_body

        forwarded = json.loads(raw_body)
        assert forwarded["params"]["arguments"]["message"] == "contact [REDACTED:email] for details"
        # Everything else about the envelope must be preserved untouched.
        assert forwarded["params"]["name"] == "echo"
        assert forwarded["jsonrpc"] == "2.0"

    async def test_redact_preserves_untouched_sibling_arguments(self, app_and_db, body_capturing_upstream):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"email": "redact"}))

        await _post_tools_call(
            app, "dlp-test", "write_file",
            {"path": "/tmp/notes.txt", "content": "email nick@example.com", "overwrite": True},
        )
        raw_body = body_capturing_upstream.received_bodies[0]
        forwarded = json.loads(raw_body)
        args = forwarded["params"]["arguments"]
        assert args["path"] == "/tmp/notes.txt"  # untouched
        assert args["overwrite"] is True  # untouched, right type preserved
        assert "nick@example.com" not in args["content"]


# ---------------------------------------------------------------------------
# block — never reaches the upstream at all
# ---------------------------------------------------------------------------

class TestBlockNeverReachesUpstream:
    async def test_block_returns_403_and_upstream_is_never_contacted(self, app_and_db, body_capturing_upstream):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "block"}))

        resp = await _post_tools_call(app, "dlp-test", "echo", {"message": "card 4111111111111111"})
        assert resp.status_code == 403
        assert body_capturing_upstream.call_count == 0
        assert body_capturing_upstream.received_bodies == []

    async def test_block_writes_blocked_audit_row_naming_the_detector(self, app_and_db):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "block"}))
        await _post_tools_call(app, "dlp-test", "echo", {"message": "card 4111111111111111"})

        # Audit writes are batched/async — give the flush loop a beat.
        await asyncio.sleep(0.3)
        audit_repo = AuditRepo(db)
        rows = await audit_repo.query(server_slug="dlp-test", decision="BLOCKED")
        assert len(rows) == 1
        assert rows[0]["dlp_detector"] == "credit_card"
        assert rows[0]["dlp_action"] == "block"
        assert rows[0]["rule"] == "dlp"


# ---------------------------------------------------------------------------
# Audit row: the matched/redacted value must NEVER appear anywhere in the serialized row
# ---------------------------------------------------------------------------

class TestAuditRowNeverContainsMatchedValue:
    async def test_redact_audit_row_excludes_the_secret_entirely(self, app_and_db):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"email": "redact"}))
        await _post_tools_call(app, "dlp-test", "echo", {"message": "contact nick@example.com now"})

        await asyncio.sleep(0.3)
        audit_repo = AuditRepo(db)
        rows = await audit_repo.query(server_slug="dlp-test")
        assert len(rows) == 1
        row = rows[0]

        # Discipline matching the control-plane audit PR's secret-exclusion tests: assert on
        # the fully serialized row text, not just individual fields, so a leak via an
        # unexpected column can't slip past a narrower assertion.
        serialized = json.dumps(dict(row), default=str)
        assert "nick@example.com" not in serialized
        assert row["dlp_detector"] == "email"
        assert row["dlp_action"] == "redact"
        assert row["decision"] == "ALLOWED"

    async def test_block_audit_row_excludes_the_secret_entirely(self, app_and_db):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "block"}))
        await _post_tools_call(app, "dlp-test", "echo", {"message": "card 4111111111111111 expires soon"})

        await asyncio.sleep(0.3)
        audit_repo = AuditRepo(db)
        rows = await audit_repo.query(server_slug="dlp-test", decision="BLOCKED")
        assert len(rows) == 1
        serialized = json.dumps(dict(rows[0]), default=str)
        assert "4111111111111111" not in serialized

    async def test_custom_pattern_match_never_appears_in_audit_row(self, app_and_db):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import DlpCustomPattern, ServerPolicy

        await server_repo.set_policy(
            server.id,
            ServerPolicy(
                mode="passthrough",
                dlp_custom_patterns=[DlpCustomPattern(name="internal_id", pattern=r"EMP-\d{6}", action="redact")],
            ),
        )
        await _post_tools_call(app, "dlp-test", "echo", {"message": "employee EMP-654321 requested"})

        await asyncio.sleep(0.3)
        audit_repo = AuditRepo(db)
        rows = await audit_repo.query(server_slug="dlp-test")
        serialized = json.dumps(dict(rows[0]), default=str)
        assert "EMP-654321" not in serialized
        assert rows[0]["dlp_detector"] == "internal_id"


# ---------------------------------------------------------------------------
# Regression: no DLP config configured == byte-identical to pre-DLP behavior
# ---------------------------------------------------------------------------

class TestNoDlpConfigIsUnchangedBehavior:
    async def test_no_dlp_detectors_forwards_body_unmodified(self, app_and_db, body_capturing_upstream):
        """The hard regression-test requirement: a server with no dlp_detectors/
        dlp_custom_patterns configured must forward the EXACT original body bytes for the
        arguments portion — even when the argument content would match a detector if one were
        configured — proving default-off is really off, not just off by default action."""
        app, db, server_repo = app_and_db

        resp = await _post_tools_call(
            app, "dlp-test", "echo",
            {"message": "card 4111111111111111 and email nick@example.com and AKIAIOSFODNN7EXAMPLE"},
        )
        assert resp.status_code == 200
        raw_body = body_capturing_upstream.received_bodies[0]
        forwarded = json.loads(raw_body)
        assert forwarded["params"]["arguments"]["message"] == (
            "card 4111111111111111 and email nick@example.com and AKIAIOSFODNN7EXAMPLE"
        )


# ---------------------------------------------------------------------------
# Config export/import round trip
# ---------------------------------------------------------------------------

class TestDlpConfigExportImportRoundTrip:
    async def test_dlp_config_survives_export_then_import(self, app_and_db):
        app, db, server_repo = app_and_db
        server = await server_repo.get("dlp-test")
        from db.models import DlpCustomPattern, ServerPolicy

        original = ServerPolicy(
            mode="passthrough",
            dlp_detectors={"credit_card": "block", "email": "redact"},
            dlp_custom_patterns=[DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="redact")],
        )
        await server_repo.set_policy(server.id, original)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            export_resp = await client.get("/api/v1/config/export")
            assert export_resp.status_code == 200
            exported_yaml = export_resp.text

            # Round-trip: import the exact export back in and confirm plan_import reports the
            # DLP-bearing server as unchanged — the strongest possible round-trip assertion,
            # since ANY drift in the DLP fields would show up as an "update" action instead.
            import_resp = await client.post("/api/v1/config/import", json={"yaml": exported_yaml})
            assert import_resp.status_code == 200
            body = import_resp.json()
            server_actions = [a for a in body["actions"] if a["target"] == "server 'dlp-test'"]
            assert len(server_actions) == 1
            assert server_actions[0]["kind"] == "unchanged", server_actions[0]

        # Also verify the exported YAML text itself actually carries the DLP fields (not just
        # "didn't change" by accident because it round-tripped as empty on both sides).
        data = yaml.safe_load(exported_yaml)
        server_entry = next(s for s in data["servers"] if s["slug"] == "dlp-test")
        assert server_entry["policy"]["dlp_detectors"] == {"credit_card": "block", "email": "redact"}
        assert server_entry["policy"]["dlp_custom_patterns"][0]["name"] == "employee_id"

    async def test_import_of_dlp_config_onto_fresh_server_applies_it(self, app_and_db):
        app, db, server_repo = app_and_db
        doc = yaml.safe_dump({
            "version": 1,
            "servers": [{
                "slug": "brand-new-dlp", "name": "New", "upstream_url": "http://127.0.0.1:9099/mcp",
                "policy": {
                    "mode": "passthrough",
                    "dlp_detectors": {"credit_card": "block"},
                    "dlp_custom_patterns": [],
                },
            }],
        })
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
            assert resp.json()["applied"] is True

            policy_resp = await client.get("/api/v1/servers/brand-new-dlp/policy")
            assert policy_resp.json()["dlp_detectors"] == {"credit_card": "block"}


# ---------------------------------------------------------------------------
# Live-shaped check against a real FastMCP upstream (call_counter, echoed argument)
# ---------------------------------------------------------------------------

class TestAgainstRealFastMcpUpstream:
    @pytest.fixture
    async def fastmcp_app_and_db(self, tmp_path: Path):
        async with run_fastmcp_server() as upstream:
            settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
            db = Database(tmp_path)
            await db.connect()
            server_repo = ServerRepo(db)
            await server_repo.create(slug="live-dlp", name="Live DLP", upstream_url=f"{upstream.url}/mcp")
            app = create_app(settings, db)
            async with app.router.lifespan_context(app):
                yield app, db, server_repo, upstream
            await db.close()

    async def test_redact_against_real_fastmcp_upstream_echoes_redacted_text(self, fastmcp_app_and_db):
        app, db, server_repo, upstream = fastmcp_app_and_db
        server = await server_repo.get("live-dlp")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "redact"}))

        resp = await _post_2026_tools_call(app, "live-dlp", "echo", {"message": "card 4111111111111111 on file"})
        assert resp.status_code == 200
        body = resp.json()
        # The real FastMCP tool handler received and echoed back whatever argument value
        # actually arrived — a second, independent proof (distinct from the raw-socket
        # capture above) that the redacted form, not the original, reached the upstream.
        text = json.dumps(body)
        assert "4111111111111111" not in text
        assert "[REDACTED:credit_card]" in text
        assert upstream.call_counter.get("echo") == 1

    async def test_block_against_real_fastmcp_upstream_never_calls_the_tool(self, fastmcp_app_and_db):
        app, db, server_repo, upstream = fastmcp_app_and_db
        server = await server_repo.get("live-dlp")
        from db.models import ServerPolicy

        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "block"}))

        resp = await _post_2026_tools_call(app, "live-dlp", "echo", {"message": "card 4111111111111111 on file"})
        assert resp.status_code == 403
        assert upstream.call_counter.get("echo", 0) == 0
