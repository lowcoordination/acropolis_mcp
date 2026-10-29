"""Issue #166: a POST body that is not a single JSON-RPC object must be refused, never forwarded.

Before the fix, `Pipeline._process` treated a JSON-RPC batch (top-level array) as "unparseable"
and handed the raw bytes to `_forward`, skipping `_enforce` entirely: a denylisted tool
wrapped in `[...]` went to the upstream with no BLOCKED audit row. MCP 2025-06-18 removed
batching, and its Streamable HTTP transport says the POST body MUST be a single JSON-RPC
message, so no version Acropolis supports needs batches handled.

`Pipeline._forward` is replaced with a spy. "Never forwarded" is asserted directly, so it does
not depend on whether some upstream would execute a batch. FastMCP 1.29 rejects batches
itself, so a call counter on a real upstream would pass vacuously against the unpatched code.
"""
from __future__ import annotations

import asyncio
import gzip
import json
from pathlib import Path

import httpx
import pytest
from starlette.responses import Response

from archon.settings import Settings
from argus.app import create_app
from argus.pipeline import Pipeline
from db.database import Database
from db.models import ServerPolicy
from db.repo import AuditRepo, ServerRepo

HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def _call(tool: str, req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
        "params": {"name": tool, "arguments": {"path": "/x", "content": "y", "message": "m"}},
    }


DENIED = json.dumps(_call("write_file")).encode()
ALLOWED = json.dumps(_call("echo")).encode()

# (body, expected JSON-RPC error code). -32600 = Invalid Request, -32700 = Parse error.
REFUSED_BODIES = {
    "batch-one-denied": (b"[" + DENIED + b"]", -32600),
    "batch-one-allowed": (b"[" + ALLOWED + b"]", -32600),
    "batch-many": (b"[" + ALLOWED + b"," + DENIED + b"," + ALLOWED + b"]", -32600),
    "batch-nested": (b"[[" + DENIED + b"]]", -32600),
    "batch-whitespace-prefixed": (b" \r\n\t [" + DENIED + b"]", -32600),
    "batch-bom-prefixed": (b"\xef\xbb\xbf[" + DENIED + b"]", -32600),
    "batch-empty": (b"[]", -32600),
    "batch-empty-whitespace": (b"  [ ]  ", -32600),
    "scalar-string": (b'"tools/call"', -32600),
    "scalar-number": (b"42", -32600),
    "scalar-null": (b"null", -32600),
    "scalar-true": (b"true", -32600),
    "unparseable-truncated": (DENIED[:-5], -32700),
    "unparseable-trailing-comma": (DENIED[:-1] + b",}", -32700),
    "unparseable-two-objects": (DENIED + DENIED, -32700),
    "invalid-utf8": (b'{"jsonrpc":"2.0","method":"\xff"}', -32700),
    "deeply-nested": (b"[" * 100_000, -32700),
    # Acropolis does not decode Content-Encoding. A compressed body used to be forwarded for
    # the upstream to decompress, unread.
    "gzip-compressed": (gzip.compress(DENIED), -32700),
    # json.loads auto-detects UTF-16/32, so this is read as a list and refused like any batch.
    "batch-utf16": (("[" + DENIED.decode() + "]").encode("utf-16"), -32600),
}


@pytest.fixture
async def gateway(tmp_path: Path, monkeypatch):
    forwarded: list[bytes] = []

    async def spy_forward(self, request, server, path, body_bytes, resolved_auth_header):
        forwarded.append(body_bytes)
        return Response(content=b"{}", status_code=200, media_type="application/json")

    monkeypatch.setattr(Pipeline, "_forward", spy_forward)

    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open",
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    # Nothing listens here. The spy means nothing ever connects to it.
    await server_repo.create(slug="test-server", name="Test", upstream_url="http://127.0.0.1:9/mcp")
    server = await server_repo.get("test-server")
    await server_repo.set_policy(server.id, ServerPolicy(mode="denylist", denied=["write_file"]))

    app = create_app(settings, db)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://argus.test",
        ) as client:
            yield client, forwarded, db
    await db.close()


async def _audit_rows(db, decision: str) -> list[dict]:
    """Wait for the audit logger's background flush instead of sleeping a fixed interval,
    which flaked under load. Then wait one more interval, so a duplicate row shows up too."""
    repo = AuditRepo(db)
    for _ in range(50):
        rows = await repo.query(decision=decision)
        if rows:
            await asyncio.sleep(0.3)
            return await repo.query(decision=decision)
        await asyncio.sleep(0.1)
    return []


async def test_single_denied_call_is_blocked(gateway):
    """Control: the unwrapped call is refused, so the batch tests below are testing the wrapper."""
    client, forwarded, _ = gateway
    r = await client.post("/mcp/test-server", content=DENIED, headers=HEADERS)
    assert r.status_code == 403
    assert forwarded == []


async def test_single_allowed_call_is_forwarded(gateway):
    """Control: the spy really does see forwarded traffic."""
    client, forwarded, _ = gateway
    r = await client.post("/mcp/test-server", content=ALLOWED, headers=HEADERS)
    assert r.status_code == 200
    assert len(forwarded) == 1


@pytest.mark.parametrize("name", list(REFUSED_BODIES))
async def test_non_object_body_is_refused_and_audited_per_server(gateway, name):
    body, code = REFUSED_BODIES[name]
    client, forwarded, db = gateway
    r = await client.post("/mcp/test-server", content=body, headers=HEADERS)

    assert forwarded == [], f"{name}: body was forwarded to the upstream"
    assert r.status_code == 400, r.text
    err = r.json()
    assert err["jsonrpc"] == "2.0" and err["id"] is None
    assert err["error"]["code"] == code

    rows = await _audit_rows(db, "BLOCKED")
    assert len(rows) == 1, rows
    assert rows[0]["server_slug"] == "test-server"
    assert rows[0]["rule"] == "single_message"
    assert rows[0]["endpoint"] == "per-server"


@pytest.mark.parametrize("name", list(REFUSED_BODIES))
async def test_non_object_body_is_refused_and_audited_aggregate(gateway, name):
    body, code = REFUSED_BODIES[name]
    client, forwarded, db = gateway
    r = await client.post("/mcp", content=body, headers=HEADERS)

    assert forwarded == []
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == code

    rows = await _audit_rows(db, "BLOCKED")
    assert len(rows) == 1, rows
    assert rows[0]["rule"] == "single_message"
    assert rows[0]["endpoint"] == "aggregate"


async def test_utf16_single_denied_call_is_still_enforced(gateway):
    """json.loads reads UTF-16, so the gateway sees the tool name and enforces it."""
    client, forwarded, _ = gateway
    r = await client.post("/mcp/test-server", content=DENIED.decode().encode("utf-16"), headers=HEADERS)
    assert r.status_code == 403
    assert forwarded == []


@pytest.mark.parametrize("method", ["PUT", "PATCH", "GET", "DELETE", "OPTIONS"])
async def test_body_on_non_post_method_is_refused(gateway, method):
    """_forward relays request.method and the raw body. Before #166, a tools/call body on any
    method but POST skipped parsing and enforcement and went straight to the upstream."""
    client, forwarded, db = gateway
    r = await client.request(method, "/mcp/test-server", content=DENIED, headers=HEADERS)
    assert forwarded == [], f"{method} body was forwarded"
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600
    rows = await _audit_rows(db, "BLOCKED")
    assert len(rows) == 1 and rows[0]["rule"] == "single_message"


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_bodiless_non_post_is_still_forwarded(gateway, method):
    """Control: the SSE GET and the session-ending DELETE carry no body and must still pass."""
    client, forwarded, _ = gateway
    r = await client.request(method, "/mcp/test-server", headers=HEADERS)
    assert r.status_code == 200
    assert forwarded == [b""]
