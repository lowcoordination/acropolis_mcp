"""Issue #154: a failed tools/list fetch must be logged and distinguishable from an empty upstream.

``ToolsCache.get_raw_tools`` degrades to the stale cache (or ``[]``) on an upstream failure — that
is the data-plane contract and stays — but it used to do so silently, so a token-mode server that
rejected the Acropolis token showed an empty Tools card with nothing in the logs. These tests pin:

  * a warning naming the server and the status / exception type is logged;
  * ``get_raw_tools_result`` and ``GET /servers/{slug}/tools`` report ``stale`` / an error reason;
  * the reason and the log carry ONLY our own values — never upstream body, header or exception
    text, which an untrusted upstream controls (the stub below echoes credentials and markup);
  * a successful fetch, and a genuinely empty upstream, are NOT marked stale.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
from pathlib import Path
from typing import Callable, Optional

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from argus.bridge import ProtocolBridge
from argus.toolslist import ToolsCache
from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.repo import ServerRepo

SECRET = "Bearer sk-live-SUPERSECRET-0123456789"
HOSTILE_MARKERS = ("SUPERSECRET", "<script>", "leaky-header-value", "BODYMARKER")
TOOLS = [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object", "properties": {}}}]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Upstream:
    """Raw-TCP 2025-generation upstream whose ``tools/list`` behaviour is switchable. ``initialize``
    always succeeds so the failure lands on tools/list (the ``status != 200`` path); set
    ``reject_all`` to fail the handshake too (the ``BridgeError`` path).

    A rejection answers with a hostile body and headers: markup, a marker string, and the
    Authorization header it received echoed back."""

    def __init__(self) -> None:
        self.tools: list[dict] = TOOLS
        self.tools_status = 200
        self.reject_all = False
        self.reject_body: bytes = b""
        self.url = ""
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            headers: dict[str, str] = {}
            for line in head.decode(errors="replace").split("\r\n")[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.lower()] = v
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            rpc = json.loads(body) if body else {}
            method = rpc.get("method", "")
            echoed = headers.get("authorization", "")

            rejecting = self.reject_all or (method == "tools/list" and self.tools_status != 200)
            if rejecting:
                status = 401 if self.reject_all else self.tools_status
                data = self.reject_body or json.dumps({
                    "jsonrpc": "2.0", "id": rpc.get("id"),
                    "error": {"code": -32000, "message": f"<script>alert(1)</script> BODYMARKER {echoed}"},
                }).encode()
                extra = f"WWW-Authenticate: Bearer error=\"leaky-header-value\" {echoed}\r\n"
            elif method == "initialize":
                status, extra = 200, ""
                data = json.dumps({"jsonrpc": "2.0", "id": rpc.get("id"), "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "serverInfo": {"name": "stub", "version": "0"},
                }}).encode()
            elif method == "tools/list":
                status, extra = 200, ""
                data = json.dumps({"jsonrpc": "2.0", "id": rpc.get("id"), "result": {"tools": self.tools}}).encode()
            else:
                status, extra, data = 202, "", b""
            writer.write(
                (f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}"
                 f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data
            )
            await writer.drain()
        finally:
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
async def upstream():
    u = _Upstream()
    await u.start()
    yield u
    await u.stop()


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
async def cache(db):
    async with httpx.AsyncClient() as client:
        yield ToolsCache(db, ProtocolBridge(client, UpstreamHandshakeCache(client)))


def _warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "argus.toolslist" and r.levelno == logging.WARNING]


def _assert_nothing_hostile_leaked(*texts: str) -> None:
    for text in texts:
        for marker in HOSTILE_MARKERS:
            assert marker not in text, f"{marker!r} leaked into {text[:200]!r}"


# ---- ToolsCache level ---------------------------------------------------------------------


async def test_success_path_is_not_stale_and_logs_nothing(db, cache, upstream, caplog):
    server = await ServerRepo(db).create(slug="ok", name="Ok", upstream_url=upstream.url)
    with caplog.at_level(logging.DEBUG, logger="argus.toolslist"):
        result = await cache.get_raw_tools_result(server.id, server.upstream_url, server_slug="ok")
    assert [t["name"] for t in result.tools] == ["echo"]
    assert result.stale is False and result.error is None
    assert _warnings(caplog) == []


async def test_genuinely_empty_upstream_is_not_stale(db, cache, upstream, caplog):
    upstream.tools = []
    server = await ServerRepo(db).create(slug="empty", name="Empty", upstream_url=upstream.url)
    with caplog.at_level(logging.DEBUG, logger="argus.toolslist"):
        result = await cache.get_raw_tools_result(server.id, server.upstream_url, server_slug="empty")
    assert result.tools == [] and result.stale is False and result.error is None
    assert _warnings(caplog) == []


async def test_tools_list_401_is_logged_and_flagged_stale(db, cache, upstream, caplog):
    upstream.tools_status = 401
    server = await ServerRepo(db).create(slug="rejecting", name="R", upstream_url=upstream.url)
    with caplog.at_level(logging.WARNING, logger="argus.toolslist"):
        result = await cache.get_raw_tools_result(
            server.id, server.upstream_url, upstream_auth_header=SECRET, server_slug="rejecting",
        )
    assert result.tools == []
    assert result.stale is True
    assert result.error == "upstream answered 401"
    (record,) = _warnings(caplog)
    assert "rejecting" in record.getMessage() and "401" in record.getMessage()
    _assert_nothing_hostile_leaked(caplog.text, result.error)


async def test_tools_list_401_with_stale_cache_serves_cache_and_flags_it(db, cache, upstream, caplog):
    server = await ServerRepo(db).create(slug="rot", name="R", upstream_url=upstream.url)
    first = await cache.get_raw_tools_result(server.id, server.upstream_url)
    assert first.stale is False and first.tools

    upstream.tools_status = 401  # e.g. the token's audience no longer matches after a rotation
    with caplog.at_level(logging.WARNING, logger="argus.toolslist"):
        second = await cache.get_raw_tools_result(
            server.id, server.upstream_url, force_refresh=True, server_slug="rot",
        )
    assert [t["name"] for t in second.tools] == ["echo"]
    assert second.stale is True and second.error == "upstream answered 401"
    assert len(_warnings(caplog)) == 1
    assert "1 stale cached tool" in _warnings(caplog)[0].getMessage()


async def test_handshake_rejection_is_a_flagged_bridge_error_without_upstream_text(
    db, cache, upstream, caplog,
):
    upstream.reject_all = True
    server = await ServerRepo(db).create(slug="hs", name="H", upstream_url=upstream.url)
    with caplog.at_level(logging.WARNING, logger="argus.toolslist"):
        result = await cache.get_raw_tools_result(
            server.id, server.upstream_url, upstream_auth_header=SECRET, server_slug="hs",
        )
    assert result.tools == [] and result.stale is True
    assert result.error == "upstream fetch failed (BridgeError 502)"
    assert len(_warnings(caplog)) == 1 and "hs" in _warnings(caplog)[0].getMessage()
    _assert_nothing_hostile_leaked(caplog.text, result.error)


async def test_unreachable_upstream_with_stale_cache_is_flagged(db, cache, upstream, caplog):
    server = await ServerRepo(db).create(slug="gone", name="G", upstream_url=upstream.url)
    await cache.get_raw_tools_result(server.id, server.upstream_url)
    with caplog.at_level(logging.WARNING, logger="argus.toolslist"):
        result = await cache.get_raw_tools_result(
            server.id, "http://127.0.0.1:1/mcp", force_refresh=True, server_slug="gone",
        )
    assert [t["name"] for t in result.tools] == ["echo"]
    assert result.stale is True
    assert result.error == "upstream fetch failed (BridgeError 502)"
    assert len(_warnings(caplog)) == 1


async def test_get_raw_tools_keeps_its_list_contract_on_failure(db, cache, upstream):
    """Data-plane callers (pipeline, aggregate) still get a plain list, never an exception."""
    upstream.tools_status = 401
    server = await ServerRepo(db).create(slug="dp", name="D", upstream_url=upstream.url)
    tools = await cache.get_raw_tools(server.id, server.upstream_url)
    assert tools == []
    assert isinstance(tools, list)


async def test_fallback_log_uses_id_when_no_slug_given(db, cache, upstream, caplog):
    upstream.tools_status = 401
    server = await ServerRepo(db).create(slug="noslug", name="N", upstream_url=upstream.url)
    with caplog.at_level(logging.WARNING, logger="argus.toolslist"):
        await cache.get_raw_tools(server.id, server.upstream_url)
    (record,) = _warnings(caplog)
    assert f"id={server.id}" in record.getMessage()


@pytest.mark.parametrize("payload", [
    b"<html><script>BODYMARKER</script></html>",
    b"\xff\xfe\x00BODYMARKER\x80" * 10,
    b"A" * (2 * 1024 * 1024) + b"BODYMARKER",
    b"",
], ids=["html", "non-utf8", "huge", "empty"])
async def test_hostile_rejection_bodies_never_reach_log_or_reason(db, cache, upstream, caplog, payload):
    upstream.tools_status = 401
    upstream.reject_body = payload
    server = await ServerRepo(db).create(slug="hostile", name="H", upstream_url=upstream.url)
    with caplog.at_level(logging.DEBUG, logger="argus.toolslist"):
        result = await cache.get_raw_tools_result(
            server.id, server.upstream_url, upstream_auth_header=SECRET, server_slug="hostile",
        )
    assert result.stale is True and result.error is not None
    assert len(result.error) < 80
    assert result.error.isascii() and result.error.isprintable()
    assert len(caplog.text) < 2000
    _assert_nothing_hostile_leaked(caplog.text, result.error)


# ---- API level ----------------------------------------------------------------------------


@pytest.fixture
async def api(tmp_path: Path, upstream):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db, probe_on_create=False)
    transport = httpx.ASGITransport(app=app)
    try:
        async with app.router.lifespan_context(app):
            await ServerRepo(db).create(
                slug="s", name="S", upstream_url=upstream.url, upstream_auth_header=SECRET,
                credential_mode="static",
            )
            async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
                yield c
    finally:
        await db.close()


async def test_api_marks_a_rejected_fetch_as_stale_with_a_fixed_reason(api, upstream, caplog):
    upstream.tools_status = 401
    with caplog.at_level(logging.WARNING, logger="argus.toolslist"):
        resp = await api.get("/api/v1/servers/s/tools", params={"force_refresh": "true"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tools"] == []
    assert body["stale"] is True
    assert body["fetch_error"] == "upstream answered 401"
    assert any("server s " in r.getMessage() for r in _warnings(caplog))
    _assert_nothing_hostile_leaked(resp.text, caplog.text)


async def test_api_stale_cache_is_served_and_flagged(api, upstream):
    ok = await api.get("/api/v1/servers/s/tools", params={"force_refresh": "true"})
    assert ok.json()["stale"] is False and ok.json()["fetch_error"] is None

    upstream.tools_status = 401
    resp = await api.get("/api/v1/servers/s/tools", params={"force_refresh": "true"})
    body = resp.json()
    assert [t["name"] for t in body["tools"]] == ["echo"]
    assert body["stale"] is True and body["fetch_error"] == "upstream answered 401"
    _assert_nothing_hostile_leaked(resp.text)


async def test_api_empty_upstream_is_not_stale(api, upstream):
    upstream.tools = []
    resp = await api.get("/api/v1/servers/s/tools", params={"force_refresh": "true"})
    body = resp.json()
    assert body["tools"] == [] and body["stale"] is False and body["fetch_error"] is None


async def test_api_handshake_rejection_reports_a_fixed_reason(api, upstream):
    upstream.reject_all = True
    resp = await api.get("/api/v1/servers/s/tools", params={"force_refresh": "true"})
    assert resp.status_code == 200
    assert resp.json()["fetch_error"] == "upstream fetch failed (BridgeError 502)"
    _assert_nothing_hostile_leaked(resp.text)
