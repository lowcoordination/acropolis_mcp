"""Issue #165: response DLP on both forwarding paths.

`_ScriptedUpstream` is a raw TCP MCP upstream (same style as test_dlp_redaction.py's
_BodyCapturingUpstream). It answers the 2025 handshake itself, and serves tools/call (or any
method) from a script: content type, the body split into TCP writes with pauses between them,
and Content-Length or close-delimited framing. That is what lets these tests split a JWT
across two writes, stream past the hard ceiling, and see whether Acropolis hung up early.
"""
from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from argus.response_dlp import HARD_LIMIT_MARKER, TRUNCATION_MARKER, UNPARSEABLE_MARKER
from db.database import Database
from db.models import ServerPolicy
from db.repo import ServerRepo

from tests.unit.test_dlp import _FAKE_GH_PAT, _FAKE_GHP, _FAKE_JWT

PLANTED = {
    "bearer_token": "Authorization: Bearer zY9-kL2.mN4_pQ6~rS8tU0vW",
    "jwt": _FAKE_JWT,
    "github_token": _FAKE_GHP,
    "secret_assignment": "DB_PASSWORD=hunter2hunter2",
    "url_credentials": "postgres://app:s3cr3tpw@db:5432/x",
}
# The secret part of each planted string: what must never reach the client.
SECRET_PARTS = {
    "bearer_token": "zY9-kL2.mN4_pQ6~rS8tU0vW",
    "jwt": _FAKE_JWT,
    "github_token": _FAKE_GHP,
    "secret_assignment": "hunter2hunter2",
    "url_credentials": "s3cr3tpw",
}
ALL_NEW_REDACT = {name: "redact" for name in PLANTED}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Reply:
    body_chunks: list[bytes]
    content_type: str = "application/json"
    status: int = 200
    pause: float = 0.0            # seconds between chunks
    content_length: bool = True   # False = close-delimited body
    extra_headers: dict[str, str] = field(default_factory=dict)


def json_reply(message: dict, **kw) -> Reply:
    return Reply([json.dumps(message).encode()], **kw)


def sse_reply(messages: list[dict], split_at: Optional[bytes] = None, **kw) -> Reply:
    """One SSE event per message. With split_at, the body is cut in two TCP writes in the
    middle of that byte string (e.g. mid-JWT)."""
    events = []
    for i, m in enumerate(messages):
        events.append(f"event: message\nid: ev-{i}\ndata: {json.dumps(m)}\n\n".encode())
    body = b"".join(events)
    if split_at is not None:
        cut = body.index(split_at) + len(split_at) // 2
        return Reply([body[:cut], body[cut:]], content_type="text/event-stream", pause=0.05, **kw)
    return Reply([body], content_type="text/event-stream", **kw)


class _ScriptedUpstream:
    def __init__(self) -> None:
        self.script: dict[str, Callable[[dict], Reply]] = {}
        self.aborted_early = False
        self.bytes_sent = 0
        self.request_headers: dict[str, dict[str, str]] = {}  # rpc method -> lower-cased headers
        self.tool_description = f"reads logs; example header {PLANTED['bearer_token']}"
        self._server: Optional[asyncio.AbstractServer] = None
        self.url = ""

    def _default(self, req: dict) -> Reply:
        method = req.get("method", "")
        rid = req.get("id")
        if method == "initialize":
            return json_reply({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "scripted", "version": "1"},
            }})
        if method.startswith("notifications/"):
            return Reply([b""], status=202)
        if method == "tools/list":
            return json_reply({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "logs", "description": self.tool_description,
                "inputSchema": {"type": "object", "properties": {}},
            }]}})
        return json_reply({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": "default"}], "isError": False}})

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = 0
            for line in head.decode(errors="replace").split("\r\n")[1:]:
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1])
            raw = await reader.readexactly(length) if length else b""
            req = json.loads(raw) if raw else {}
            self.request_headers[req.get("method", "")] = {
                k.strip().lower(): v.strip()
                for k, _, v in (ln.partition(":") for ln in head.decode(errors="replace").split("\r\n")[1:] if ln)
            }
            handler = self.script.get(req.get("method", ""), self._default)
            reply = handler(req)
            total = sum(len(c) for c in reply.body_chunks)
            headers = [f"HTTP/1.1 {reply.status} OK", f"Content-Type: {reply.content_type}"]
            if reply.content_length:
                headers.append(f"Content-Length: {total}")
            else:
                headers.append("Connection: close")
            headers += [f"{k}: {v}" for k, v in reply.extra_headers.items()]
            writer.write(("\r\n".join(headers) + "\r\n\r\n").encode())
            await writer.drain()
            for i, chunk in enumerate(reply.body_chunks):
                if i and reply.pause:
                    await asyncio.sleep(reply.pause)
                writer.write(chunk)
                await writer.drain()
                self.bytes_sent += len(chunk)
        except (ConnectionResetError, BrokenPipeError):
            self.aborted_early = True
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

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
    u = _ScriptedUpstream()
    await u.start()
    try:
        yield u
    finally:
        await u.stop()


@pytest.fixture
async def env(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
                        audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    repo = ServerRepo(db)
    server = await repo.create(slug="logs", name="Logs", upstream_url=upstream.url)
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client, repo, server, db
    await db.close()


async def _set_response_dlp(repo, server, detectors, max_bytes: Optional[int] = None):
    kw = {"response_dlp_detectors": detectors}
    if max_bytes is not None:
        kw["response_dlp_max_bytes"] = max_bytes
    await repo.set_policy(server.id, ServerPolicy(**kw))


def _call(rpc_id: int = 1, method: str = "tools/call", params: Optional[dict] = None) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "method": method,
            "params": params if params is not None else {"name": "logs", "arguments": {}}}


async def passthrough(client, body: dict) -> httpx.Response:
    return await client.post("/mcp/logs/mcp", json=body,
                             headers={"Accept": "application/json, text/event-stream"})


async def bridged(client, body: dict) -> httpx.Response:
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Mcp-Method": body["method"]}
    if body["method"] == "tools/call":
        headers["Mcp-Name"] = body["params"]["name"]
    return await client.post("/mcp/logs", json=body, headers=headers)


def _planted_result(rpc_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": {
        "content": [{"type": "text", "text": f"line {i}: {v}"} for i, v in enumerate(PLANTED.values())],
        "isError": False,
    }}


def _assert_no_secret(text: str) -> None:
    for name, secret in SECRET_PARTS.items():
        assert secret not in text, f"{name} leaked"


# ---------------------------------------------------------------------------- Task 4: bridged

class TestBridged:
    async def test_secrets_redacted_when_on(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: json_reply(_planted_result(req["id"]))
        resp = await bridged(client, _call())
        assert resp.status_code == 200
        _assert_no_secret(resp.text)
        for name in PLANTED:
            assert f"[REDACTED:{name}]" in resp.text

    async def test_identical_when_off(self, env, upstream):
        client, repo, server, _ = env
        upstream.script["tools/call"] = lambda req: json_reply(_planted_result(req["id"]))
        resp = await bridged(client, _call())
        assert resp.json()["result"] == _planted_result()["result"]

    async def test_tools_list_never_scanned(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        resp = await bridged(client, _call(method="tools/list", params={}))
        assert resp.status_code == 200
        assert SECRET_PARTS["bearer_token"] in resp.text


# ------------------------------------------------------------------------ Task 5: passthrough

class TestPassthroughJson:
    async def test_json_redacted_with_correct_length_and_headers(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: json_reply(
            _planted_result(req["id"]), extra_headers={"X-Upstream-Trace": "abc", "Mcp-Session-Id": "s-1"})
        resp = await passthrough(client, _call())
        assert resp.status_code == 200
        _assert_no_secret(resp.text)
        for name in PLANTED:
            assert f"[REDACTED:{name}]" in resp.text
        assert int(resp.headers["content-length"]) == len(resp.content)
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.headers.get("mcp-session-id") == "s-1"
        assert resp.json()["id"] == 1

    async def test_status_is_kept(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: json_reply(
            {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32000, "message": PLANTED["url_credentials"]}},
            status=500)
        resp = await passthrough(client, _call())
        assert resp.status_code == 500
        _assert_no_secret(resp.text)


class TestPassthroughSse:
    async def test_sse_redacted_jwt_split_across_writes_framing_kept(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        progress = {"jsonrpc": "2.0", "method": "notifications/message",
                    "params": {"level": "info", "data": f"connecting {PLANTED['url_credentials']}"}}
        upstream.script["tools/call"] = lambda req: sse_reply(
            [progress, _planted_result(req["id"])], split_at=_FAKE_JWT.encode())
        resp = await passthrough(client, _call())
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        _assert_no_secret(resp.text)
        assert "[REDACTED:jwt]" in resp.text
        blocks = resp.text.split("\n\n")
        assert blocks[0].startswith("event: message\nid: ev-0\ndata: ")
        assert blocks[1].startswith("event: message\nid: ev-1\ndata: ")
        assert json.loads(blocks[1].split("data: ", 1)[1])["id"] == 1

    async def test_sse_cut_mid_event_fails_closed(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)

        def cut(req):
            full = sse_reply([_planted_result(req["id"])]).body_chunks[0]
            return Reply([full[: len(full) // 2]], content_type="text/event-stream")
        upstream.script["tools/call"] = cut
        resp = await passthrough(client, _call(rpc_id=5))
        _assert_no_secret(resp.text)
        assert UNPARSEABLE_MARKER in resp.text


class TestPassthroughFailClosed:
    async def test_truncated_json_gives_marker_never_bytes(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: Reply(
            [f'{{"jsonrpc":"2.0","id":1,"res {PLANTED["github_token"]}'.encode()])
        resp = await passthrough(client, _call(rpc_id=9))
        assert resp.status_code == 200
        _assert_no_secret(resp.text)
        body = resp.json()
        assert body["id"] == 9
        assert body["result"]["content"][0]["text"] == UNPARSEABLE_MARKER

    async def test_unknown_content_type_fails_closed(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: Reply(
            [PLANTED["github_token"].encode()], content_type="text/plain")
        resp = await passthrough(client, _call())
        _assert_no_secret(resp.text)
        assert UNPARSEABLE_MARKER in resp.text


class TestPassthroughSizeTiers:
    BUDGET = 64 * 1024

    def _sized(self, total: int, rid: int) -> dict:
        # One text item whose JSON body is about `total` bytes, with a planted token near the
        # start so the scanned head always carries a secret.
        filler = "x" * (total - 300)
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": f"{PLANTED['github_token']} {filler}"}], "isError": False}}

    async def test_60k_complete(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT, max_bytes=self.BUDGET)
        upstream.script["tools/call"] = lambda req: json_reply(self._sized(60 * 1024, req["id"]))
        resp = await passthrough(client, _call())
        text = resp.json()["result"]["content"][0]["text"]
        assert "[TRUNCATED" not in text
        assert text.startswith("[REDACTED:github_token] ")
        assert len(text) > 59 * 1024

    async def test_70k_cut_and_marked_head_scanned(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT, max_bytes=self.BUDGET)
        upstream.script["tools/call"] = lambda req: json_reply(self._sized(70 * 1024, req["id"]))
        resp = await passthrough(client, _call())
        text = resp.json()["result"]["content"][0]["text"]
        assert text.endswith(TRUNCATION_MARKER.format(limit="65536 bytes"))
        assert text.startswith("[REDACTED:github_token] ")
        _assert_no_secret(resp.text)

    async def test_600k_hard_ceiling_stops_reading_and_closes_upstream(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT, max_bytes=self.BUDGET)
        # Streamed slowly in 16 KiB writes, close-delimited, and far past 8 x 64 KiB, so the
        # upstream sees the hang-up as a failed write instead of finishing into socket buffers.
        big = json.dumps(self._sized(4 * 1024 * 1024, 1)).encode()
        chunks = [big[i:i + 16384] for i in range(0, len(big), 16384)]
        upstream.script["tools/call"] = lambda req: Reply(chunks, pause=0.002, content_length=False)
        resp = await passthrough(client, _call(rpc_id=4))
        body = resp.json()
        assert body["id"] == 4
        assert body["result"]["content"][0]["text"] == HARD_LIMIT_MARKER
        _assert_no_secret(resp.text)
        await asyncio.sleep(0.3)
        assert upstream.aborted_early, "Acropolis must hang up on the upstream at the ceiling"
        assert upstream.bytes_sent < len(big)


    async def test_600k_exact_plan_size_gets_hard_limit_marker(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT, max_bytes=self.BUDGET)
        upstream.script["tools/call"] = lambda req: json_reply(self._sized(600 * 1024, req["id"]))
        resp = await passthrough(client, _call(rpc_id=6))
        assert resp.json()["result"]["content"][0]["text"] == HARD_LIMIT_MARKER
        _assert_no_secret(resp.text)


class TestUntouchedWhenOffOrOtherMethods:
    async def test_off_is_byte_identical_for_tools_call(self, env, upstream):
        """Response-side twin of test_no_dlp_detectors_forwards_body_unmodified."""
        client, repo, server, _ = env
        raw = (b'{"jsonrpc": "2.0",   "id": 1, "result": {"content": [{"type": "text", "text": "'
               + PLANTED["github_token"].encode() + b'"}], "isError": false}}\n')
        upstream.script["tools/call"] = lambda req: Reply([raw])
        resp = await passthrough(client, _call())
        assert resp.content == raw

    async def test_off_is_byte_identical_for_sse(self, env, upstream):
        client, repo, server, _ = env
        reply = sse_reply([_planted_result(1)], split_at=_FAKE_JWT.encode())
        raw = b"".join(reply.body_chunks)
        upstream.script["tools/call"] = lambda req: reply
        resp = await passthrough(client, _call())
        assert resp.content == raw

    @pytest.mark.parametrize("method", ["resources/read", "prompts/get", "initialize"])
    async def test_other_methods_byte_identical_when_on(self, env, upstream, method):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        raw = (b'{"jsonrpc":"2.0","id":1,"result":{"contents":[{"text":"'
               + _FAKE_GH_PAT.encode() + b'"}]}}')
        upstream.script[method] = lambda req: Reply([raw])
        resp = await passthrough(client, _call(method=method, params={"uri": "x"}))
        assert resp.content == raw


class TestPassthroughHostileBodies:
    async def test_deeply_nested_json_fails_closed_not_500(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        deep = b'{"jsonrpc":"2.0","id":1,"result":' + b"[" * 200000 + b"]" * 200000 + b"}"
        upstream.script["tools/call"] = lambda req: Reply([deep])
        resp = await passthrough(client, _call())
        assert resp.status_code == 200
        assert UNPARSEABLE_MARKER in resp.text

    @pytest.mark.parametrize("kind", ["json", "sse"])
    async def test_duplicate_key_fails_closed(self, env, upstream, kind):
        """A repeated key parses last-wins: the scan sees only the clean copy, finds nothing,
        and the original bytes (secret in the first copy) would go out unscanned. Found by a
        payload probe on the compose stack."""
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        message = ('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"%s",'
                   '"text":"clean"}],"isError":false}}' % _FAKE_GHP)
        if kind == "json":
            reply = Reply([message.encode()])
        else:
            reply = Reply([f"event: message\ndata: {message}\n\n".encode()],
                          content_type="text/event-stream")
        upstream.script["tools/call"] = lambda req: reply
        resp = await passthrough(client, _call())
        assert resp.status_code == 200
        _assert_no_secret(resp.text)
        assert UNPARSEABLE_MARKER in resp.text

    async def test_compressed_upstream_fails_closed(self, env, upstream):
        import gzip
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        gz = gzip.compress(json.dumps(_planted_result(1)).encode())
        upstream.script["tools/call"] = lambda req: Reply([gz], extra_headers={"Content-Encoding": "gzip"})
        resp = await passthrough(client, _call())
        _assert_no_secret(resp.text)
        assert UNPARSEABLE_MARKER in resp.text

    async def test_scan_path_asks_upstream_for_identity_encoding(self, env, upstream):
        client, repo, server, _ = env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: json_reply(_planted_result(req["id"]))
        resp = await client.post("/mcp/logs/mcp", json=_call(),
                                 headers={"Accept-Encoding": "gzip", "Accept": "application/json"})
        assert resp.status_code == 200
        assert upstream.request_headers["tools/call"]["accept-encoding"] == "identity"

    async def test_off_path_keeps_client_accept_encoding(self, env, upstream):
        client, repo, server, _ = env
        await client.post("/mcp/logs/mcp", json=_call(),
                          headers={"Accept-Encoding": "gzip", "Accept": "application/json"})
        assert upstream.request_headers["tools/call"]["accept-encoding"] == "gzip"


# ---------------------------------------------------------------------------- Task 6: audit

pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from argus.tracing import TracingManager  # noqa: E402
from db.repo import AuditRepo  # noqa: E402


@pytest.fixture
async def traced_env(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
                        audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    repo = ServerRepo(db)
    server = await repo.create(slug="logs", name="Logs", upstream_url=upstream.url)
    app = create_app(settings, db)
    exporter = InMemorySpanExporter()
    manager = TracingManager(enabled=True, sample_ratio=1.0)
    manager.init(exporter=exporter)
    app.state.pipeline._tracing = manager
    app.state.bridge._tracing = manager
    app.state.tracing = manager
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client, repo, server, db, exporter
    await db.close()


def _spans_text(exporter: InMemorySpanExporter) -> str:
    return json.dumps([
        {"name": s.name, "attributes": dict(s.attributes or {}),
         "events": [{"name": e.name, "attributes": dict(e.attributes or {})} for e in s.events]}
        for s in exporter.get_finished_spans()
    ], default=str)


class TestAuditInvariant:
    async def test_values_never_reach_audit_logs_or_spans(self, traced_env, upstream, caplog):
        client, repo, server, db, exporter = traced_env
        caplog.set_level("DEBUG")
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: json_reply(_planted_result(req["id"]))

        r1 = await passthrough(client, _call(rpc_id=1))
        r2 = await bridged(client, _call(rpc_id=2))
        _assert_no_secret(r1.text)
        _assert_no_secret(r2.text)

        await asyncio.sleep(0.5)
        rows = await AuditRepo(db).query(server_slug="logs")
        dumped = json.dumps([dict(r) for r in rows], default=str)
        _assert_no_secret(dumped)
        _assert_no_secret(caplog.text)
        spans = _spans_text(exporter)
        _assert_no_secret(spans)

        calls = [dict(r) for r in rows if r["rpc_method"] == "tools/call" and r["decision"] == "ALLOWED"]
        assert len(calls) == 2, calls
        for row in calls:
            assert row["response_dlp_detectors_fired"] == ",".join(sorted(PLANTED))
            assert row["response_dlp_match_count"] == len(PLANTED)
            assert row["response_truncated"] is False
        assert {row["bridged"] for row in calls} == {True, False}

        assert '"acropolis.response_dlp.match_count": 5' in spans
        assert "response.dlp_scan" in spans

    async def test_off_leaves_the_three_columns_null(self, traced_env, upstream):
        client, repo, server, db, _ = traced_env
        upstream.script["tools/call"] = lambda req: json_reply(_planted_result(req["id"]))
        await passthrough(client, _call())
        await asyncio.sleep(0.5)
        rows = [dict(r) for r in await AuditRepo(db).query(server_slug="logs")
                if r["rpc_method"] == "tools/call"]
        assert rows and all(
            r["response_dlp_detectors_fired"] is None and r["response_dlp_match_count"] is None
            and r["response_truncated"] is None for r in rows
        )

    async def test_truncation_is_recorded(self, traced_env, upstream):
        client, repo, server, db, _ = traced_env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: Reply([b'{"jsonrpc":"2.0","id":1,"res'])
        await passthrough(client, _call())
        await asyncio.sleep(0.5)
        rows = [dict(r) for r in await AuditRepo(db).query(server_slug="logs")
                if r["rpc_method"] == "tools/call"]
        assert rows[0]["response_truncated"] is True
        assert rows[0]["response_dlp_detectors_fired"] == ""

    async def test_audit_api_exposes_names_as_a_list(self, traced_env, upstream):
        client, repo, server, db, _ = traced_env
        await _set_response_dlp(repo, server, ALL_NEW_REDACT)
        upstream.script["tools/call"] = lambda req: json_reply(_planted_result(req["id"]))
        await passthrough(client, _call())
        await asyncio.sleep(0.5)
        resp = await client.get("/api/v1/audit", params={"server_slug": "logs"})
        assert resp.status_code == 200
        _assert_no_secret(resp.text)
        row = next(e for e in resp.json() if e["rpc_method"] == "tools/call")
        assert row["response_dlp_detectors_fired"] == sorted(PLANTED)
        assert row["response_dlp_match_count"] == 5


def test_audit_event_response_forbids_unknown_fields():
    from archon.schemas import AuditEventResponse

    base = dict(id=1, ts="t", server_slug=None, api_key_id=None, client_ip=None, endpoint=None,
                rpc_method=None, tool=None, decision="ALLOWED", rule=None, matched=None, reason=None,
                args_summary=None, bridged=False, status_code=None, latency_ms=None)
    AuditEventResponse(**base)
    with pytest.raises(ValueError):
        AuditEventResponse(**base, response_dlp_matched_value="x")
