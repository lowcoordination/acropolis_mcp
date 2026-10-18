"""Issue #146: the control plane's tools-list fetch must authenticate to the upstream exactly the
way the data plane does.

``GET /servers/{slug}/tools`` and ``POST /servers/{slug}/probe`` (whose catalog refresh) used to
call ``ToolsCache.get_raw_tools`` with the RAW ``server.upstream_auth_header``:

  * ``credential_mode='token'`` -> header is NULL -> the upstream got no Authorization, 401'd, and
    ``get_raw_tools`` swallowed the failure and served a stale cache, or ``[]`` after a policy save
    invalidated it. "Refresh from upstream" was a silent no-op.
  * ``static`` with a REFERENCE (``enc:v1:...``, ``vault://...``) -> the unresolved reference string
    itself went out as the Authorization header (wrong, and it discloses the secret's location).

The upstream below REQUIRES a valid credential and records every request, so each test fails on
the old code by the upstream refusing the call, not by an assertion about our own internals.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
from pathlib import Path
from typing import Callable, Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from archon.settings import Settings
from argus.app import create_app
from argus.tokens import TokenIssuer
from db.database import Database
from db.repo import AuditRepo, ServerRepo

from .fixture_token_verifier import verify_request_token

TOOLS = [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object", "properties": {}}}]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _AuthEnforcingUpstream:
    """A minimal 2025-generation MCP upstream over raw TCP that 401s any request whose
    Authorization header ``authorize`` rejects, and records (rpc_method, authorization) for every
    request it sees. Handles ``initialize`` / ``notifications/initialized`` / ``tools/list`` — the
    three calls the bridge makes to fetch a tool catalog."""

    def __init__(self, authorize: Callable[[Optional[str]], bool]) -> None:
        self._authorize = authorize
        self.requests: list[tuple[str, Optional[str]]] = []
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
            auth = headers.get("authorization")
            self.requests.append((method, auth))

            if not self._authorize(auth):
                status, payload = 401, {"error": "unauthorized"}
            elif method == "initialize":
                status, payload = 200, {"jsonrpc": "2.0", "id": rpc.get("id"), "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "serverInfo": {"name": "auth-upstream", "version": "0"},
                }}
            elif method == "tools/list":
                status, payload = 200, {"jsonrpc": "2.0", "id": rpc.get("id"), "result": {"tools": TOOLS}}
            else:  # notifications/initialized and anything else
                status, payload = 202, None

            data = json.dumps(payload).encode() if payload is not None else b""
            writer.write(
                (f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
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

    def unauthenticated(self) -> list[str]:
        """RPC methods that arrived with a credential the upstream refused."""
        return [m for m, a in self.requests if not self._authorize(a)]


def _settings(tmp_path: Path, **extra) -> Settings:
    return Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, **extra,
    )


@pytest.fixture
async def token_env(tmp_path: Path):
    """App + auth-enforcing upstream that accepts only a JWT for audience ``mcp-fetch`` signed by the
    test issuer. The issuer is injected AFTER lifespan startup (which leaves it None because no
    signing key is configured in Settings) — the same shape as test_upstream_tokens.py."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = TokenIssuer(private_key)

    def authorize(header: Optional[str]) -> bool:
        if not header or not header.startswith("Bearer "):
            return False
        try:
            verify_request_token(
                header[len("Bearer "):], audience="mcp-fetch", issuer="acropolis",
                public_key=private_key.public_key(),
            )
        except AssertionError:
            return False
        return True

    upstream = _AuthEnforcingUpstream(authorize)
    await upstream.start()
    db = Database(tmp_path)
    await db.connect()
    app = create_app(_settings(tmp_path), db, probe_on_create=False)
    transport = httpx.ASGITransport(app=app)
    try:
        async with app.router.lifespan_context(app):
            app.state.token_issuer = issuer
            app.state.pipeline.set_token_issuer(issuer)
            app.state.health_poller.set_token_issuer(issuer)
            await ServerRepo(db).create(
                slug="mcp-fetch", name="Fetch", upstream_url=upstream.url, credential_mode="token",
            )
            async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
                yield client, app, db, upstream
    finally:
        await upstream.stop()
        await db.close()


async def test_token_mode_forced_refresh_authenticates_and_returns_the_tools(token_env):
    """The #146 repro: token-mode server, EMPTY cache, ``force_refresh=true`` must carry a valid
    JWT upstream and come back with the real tool list — not ``[]`` from a swallowed 401."""
    client, _, _, upstream = token_env

    resp = await client.get("/api/v1/servers/mcp-fetch/tools", params={"force_refresh": "true"})

    assert resp.status_code == 200, resp.text
    assert [t["name"] for t in resp.json()["tools"]] == ["echo"], (resp.json(), upstream.requests)
    assert resp.json()["fetched_at"] is not None
    assert upstream.unauthenticated() == [], upstream.requests
    assert {m for m, _ in upstream.requests} >= {"initialize", "tools/list"}


async def test_token_mode_refresh_after_policy_save_repopulates_the_cache(token_env):
    """The user-visible symptom: saving a policy invalidates the tools cache; the Tools card must
    repopulate on the next load instead of staying empty until some data-plane call warms it."""
    client, _, _, upstream = token_env
    first = await client.get("/api/v1/servers/mcp-fetch/tools", params={"force_refresh": "true"})
    assert first.status_code == 200 and first.json()["tools"], first.text

    put = await client.put("/api/v1/servers/mcp-fetch/policy", json={"mode": "denylist", "denied": []})
    assert put.status_code == 200, put.text  # invalidates ToolsCache for this server

    after = await client.get("/api/v1/servers/mcp-fetch/tools")  # no force: cache is empty -> must fetch
    assert [t["name"] for t in after.json()["tools"]] == ["echo"], (after.json(), upstream.requests)
    assert upstream.unauthenticated() == [], upstream.requests


async def test_token_mode_reprobe_refreshes_the_tool_catalog(token_env):
    """``POST /probe`` promises a catalog refresh; for a token-mode server it must actually do it."""
    client, _, _, upstream = token_env

    resp = await client.post("/api/v1/servers/mcp-fetch/probe")
    assert resp.status_code == 200, resp.text

    cached = await client.get("/api/v1/servers/mcp-fetch/tools")  # served from the cache the probe filled
    assert [t["name"] for t in cached.json()["tools"]] == ["echo"], (cached.json(), upstream.requests)
    assert upstream.unauthenticated() == [], upstream.requests


async def test_token_mode_without_issuer_fails_closed_without_contacting_the_upstream(token_env):
    """Same guarantee as the data plane: no credential -> an explicit error, never an
    unauthenticated request (and never a silent empty list)."""
    client, app, _, upstream = token_env
    app.state.token_issuer = None
    app.state.pipeline.set_token_issuer(None)

    resp = await client.get("/api/v1/servers/mcp-fetch/tools", params={"force_refresh": "true"})

    assert resp.status_code == 502, resp.text
    assert "token signing is not configured" in resp.text.lower()
    assert upstream.requests == [], "the upstream must not be contacted without a credential"


async def test_static_reference_is_resolved_not_sent_verbatim(tmp_path: Path, monkeypatch):
    """The second half of #146: under the ``encrypted`` tier ``upstream_auth_header`` is stored as an
    ``enc:v1:`` reference. The control plane used to put that reference string on the wire."""
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", os.urandom(32).hex())
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    plaintext = "Bearer static-secret-146"
    upstream = _AuthEnforcingUpstream(lambda h: h == plaintext)
    await upstream.start()
    db = Database(tmp_path)
    await db.connect()
    app = create_app(
        _settings(tmp_path, secret_provider="encrypted", admin_token="t146-admin"), db,
        probe_on_create=False,
    )
    transport = httpx.ASGITransport(app=app)
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=transport, base_url="http://argus.test",
                headers={"Authorization": "Bearer t146-admin"},
            ) as client:
                created = await client.post("/api/v1/servers", json={
                    "slug": "static-ref", "name": "S", "upstream_url": upstream.url,
                    "upstream_auth_header": plaintext,
                })
                assert created.status_code == 201, created.text
                stored = await ServerRepo(db).get("static-ref")
                assert stored.upstream_auth_header.startswith("enc:v1:"), "premise: stored as a reference"

                resp = await client.get("/api/v1/servers/static-ref/tools", params={"force_refresh": "true"})

                assert resp.status_code == 200, resp.text
                assert [t["name"] for t in resp.json()["tools"]] == ["echo"], upstream.requests
                assert all(a == plaintext for _, a in upstream.requests), upstream.requests
                assert not any(a and "enc:v1:" in a for _, a in upstream.requests), \
                    "the unresolved reference must never reach the upstream"
    finally:
        await upstream.stop()
        await db.close()


async def test_cache_hit_needs_no_credential(token_env):
    """The credential is resolved lazily, only when a fetch really happens: a warm cache must keep
    serving even if the issuer (or a secret backend) is down. Pins the 'deferred' half of the
    design so a future 'resolve first, then look at the cache' change fails here."""
    client, app, _, upstream = token_env
    warm = await client.get("/api/v1/servers/mcp-fetch/tools", params={"force_refresh": "true"})
    assert warm.status_code == 200 and warm.json()["tools"], warm.text
    seen = len(upstream.requests)
    app.state.token_issuer = None
    app.state.pipeline.set_token_issuer(None)

    resp = await client.get("/api/v1/servers/mcp-fetch/tools")  # fresh cache -> no fetch

    assert resp.status_code == 200, resp.text
    assert [t["name"] for t in resp.json()["tools"]] == ["echo"]
    assert len(upstream.requests) == seen, "a cache hit must not contact the upstream"


async def test_aggregate_tools_list_authenticates_token_mode_servers(token_env):
    """The same defect on the third path that fetches catalogs: the aggregate POST /mcp tools/list
    handed ToolsCache the raw header, so a token-mode server silently contributed no tools."""
    client, _, _, upstream = token_env

    resp = await client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert "mcp-fetch__echo" in names, (names, upstream.requests)
    assert upstream.unauthenticated() == [], upstream.requests


async def test_aggregate_excludes_a_server_whose_credential_cannot_be_produced(token_env):
    """Fail closed per server: with no signing key the token-mode server is left out of the merged
    list (and logged), the request still succeeds, and the upstream is never contacted."""
    client, app, _, upstream = token_env
    app.state.token_issuer = None
    app.state.pipeline.set_token_issuer(None)

    resp = await client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["result"]["tools"] == []
    assert upstream.requests == [], "no credential -> the upstream must not be contacted"
