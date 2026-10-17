"""Issue #134 T3: ``credential_mode=token`` on the upstream hop.

Proves, against a raw TCP listener standing in for the upstream (which captures the exact headers
Acropolis forwards — the same wire-level proof pattern test_security_registry.py uses):

  1. a token-mode tools/call reaches the upstream with a valid, audience-matching RS256 JWT;
  2. ``static`` mode still injects the resolved header (pre-#134 behaviour unchanged);
  3. ``none`` mode sends no Authorization header at all;
  4. a token-mode server with no signing key configured fails CLOSED — audited ERROR, and the
     upstream is never reached (the same guarantee as test_secret_resolution_failure.py);
  5. the minted token is audience-bound — a verifier configured for the wrong audience rejects it.

The signature/claim verification uses the Python-side verifier mirror (fixture_token_verifier) —
the same contract the Go middleware (T5) will enforce; the actual 401-on-wrong-audience lives on
the Go side, out of scope for this Python task.
"""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from archon.settings import Settings
from argus.app import create_app
from argus.tokens import TokenIssuer
from db.database import Database
from db.repo import AuditRepo, ServerRepo

from .fixture_token_verifier import verify_request_token


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _HeaderCapturingUpstream:
    """Raw TCP listener standing in for an MCP upstream — captures the exact request headers
    Acropolis forwards, replies with a bare 200 so the passthrough doesn't error. Same pattern as
    test_security_regression.py's class of the same name (duplicated — that one is module-private,
    and copying keeps this file's dependency on its internals at zero)."""

    def __init__(self) -> None:
        self.received_headers: dict[str, str] = {}
        self._server: asyncio.AbstractServer | None = None
        self.url = ""

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                self.received_headers[k.lower()] = v
        body = b'{"jsonrpc":"2.0","id":1,"result":{}}'
        writer.write(
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode() + body
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


MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

TOOLS_CALL = {
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "echo", "arguments": {"message": "hi"}},
}


@pytest.fixture
async def token_env(tmp_path: Path):
    """App + raw upstream + an in-memory TokenIssuer, injected AFTER lifespan startup (which
    legitimately leaves token_issuer=None because no signing key is configured in Settings)."""
    upstream = _HeaderCapturingUpstream()
    await upstream.start()
    private_key = _generate_rsa_key()
    issuer = TokenIssuer(private_key)
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    app = create_app(settings, db, probe_on_create=False)
    transport = httpx.ASGITransport(app=app)
    try:
        async with app.router.lifespan_context(app):
            # Startup ran from_settings -> None (no key); inject the test issuer after it, so the
            # requests below actually mint real tokens.
            app.state.token_issuer = issuer
            app.state.pipeline.set_token_issuer(issuer)
            app.state.health_poller.set_token_issuer(issuer)
            yield app, transport, db, server_repo, upstream, issuer, private_key
    finally:
        await upstream.stop()
        await db.close()


async def _tools_call(transport: httpx.ASGITransport, slug: str) -> httpx.Response:
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        return await client.post(f"/mcp/{slug}", json=TOOLS_CALL, headers=MCP_HEADERS)


async def test_token_mode_forward_sends_valid_audience_jwt(token_env):
    _, transport, _, server_repo, upstream, _, private_key = token_env
    await server_repo.create(
        slug="mcp-fetch", name="Fetch", upstream_url=upstream.url, credential_mode="token",
    )

    resp = await _tools_call(transport, "mcp-fetch")
    assert resp.status_code == 200, resp.text

    auth = upstream.received_headers.get("authorization")
    assert auth and auth.startswith("Bearer "), upstream.received_headers
    payload = verify_request_token(
        auth[len("Bearer "):], audience="mcp-fetch", issuer="acropolis",
        public_key=private_key.public_key(),
    )
    assert payload["aud"] == "mcp-fetch"


async def test_static_mode_still_resolves_header(token_env):
    _, transport, _, server_repo, upstream, _, _ = token_env
    await server_repo.create(
        slug="static-server", name="S", upstream_url=upstream.url,
        upstream_auth_header="Bearer static-token", credential_mode="static",
    )

    resp = await _tools_call(transport, "static-server")
    assert resp.status_code == 200, resp.text
    assert upstream.received_headers.get("authorization") == "Bearer static-token"


async def test_none_mode_sends_no_authorization(token_env):
    _, transport, _, server_repo, upstream, _, _ = token_env
    await server_repo.create(slug="open-server", name="O", upstream_url=upstream.url)  # default 'none'

    resp = await _tools_call(transport, "open-server")
    assert resp.status_code == 200, resp.text
    assert "authorization" not in upstream.received_headers


async def test_token_mode_without_issuer_fails_closed_and_is_audited(tmp_path: Path):
    upstream = _HeaderCapturingUpstream()
    await upstream.start()
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    app = create_app(settings, db, probe_on_create=False)
    transport = httpx.ASGITransport(app=app)
    try:
        async with app.router.lifespan_context(app):
            # token_issuer stays None (no signing key). Create the server DIRECTLY via the repo —
            # the API rejects token mode up front, so this exercises the pipeline's
            # defense-in-depth fail-closed for a token-mode row that somehow exists anyway.
            await server_repo.create(
                slug="tokened", name="T", upstream_url=upstream.url, credential_mode="token",
            )
            resp = await _tools_call(transport, "tokened")
            assert resp.status_code == 502, resp.text
            assert "token signing is not configured" in resp.text.lower()

            await asyncio.sleep(0.3)  # AuditLogger flushes asynchronously
            events = await AuditRepo(db).query(limit=10)
            matching = [e for e in events if e["server_slug"] == "tokened"]
            assert matching and matching[0]["decision"] == "ERROR", matching
    finally:
        await upstream.stop()
        await db.close()
    assert "authorization" not in upstream.received_headers  # never reached the upstream


async def test_minted_token_is_audience_bound(token_env):
    _, _, _, _, _, issuer, private_key = token_env
    token = await issuer.get_token("mcp-fetch")

    payload = verify_request_token(
        token, audience="mcp-fetch", issuer="acropolis", public_key=private_key.public_key(),
    )
    assert payload["aud"] == "mcp-fetch"

    # The audience-binding proof: a verifier configured for a DIFFERENT server must reject the
    # same token — the property the Go middleware enforces at the fleet (a stolen fetch-token
    # replayed at shell 401s).
    with pytest.raises(AssertionError, match="aud"):
        verify_request_token(
            token, audience="mcp-shell", issuer="acropolis", public_key=private_key.public_key(),
        )
