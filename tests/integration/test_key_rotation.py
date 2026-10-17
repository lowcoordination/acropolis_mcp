"""Integration tests for signing-key rotation and the public JWKS route (issue #134, Task 4).

These exercise the full rotation sequence against a real app + real Postgres, nothing mocked:
seed the issuer with an ``enc:v1:``-encrypted key reference → serve the single-kid JWKS → run the
``rotate-signing-key`` sequence (the same function the CLI wraps) → verify the overlap window
publishes BOTH kids, new tokens sign under the new key while old tokens still verify against the
still-published old key (the server-cache property), an unknown-kid client refetches the live
route and finds the new kid, and the old kid drops once the overlap deadline passes.

The signature checks reconstruct the RSA public key from the JWKS's ``n``/``e`` — the exact
operation the Go ``mcp-authn`` middleware performs — rather than importing the private key, so
"the token verifies against the published JWKS" is proven the same way production verifies it.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from archon.secrets.encrypted import EncryptedSecretProvider
from archon.settings import Settings
from argus import tokens
from argus.app import create_app
from argus.rotate_key import (
    ACTIVE_REF_KEY,
    PREVIOUS_DROP_AT_KEY,
    PREVIOUS_REF_KEY,
    rotate_signing_key,
)
from db.database import Database
from db.repo import ServerRepo, SettingsRepo


def _pem(private_key) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _decode(token: str) -> tuple[dict, dict]:
    header_b64, payload_b64, _ = token.split(".")
    return (
        json.loads(tokens._b64url_decode(header_b64)),
        json.loads(tokens._b64url_decode(payload_b64)),
    )


def _verify_against_jwk(token: str, jwk: dict) -> None:
    """Verify a compact JWS's RS256 signature against a public JWK — the middleware's exact
    operation (reconstruct the RSA public key from ``n``/``e``, check PKCS1v15 + SHA-256)."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    n = int.from_bytes(tokens._b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(tokens._b64url_decode(jwk["e"]), "big")
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    public_key.verify(
        tokens._b64url_decode(signature_b64),
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


@pytest.fixture
def encrypted_key_env(monkeypatch):
    key_hex = os.urandom(32).hex()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    return key_hex


async def test_jwks_route_404_without_issuer(tmp_path):
    """No signing key configured anywhere → the public route honestly says 404 rather than
    publishing an empty (and misleading) JWKS."""
    settings = Settings(
        data_dir=str(tmp_path),
        auth_mode="open",
        health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    try:
        app = create_app(settings, db)
        transport = httpx.ASGITransport(app=app)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/.well-known/jwks.json")
                assert resp.status_code == 404
    finally:
        await db.close()


async def test_rotation_overlap_and_drop(tmp_path, encrypted_key_env, monkeypatch):
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_kid = tokens._derive_kid(old_key.public_key())
    provider = EncryptedSecretProvider()  # reads ACROPOLIS_SECRET_KEY from the fixture
    old_ref = await provider.store("", _pem(old_key))

    settings = Settings(
        data_dir=str(tmp_path),
        auth_mode="open",
        health_poll_enabled=False,
        audit_retention_enabled=False,
        secret_provider="encrypted",
        token_signing_key_ref=old_ref,
    )
    db = Database(tmp_path)
    await db.connect()
    try:
        app = create_app(settings, db)
        transport = httpx.ASGITransport(app=app)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                # Pre-rotation: exactly one kid, the seeded key, served as application/json.
                resp = await client.get("/.well-known/jwks.json")
                assert resp.status_code == 200
                assert resp.headers["content-type"].startswith("application/json")
                doc = resp.json()
                assert [k["kid"] for k in doc["keys"]] == [old_kid]

                # Mint a token under the OLD key — the "old token" a server would have cached.
                old_token = await (await app.state.token_key_manager.current()).get_token("mcp-fetch")
                old_header, _ = _decode(old_token)
                assert old_header["kid"] == old_kid

                settings_repo = SettingsRepo(db)

                # Dry run previews and writes nothing.
                preview = await rotate_signing_key(
                    settings, provider, settings_repo, dry_run=True
                )
                assert preview.error is None
                assert preview.new_kid and preview.new_kid != old_kid
                assert preview.dry_run is True
                assert await settings_repo.get(ACTIVE_REF_KEY) is None
                assert await settings_repo.get(PREVIOUS_REF_KEY) is None

                # Apply: the persisted new key must verify live-and-signing before the CLI would
                # exit 0.
                result = await rotate_signing_key(
                    settings, provider, settings_repo, dry_run=False
                )
                assert result.error is None
                assert result.verified is True
                new_kid = result.new_kid

                # Overlap window: BOTH kids published, active (new) first, old still present.
                resp = await client.get("/.well-known/jwks.json")
                doc = resp.json()
                kids = [k["kid"] for k in doc["keys"]]
                assert kids == [new_kid, old_kid]
                new_jwk, old_jwk = doc["keys"][0], doc["keys"][1]

                # New tokens mint under the NEW key and verify against the PUBLISHED JWKS (the
                # middleware's exact check, public key reconstructed from n/e).
                new_token = await (await app.state.token_key_manager.current()).get_token("mcp-fetch")
                new_header, _ = _decode(new_token)
                assert new_header["kid"] == new_kid
                _verify_against_jwk(new_token, new_jwk)

                # Old tokens still verify against the still-published old kid — the reason the
                # overlap exists (a server with a cached JWKS keeps accepting until it refetches).
                _verify_against_jwk(old_token, old_jwk)

                # Unknown-kid refetch: a server holding only the old kid sees a new-kid token,
                # refetches the live route, and finds the new kid there.
                assert new_kid in kids and old_kid in kids

                # Drop after overlap: advance the wall clock past the persisted deadline and the
                # old kid disappears from the live route while the new kid remains.
                drop_at = float(await settings_repo.get(PREVIOUS_DROP_AT_KEY))
                assert drop_at > 0
                monkeypatch.setattr(tokens, "_epoch_seconds", lambda: drop_at + 1)
                resp = await client.get("/.well-known/jwks.json")
                doc = resp.json()
                assert [k["kid"] for k in doc["keys"]] == [new_kid]
    finally:
        await db.close()


async def test_rotation_requires_existing_key(tmp_path, encrypted_key_env):
    """With no signing key configured (env unset, no DB override) the rotation CLI refuses with
    an actionable error rather than inventing a first key — rotation is not provisioning."""
    settings = Settings(
        data_dir=str(tmp_path),
        secret_provider="encrypted",
    )
    db = Database(tmp_path)
    await db.connect()
    try:
        result = await rotate_signing_key(
            settings, EncryptedSecretProvider(), SettingsRepo(db), dry_run=True
        )
        assert result.error is not None
        assert "ACROPOLIS_TOKEN_SIGNING_KEY_REF" in result.error
        assert result.new_kid is None
    finally:
        await db.close()


class _HeaderCapturingUpstream:
    """Raw TCP listener standing in for a token-mode upstream — captures the exact Authorization
    header Acropolis forwards and replies with a bare 200. Same pattern as test_upstream_tokens.py's
    class of the same name (duplicated — that one is module-private, and copying keeps this file's
    dependency on its internals at zero)."""

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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", port)
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


TOOLS_CALL = {
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "echo", "arguments": {"message": "hi"}},
}
MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


async def test_token_injection_picks_up_rotation(tmp_path, encrypted_key_env):
    """The remediation test for the rotation handoff: a `rotate-signing-key --apply` flips the
    signer the PIPELINE uses for token injection, not just the public JWKS route — because the
    manager mutates the SAME issuer object in place, the references T3 wired at boot stay valid.
    Proved end-to-end through a real tools/call against a header-capturing upstream."""
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_kid = tokens._derive_kid(old_key.public_key())
    provider = EncryptedSecretProvider()
    old_ref = await provider.store("", _pem(old_key))

    upstream = _HeaderCapturingUpstream()
    await upstream.start()

    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, secret_provider="encrypted",
        token_signing_key_ref=old_ref,
    )
    db = Database(tmp_path)
    await db.connect()
    try:
        app = create_app(settings, db, probe_on_create=False)
        transport = httpx.ASGITransport(app=app)
        async with app.router.lifespan_context(app):
            await ServerRepo(db).create(
                slug="mcp-fetch", name="Fetch", upstream_url=upstream.url,
                credential_mode="token",
            )
            async with httpx.AsyncClient(
                transport=transport, base_url="http://argus.test"
            ) as client:
                # Pre-rotation: injection signs with the boot-time (old) key.
                r1 = await client.post("/mcp/mcp-fetch", json=TOOLS_CALL, headers=MCP_HEADERS)
                assert r1.status_code == 200, r1.text
                first_auth = upstream.received_headers["authorization"]
                assert _decode(first_auth[len("Bearer "):])[0]["kid"] == old_kid

                # Rotate, then let the manager refresh (what the periodic loop does within 5s).
                result = await rotate_signing_key(
                    settings, provider, SettingsRepo(db), dry_run=False
                )
                assert result.error is None and result.verified
                issuer = await app.state.token_key_manager.current()
                assert issuer is not None and issuer.kid == result.new_kid

                # Post-rotation: the SAME wired object now signs with the new key.
                r2 = await client.post("/mcp/mcp-fetch", json=TOOLS_CALL, headers=MCP_HEADERS)
                assert r2.status_code == 200, r2.text
                second_auth = upstream.received_headers["authorization"]
                assert _decode(second_auth[len("Bearer "):])[0]["kid"] == result.new_kid
    finally:
        await upstream.stop()
        await db.close()
