"""Issue #155: the three planes that need an upstream credential must agree on it.

The rule — token mode mints a JWT and ignores ``upstream_auth_header``; static/none resolve the
header through the secret provider; a failure must NEVER fall through to an unauthenticated request —
used to exist three times (control plane, data plane, health probe), and the drift between them was
issue #146. It now lives in ``argus.credentials.resolve_upstream_credential``; each plane maps a
failure to its own outcome. This test drives each plane's real entry point over the whole mode matrix
and asserts they produce the same credential, or all fail closed:

  * control plane — ``Pipeline.catalog_credential`` (the tool-catalog fetch's resolver);
  * data plane    — ``Pipeline._resolve_credential`` (a failure becomes an audited 502);
  * health        — ``probe_server`` against a recording upstream, so what is compared is what
                    actually crossed the wire (and that a failure sent NOTHING).

Reason strings are pinned too: the data plane's 502 text equals the control plane's, and the health
reason keeps its own (documented) wording.
"""
from __future__ import annotations

import asyncio
import base64
import json
import socket
from pathlib import Path
from typing import Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from archon.secrets import SecretResolutionError
from archon.settings import Settings
from argus.app import create_app
from argus.credentials import UpstreamCredentialError
from argus.tokens import TokenIssuer
from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.repo import ServerRepo
from stoa.health import probe_server

SLUG = "matrix"
REFERENCE = "vault://secret/acropolis/matrix#token"
RESOLVED = "Bearer resolved-from-provider"
FAIL = "FAIL"


class _Provider:
    """References resolve to RESOLVED, or raise when ``fail``; a literal passes through unchanged."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def resolve(self, ref: str) -> str:
        if ref.startswith("vault://"):
            if self.fail:
                raise SecretResolutionError(ref, "simulated resolution failure")
            return RESOLVED
        return ref

    async def store(self, ref: str, value: str) -> str:
        raise NotImplementedError

    async def delete(self, ref: str) -> None:
        raise NotImplementedError


class _MintFails:
    async def get_token(self, slug: str) -> str:
        raise RuntimeError("simulated mint failure")


class _Recorder:
    """A 2026-generation upstream (answers ``server/discover``) that records every Authorization
    header it receives. Raw TCP, the house pattern."""

    def __init__(self) -> None:
        self.seen: list[Optional[str]] = []
        self.url = ""
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            headers = {}
            for line in head.decode(errors="replace").split("\r\n")[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.lower()] = v
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            rpc = json.loads(body) if body else {}
            self.seen.append(headers.get("authorization"))
            data = json.dumps({"jsonrpc": "2.0", "id": rpc.get("id"), "result": {
                "supportedVersions": ["2026-07-28"], "serverInfo": {"name": "m", "version": "0"},
            }}).encode()
            writer.write(
                (f"HTTP/1.1 200 X\r\nContent-Type: application/json\r\n"
                 f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data
            )
            await writer.drain()
        finally:
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


def _audience(header: str) -> str:
    payload = header.removeprefix("Bearer ").split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["aud"]


def _normalise(header: Optional[str]) -> Optional[str]:
    """A minted token differs on every run, so compare it by what it asserts, not by bytes."""
    if header is not None and header.startswith("Bearer ey"):
        return f"JWT(aud={_audience(header)})"
    return header


@pytest.fixture
async def rig(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    app = create_app(
        Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
                 audit_retention_enabled=False),
        db,
    )
    upstream = _Recorder()
    await upstream.start()
    async with app.router.lifespan_context(app):
        yield app.state.pipeline, ServerRepo(db), upstream
    await upstream.stop()
    await db.close()


# (id, credential_mode, upstream_auth_header, provider_fails, issuer, expected credential or FAIL,
#  expected data/control-plane failure reason, expected health reason)
_REAL = "real"
_NONE = "none"
_BROKEN = "mint-fails"
_CASES = [
    ("none-no-header", "none", None, False, _REAL, None, None, None),
    ("none-legacy-literal", "none", "Bearer legacy", False, _REAL, "Bearer legacy", None, None),
    ("static-literal", "static", "Bearer literal", False, _REAL, "Bearer literal", None, None),
    ("static-reference", "static", REFERENCE, False, _REAL, RESOLVED, None, None),
    ("token-with-issuer", "token", None, False, _REAL, f"JWT(aud={SLUG})", None, None),
    ("token-ignores-header", "token", "Bearer ignored", False, _REAL, f"JWT(aud={SLUG})", None, None),
    ("token-no-issuer", "token", None, False, _NONE, FAIL,
     "token signing is not configured (ACROPOLIS_TOKEN_SIGNING_KEY_REF)",
     "token mint failed: token signing is not configured"),
    ("token-mint-fails", "token", None, False, _BROKEN, FAIL,
     "token mint failed", "token mint failed: token mint failed"),
    ("static-secret-fails", "static", REFERENCE, True, _REAL, FAIL,
     "secret resolution failed: simulated resolution failure",
     "secret resolution failed: simulated resolution failure"),
    ("none-legacy-reference-secret-fails", "none", REFERENCE, True, _REAL, FAIL,
     "secret resolution failed: simulated resolution failure",
     "secret resolution failed: simulated resolution failure"),
]


@pytest.mark.parametrize(
    "mode,header,provider_fails,issuer_kind,expected,failure_reason,health_reason",
    [c[1:] for c in _CASES], ids=[c[0] for c in _CASES],
)
async def test_all_planes_agree(
    rig, mode, header, provider_fails, issuer_kind, expected, failure_reason, health_reason,
):
    pipeline, repo, upstream = rig
    server = await repo.create(
        slug=SLUG, name="M", upstream_url=upstream.url, credential_mode=mode,
        upstream_auth_header=header,
    )
    provider = _Provider(fail=provider_fails)
    issuer = {
        _REAL: TokenIssuer(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        _NONE: None,
        _BROKEN: _MintFails(),
    }[issuer_kind]
    pipeline._secrets = provider
    pipeline._token_issuer = issuer

    # Control plane.
    try:
        control = _normalise(await pipeline.catalog_credential(server)())
        control_reason = None
    except UpstreamCredentialError as e:
        control, control_reason = FAIL, e.reason

    # Data plane: the real method; a failure is an audited 502 whose JSON-RPC message is the reason.
    try:
        data = _normalise(await pipeline._resolve_credential(
            server, rpc_method="tools/call", rpc_id=1, tool_name="t", api_key_id=None, start=0.0,
            client_ip=None,
        ))
        data_reason = None
    except pipeline._CredentialResolutionFailed as e:
        assert e.response.status_code == 502
        data, data_reason = FAIL, json.loads(e.response.body)["error"]["message"]

    # Health: what the upstream actually received.
    async with httpx.AsyncClient() as client:
        status, _, _, reason = await probe_server(
            client, UpstreamHandshakeCache(client), server, secret_provider=provider,
            token_issuer=issuer,
        )
    if expected == FAIL:
        health = FAIL
        assert status == "unhealthy"
        assert upstream.seen == [], "a failed credential must not send an unauthenticated probe"
    else:
        health = _normalise(upstream.seen[0])
        assert status == "healthy"
        assert reason is None

    assert control == expected
    assert data == expected
    assert health == expected
    assert control_reason == failure_reason
    assert data_reason == failure_reason
    if expected == FAIL:
        assert reason == health_reason
