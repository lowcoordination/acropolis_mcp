"""Protocol-shape verification of OpenBaoSecretProvider against a MINIMAL in-process HTTP
stub — not a real Vault/OpenBao server.

This module exists as the documented fallback for environments where neither `bao` nor `vault`
is on PATH (see tests/integration/openbao_fixture.py and tests/integration/
test_secrets_openbao_live.py, which run the SAME class against a real dev-mode server whenever
one of those binaries is available). It proves the CLIENT's own request/response handling —
correct URL construction, header, JSON body shape, and status-code branches — against a
hand-written server that implements just enough of the KV v2 read/write/delete surface to
exercise that. It does NOT prove anything about real Vault/OpenBao's actual behavior, auth
flows, or edge cases; it is deliberately labeled a protocol-shape test, not an integration test.
This module always runs (no skip), specifically so CI/a from-scratch checkout without either
binary installed still gets SOME coverage of this client rather than silently zero.
"""
from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from archon.secrets import SecretResolutionError
from archon.secrets.openbao import OpenBaoSecretProvider

_VALID_TOKEN = "stub-token"


class _KVv2StubHandler(BaseHTTPRequestHandler):
    """Just enough of Vault's KV v2 HTTP API to exercise the client: token check, GET/POST/DELETE
    on /v1/<mount>/data/<path>, and DELETE on /v1/<mount>/metadata/<path>. In-memory store, no
    persistence, no versioning, no leases — a shape stub, not a spec-complete implementation."""

    store: dict[str, dict[str, str]] = {}

    def log_message(self, *args):  # silence stdout during tests
        pass

    def _check_token(self) -> bool:
        return self.headers.get("X-Vault-Token") == _VALID_TOKEN

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if not self._check_token():
            return self._send_json(403, {"errors": ["permission denied"]})
        if "/data/" not in self.path:
            return self._send_json(404, {"errors": ["not found"]})
        key = self.path.split("/v1/", 1)[1]
        data = _KVv2StubHandler.store.get(key)
        if data is None:
            return self._send_json(404, {"errors": []})
        self._send_json(200, {"data": {"data": data, "metadata": {"version": 1}}})

    def do_POST(self):
        if not self._check_token():
            return self._send_json(403, {"errors": ["permission denied"]})
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return self._send_json(400, {"errors": ["bad json"]})
        key = self.path.split("/v1/", 1)[1]
        _KVv2StubHandler.store[key] = body.get("data", {})
        self._send_json(200, {"data": {"version": 1}})

    def do_DELETE(self):
        if not self._check_token():
            return self._send_json(403, {"errors": ["permission denied"]})
        key = self.path.split("/v1/", 1)[1].replace("metadata/", "data/", 1)
        _KVv2StubHandler.store.pop(key, None)
        self.send_response(204)
        self.end_headers()


@contextlib.contextmanager
def _run_stub_server():
    _KVv2StubHandler.store = {}
    server = HTTPServer(("127.0.0.1", 0), _KVv2StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.asyncio
async def test_store_and_resolve_round_trip_against_stub():
    with _run_stub_server() as base_url:
        provider = OpenBaoSecretProvider(base_url=base_url, token=_VALID_TOKEN, ttl_seconds=60.0)
        try:
            ref = await provider.store("vault://secret/acropolis/svc#token", "Bearer stub-value")
            assert ref == "vault://secret/acropolis/svc#token"
            assert await provider.resolve(ref) == "Bearer stub-value"
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_missing_key_raises_secret_resolution_error():
    with _run_stub_server() as base_url:
        provider = OpenBaoSecretProvider(base_url=base_url, token=_VALID_TOKEN, ttl_seconds=60.0)
        try:
            with pytest.raises(SecretResolutionError):
                await provider.resolve("vault://secret/acropolis/nope#token")
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_bad_token_denied():
    with _run_stub_server() as base_url:
        provider = OpenBaoSecretProvider(base_url=base_url, token="wrong", ttl_seconds=60.0)
        try:
            with pytest.raises(SecretResolutionError):
                await provider.resolve("vault://secret/acropolis/svc#token")
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_unreachable_address_raises_secret_resolution_error():
    # A closed port on localhost — nothing listening — simulates an outage without depending on
    # any real or stub server being up.
    provider = OpenBaoSecretProvider(base_url="http://127.0.0.1:1", token=_VALID_TOKEN, ttl_seconds=60.0)
    try:
        with pytest.raises(SecretResolutionError) as exc_info:
            await provider.resolve("vault://secret/acropolis/svc#token")
        assert "could not reach vault" in str(exc_info.value).lower()
    finally:
        await provider.aclose()


def test_construction_requires_base_url():
    from archon.secrets.openbao import OpenBaoConfigError

    with pytest.raises(OpenBaoConfigError):
        OpenBaoSecretProvider(base_url="", token="x")


def test_construction_requires_an_auth_mode():
    from archon.secrets.openbao import OpenBaoConfigError

    with pytest.raises(OpenBaoConfigError):
        OpenBaoSecretProvider(base_url="http://127.0.0.1:8200")


def test_parse_vault_ref_rejects_malformed_strings():
    from archon.secrets.openbao import VaultRefError, parse_vault_ref

    with pytest.raises(VaultRefError):
        parse_vault_ref("not-a-vault-ref")
    with pytest.raises(VaultRefError):
        parse_vault_ref("vault://missing-key-fragment")

    ref = parse_vault_ref("vault://secret/acropolis/svc#token")
    assert ref.mount == "secret"
    assert ref.path == "acropolis/svc"
    assert ref.key == "token"
    assert str(ref) == "vault://secret/acropolis/svc#token"
