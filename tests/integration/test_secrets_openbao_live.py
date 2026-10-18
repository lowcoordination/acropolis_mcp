"""Verifies OpenBaoSecretProvider against a REAL Vault-API-speaking server.

This is the "real dev-mode server" verification named in the plan and issue #6 — a disposable
`bao server -dev` (or `vault server -dev`) process, started fresh for this test module and torn
down after, exactly like tests/integration/fastmcp_fixture.py does for a real FastMCP server.
Nothing here talks to any specific operator's Vault/OpenBao instance; see
tests/integration/openbao_fixture.py's docstring.

Skipped entirely if neither `bao` nor `vault` is on PATH — see
tests/unit/test_secrets_openbao_stub.py for the protocol-shape-only fallback that runs
regardless, and the PR description for which of the two ran in the environment this was built in.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from archon.secrets import SecretResolutionError
from archon.secrets.openbao import OpenBaoSecretProvider

from .openbao_fixture import has_real_server, run_dev_server

pytestmark = pytest.mark.skipif(
    not has_real_server(), reason="neither 'bao' nor 'vault' binary available on PATH"
)


@pytest.mark.asyncio
async def test_resolve_against_real_dev_server():
    async with run_dev_server() as vault:
        provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
        try:
            ref = await provider.store(
                "vault://secret/acropolis/test-server#token", "Bearer sk-real-upstream-cred"
            )
            assert ref == "vault://secret/acropolis/test-server#token"

            resolved = await provider.resolve(ref)
            assert resolved == "Bearer sk-real-upstream-cred"
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_resolve_missing_secret_raises_clear_error():
    async with run_dev_server() as vault:
        provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
        try:
            with pytest.raises(SecretResolutionError) as exc_info:
                await provider.resolve("vault://secret/nonexistent/path#token")
            assert "no secret found" in str(exc_info.value).lower()
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_resolve_wrong_key_in_secret_raises_clear_error():
    async with run_dev_server() as vault:
        provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
        try:
            await provider.store("vault://secret/acropolis/svc#token", "Bearer abc")
            with pytest.raises(SecretResolutionError) as exc_info:
                await provider.resolve("vault://secret/acropolis/svc#wrong-key-name")
            assert "not present" in str(exc_info.value).lower()
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_bad_token_is_denied_not_garbage():
    async with run_dev_server() as vault:
        provider = OpenBaoSecretProvider(base_url=vault.url, token="totally-wrong-token", ttl_seconds=60.0)
        try:
            with pytest.raises(SecretResolutionError) as exc_info:
                await provider.resolve("vault://secret/acropolis/whatever#token")
            assert "denied" in str(exc_info.value).lower()
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_rotation_is_picked_up_after_ttl_without_restart():
    """The core behavioural requirement: resolution at call time with a short TTL cache means a
    credential rotated in Vault propagates to Acropolis without any process restart.

    The rotation itself is done through a SECOND provider instance pointed at the same Vault —
    modeling an operator (or an external rotation job) writing a new value directly in Vault,
    which is the realistic rotation path this feature exists for. If the write went through the
    SAME provider instance that's about to resolve(), its own store() would invalidate its own
    cache entry and the test would trivially pass without actually proving the TTL does
    anything — using two instances closes that gap. Uses a very small TTL so the test doesn't
    need to sleep for anywhere near the production default of 60s.
    """
    async with run_dev_server() as vault:
        reader = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=0.2)
        rotator = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=0.2)
        try:
            ref = await rotator.store("vault://secret/acropolis/rotating#token", "Bearer v1-old-token")
            assert await reader.resolve(ref) == "Bearer v1-old-token"

            # External rotation: a different provider instance (standing in for `vault kv put`
            # run by an operator, or an automated rotation job) writes a new value directly.
            await rotator.store(ref, "Bearer v2-new-token")

            # Still within the reader's TTL window: it must keep serving its OWN cached value —
            # proving the cache is actually doing something (a real, provable behaviour) rather
            # than "no error was raised" being mistaken for correctness.
            assert await reader.resolve(ref) == "Bearer v1-old-token"

            import asyncio

            await asyncio.sleep(0.3)  # let the reader's 0.2s TTL expire

            # Same reader instance, no restart, no re-construction — just time passing — now
            # picks up the rotated value.
            assert await reader.resolve(ref) == "Bearer v2-new-token"
        finally:
            await reader.aclose()
            await rotator.aclose()


@pytest.mark.asyncio
async def test_outage_produces_error_never_a_returned_value():
    """Stop the dev server mid-test (simulating a Vault outage) and confirm resolution fails
    loudly with SecretResolutionError — never returns a stale/garbage value, never hangs
    indefinitely, never raises some other unhandled exception type that a caller wouldn't know
    to catch."""
    async with run_dev_server() as vault:
        provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
        try:
            ref = await provider.store("vault://secret/acropolis/svc#token", "Bearer v1")
            assert await provider.resolve(ref) == "Bearer v1"
        finally:
            await provider.aclose()

    # The `async with` block above has exited — the dev server process has been terminated.
    # Point a FRESH provider (no warm cache) at the now-dead address to simulate an outage.
    dead_provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
    try:
        with pytest.raises(SecretResolutionError) as exc_info:
            await dead_provider.resolve("vault://secret/acropolis/svc#token")
        assert "could not reach vault" in str(exc_info.value).lower()
    finally:
        await dead_provider.aclose()


async def _enable_approle_and_get_credentials(vault, role_name: str = "acropolis-test") -> tuple[str, str]:
    """AppRole is a nice-to-have per the plan, not a hard requirement — but since it's
    implemented, it gets real coverage against the same disposable dev server as everything
    else here, not left completely untested. Enables the approle auth method and a role via raw
    HTTP (mirroring what an operator would do with `vault auth enable approle` /
    `vault write auth/approle/role/...`), then returns (role_id, secret_id) for
    OpenBaoSecretProvider's AppRole login path to consume."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        headers = {"X-Vault-Token": vault.token}
        resp = await client.post(f"{vault.url}/v1/sys/auth/approle", headers=headers, json={"type": "approle"})
        assert resp.status_code in (200, 204), resp.text

        # A real policy granting read on the KV path under test — Vault's built-in "default"
        # policy alone does not grant access to arbitrary secret/ paths, so a role using only
        # "default" would 403 on every read regardless of whether AppRole auth itself worked,
        # making the test meaningless. This is the realistic operational step ("policy" here is
        # a bit of Vault plumbing unrelated to Acropolis's own ServerPolicy), not something an
        # Acropolis operator would skip in practice.
        policy_hcl = 'path "secret/data/acropolis/*" { capabilities = ["read"] }'
        resp = await client.put(
            f"{vault.url}/v1/sys/policies/acl/acropolis-test-read", headers=headers,
            json={"policy": policy_hcl},
        )
        assert resp.status_code in (200, 204), resp.text

        resp = await client.post(
            f"{vault.url}/v1/auth/approle/role/{role_name}", headers=headers,
            json={"token_policies": "acropolis-test-read"},
        )
        assert resp.status_code in (200, 204), resp.text

        resp = await client.get(f"{vault.url}/v1/auth/approle/role/{role_name}/role-id", headers=headers)
        assert resp.status_code == 200, resp.text
        role_id = resp.json()["data"]["role_id"]

        resp = await client.post(f"{vault.url}/v1/auth/approle/role/{role_name}/secret-id", headers=headers)
        assert resp.status_code == 200, resp.text
        secret_id = resp.json()["data"]["secret_id"]

    return role_id, secret_id


@pytest.mark.asyncio
async def test_approle_auth_resolves_against_real_dev_server():
    async with run_dev_server() as vault:
        role_id, secret_id = await _enable_approle_and_get_credentials(vault)

        provider = OpenBaoSecretProvider(
            base_url=vault.url, role_id=role_id, secret_id=secret_id, ttl_seconds=60.0,
        )
        try:
            # Seed the secret using the root-token provider (AppRole's default policy has no
            # write access) — the AppRole-authenticated provider only needs to READ it, which
            # is the realistic division of privilege between "who provisions a secret" and "who
            # an application authenticates as to read it."
            seed_provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
            try:
                await seed_provider.store("vault://secret/acropolis/approle-test#token", "Bearer via-approle")
            finally:
                await seed_provider.aclose()

            resolved = await provider.resolve("vault://secret/acropolis/approle-test#token")
            assert resolved == "Bearer via-approle"
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_approle_bad_credentials_fail_cleanly():
    async with run_dev_server() as vault:
        await _enable_approle_and_get_credentials(vault)  # enables the auth method, ignore the real creds

        provider = OpenBaoSecretProvider(
            base_url=vault.url, role_id="not-a-real-role-id", secret_id="not-a-real-secret-id",
            ttl_seconds=60.0,
        )
        try:
            with pytest.raises(SecretResolutionError) as exc_info:
                await provider.resolve("vault://secret/acropolis/whatever#token")
            assert "approle login" in str(exc_info.value).lower()
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_delete_removes_secret():
    async with run_dev_server() as vault:
        provider = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=60.0)
        try:
            ref = await provider.store("vault://secret/acropolis/deleteme#token", "Bearer v1")
            assert await provider.resolve(ref) == "Bearer v1"

            await provider.delete(ref)

            with pytest.raises(SecretResolutionError):
                await provider.resolve(ref)
        finally:
            await provider.aclose()


@pytest.mark.asyncio
async def test_approle_secret_id_from_file_and_rotation_against_real_dev_server(tmp_path):
    """The secret_id comes from a FILE (Docker secret / Kubernetes Secret mount), is stripped of
    its trailing newline, and is re-read on the next login, so replacing the file rotates the
    credential with no restart. Real AppRole, real server."""
    async with run_dev_server() as vault:
        role_id, first_secret_id = await _enable_approle_and_get_credentials(vault)
        f = tmp_path / "vault_secret_id"
        f.write_text(first_secret_id + "\n")

        seed = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=0.0)
        try:
            await seed.store("vault://secret/acropolis/file-test#token", "Bearer via-file")
        finally:
            await seed.aclose()

        provider = OpenBaoSecretProvider(
            base_url=vault.url, role_id=role_id, secret_id_file=str(f), ttl_seconds=0.0,
        )
        try:
            assert await provider.resolve("vault://secret/acropolis/file-test#token") == "Bearer via-file"

            # Rotate: a new secret_id is issued, the old one revoked, the file replaced.
            async with httpx.AsyncClient(timeout=5.0) as client:
                headers = {"X-Vault-Token": vault.token}
                resp = await client.post(
                    f"{vault.url}/v1/auth/approle/role/acropolis-test/secret-id", headers=headers)
                new_secret_id = resp.json()["data"]["secret_id"]
                resp = await client.post(
                    f"{vault.url}/v1/auth/approle/role/acropolis-test/secret-id/destroy",
                    headers=headers, json={"secret_id": first_secret_id})
                assert resp.status_code in (200, 204), resp.text
            f.write_text(new_secret_id + "\n")
            provider._login_token_expires_at = 0.0  # make the next resolve log in again

            assert await provider.resolve("vault://secret/acropolis/file-test#token") == "Bearer via-file"
        finally:
            await provider.aclose()


# ---------------------------------------------------------------- Kubernetes auth, real OpenBao

def _throwaway_signed_jwt(sub: str) -> str:
    """A JWT signed with a throwaway RSA key. OpenBao's Kubernetes auth rejects non-asymmetric
    algorithms (HS256 gets "unexpected signature algorithm") but does not hold the cluster's
    keys: whether the token is genuine is decided by the Kubernetes TokenReview API, which is what
    is faked below."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    # The claim shape a real bound service-account token carries: the identity OpenBao matches
    # against the role comes from these claims (the nested "kubernetes.io" one on modern clusters),
    # not from `sub` alone.
    _, _, namespace, name = sub.split(":")
    now = int(time.time())
    claims = {
        "iss": "https://kubernetes.default.svc", "sub": sub, "aud": ["https://kubernetes.default.svc"],
        "iat": now, "nbf": now, "exp": now + 3600,
        "kubernetes.io": {"namespace": namespace, "serviceaccount": {"name": name, "uid": "uid-1"}},
    }
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64(sig)}"


class _FakeKubeAPI:
    """Just the one endpoint OpenBao calls to validate a login: POST /apis/authentication.k8s.io/
    v1/tokenreviews. Everything else about Kubernetes is absent."""

    def __init__(self) -> None:
        self.username = "system:serviceaccount:acropolis:acropolis"
        self.authenticated = True
        self.reviewed: list[str] = []
        self._server: HTTPServer | None = None

    def start(self) -> str:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                review = json.loads(self.rfile.read(length) or b"{}")
                outer.reviewed.append(review.get("spec", {}).get("token", ""))
                status = {"authenticated": outer.authenticated}
                if outer.authenticated:
                    # A real API server echoes the audiences it validated the token for.
                    status["audiences"] = review.get("spec", {}).get("audiences") or [
                        "https://kubernetes.default.svc"]
                    status["user"] = {"username": outer.username, "uid": "uid-1",
                                      "groups": ["system:serviceaccounts", "system:authenticated"]}
                body = json.dumps({"kind": "TokenReview", "apiVersion": "authentication.k8s.io/v1",
                                   "status": status}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self._server.server_port}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


def _throwaway_ca_pem() -> str:
    """OpenBao insists on a CA certificate for the Kubernetes API when it is told not to use the
    pod-local one. The fake API below is plain HTTP, so this is never used to verify anything."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-kube-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


async def _enable_kubernetes_auth(vault, kube_url: str) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        headers = {"X-Vault-Token": vault.token}
        resp = await client.post(f"{vault.url}/v1/sys/auth/kubernetes", headers=headers, json={"type": "kubernetes"})
        assert resp.status_code in (200, 204), resp.text
        resp = await client.post(f"{vault.url}/v1/auth/kubernetes/config", headers=headers, json={
            "kubernetes_host": kube_url, "token_reviewer_jwt": "reviewer-token",
            "disable_iss_validation": True, "disable_local_ca_jwt": True,
            "kubernetes_ca_cert": _throwaway_ca_pem()})
        assert resp.status_code in (200, 204), resp.text
        resp = await client.put(
            f"{vault.url}/v1/sys/policies/acl/acropolis-k8s-read", headers=headers,
            json={"policy": 'path "secret/data/acropolis/*" { capabilities = ["read"] }'})
        assert resp.status_code in (200, 204), resp.text
        resp = await client.post(f"{vault.url}/v1/auth/kubernetes/role/acropolis", headers=headers, json={
            "bound_service_account_names": ["acropolis"],
            "bound_service_account_namespaces": ["acropolis"],
            "policies": ["acropolis-k8s-read"], "ttl": "1h"})
        assert resp.status_code in (200, 204), resp.text


@pytest.mark.asyncio
async def test_kubernetes_auth_against_real_dev_server_with_a_fake_tokenreview(tmp_path):
    """The REAL server's Kubernetes login protocol and role bindings; only the Kubernetes API
    server is faked (a real one is not available to a test). Proves: the request shape the client
    sends is accepted, the returned token works for KV reads, and the role's bindings are enforced."""
    kube = _FakeKubeAPI()
    kube_url = kube.start()
    jwt_file = tmp_path / "token"
    jwt = _throwaway_signed_jwt("system:serviceaccount:acropolis:acropolis")
    jwt_file.write_text(jwt + "\n")
    try:
        async with run_dev_server() as vault:
            await _enable_kubernetes_auth(vault, kube_url)
            seed = OpenBaoSecretProvider(base_url=vault.url, token=vault.token, ttl_seconds=0.0)
            try:
                await seed.store("vault://secret/acropolis/k8s-test#token", "Bearer via-k8s")
            finally:
                await seed.aclose()

            provider = OpenBaoSecretProvider(
                base_url=vault.url, auth_method="kubernetes", k8s_role="acropolis",
                k8s_token_file=str(jwt_file), ttl_seconds=0.0,
            )
            try:
                assert await provider.resolve("vault://secret/acropolis/k8s-test#token") == "Bearer via-k8s"
                assert kube.reviewed == [jwt], "the server must have asked Kubernetes to review exactly our JWT"

                # Wrong service account: the TokenReview says the token belongs to someone else.
                kube.username = "system:serviceaccount:other:intruder"
                provider._login_token_expires_at = 0.0
                with pytest.raises(SecretResolutionError) as exc:
                    await provider.resolve("vault://secret/acropolis/k8s-test#token")
                assert "kubernetes auth login" in str(exc.value).lower()
                assert jwt not in str(exc.value)

                # Kubernetes says the token is not valid (deleted pod / expired).
                kube.username, kube.authenticated = "system:serviceaccount:acropolis:acropolis", False
                with pytest.raises(SecretResolutionError):
                    await provider.resolve("vault://secret/acropolis/k8s-test#token")
            finally:
                await provider.aclose()
    finally:
        kube.stop()
