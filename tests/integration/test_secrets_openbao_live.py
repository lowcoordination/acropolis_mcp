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
