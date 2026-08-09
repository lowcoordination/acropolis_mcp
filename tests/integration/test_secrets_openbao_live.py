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
