"""The `local` SecretProvider is the regression guard for enterprise #5 — resolve()/store() must
be byte-identical to a plain pass-through, since selecting `local` (the default) must reproduce
pre-feature behaviour exactly."""
from __future__ import annotations

import pytest

from archon.secrets import build_secret_provider
from archon.secrets.local import LocalSecretProvider
from archon.settings import Settings


@pytest.mark.asyncio
async def test_resolve_returns_input_unchanged():
    provider = LocalSecretProvider()
    assert await provider.resolve("Bearer sk-abc123") == "Bearer sk-abc123"
    assert await provider.resolve("") == ""
    # Even something that LOOKS like a reference is returned byte-for-byte unchanged — the
    # local provider does no interpretation of its input whatsoever.
    assert await provider.resolve("vault://secret/x#y") == "vault://secret/x#y"


@pytest.mark.asyncio
async def test_store_returns_value_unchanged():
    provider = LocalSecretProvider()
    stored_ref = await provider.store("ignored", "Bearer sk-abc123")
    assert stored_ref == "Bearer sk-abc123"


@pytest.mark.asyncio
async def test_delete_is_a_noop():
    provider = LocalSecretProvider()
    # Must not raise, must not require any prior store().
    await provider.delete("anything")


@pytest.mark.asyncio
async def test_resolve_is_idempotent_round_trip():
    provider = LocalSecretProvider()
    original = "Basic dXNlcjpwYXNz"
    stored = await provider.store("ref", original)
    resolved = await provider.resolve(stored)
    assert resolved == original


def test_default_settings_select_local_provider():
    settings = Settings()
    assert settings.secret_provider == "local"
    provider = build_secret_provider(settings)
    assert isinstance(provider, LocalSecretProvider)
