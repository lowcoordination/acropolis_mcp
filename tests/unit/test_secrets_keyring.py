"""Key-ring tests for the encrypted secret provider (R2, issue #29).

The ring is the rotation mechanism: keys[0] is the ACTIVE key for writes; resolve() tries the
active key first, then each remaining key in order, and fails only when all of them fail.
These tests pin the rotation semantics (old ciphertext keeps resolving during the window,
new writes always go under the active key, all-keys-fail is fail-closed with the UNCHANGED
message) and the env/file sourcing (plural forms + singular compat + ambiguous-both error).
"""
from __future__ import annotations

import base64
import os

import pytest

from archon.secrets import SecretResolutionError
from archon.secrets.encrypted import (
    PREFIX,
    EncryptedProviderConfigError,
    EncryptedSecretProvider,
    KeyRing,
    _parse_key_material,
    build_key_ring,
)


def _hex_key() -> str:
    return os.urandom(32).hex()


def _provider_from_keys(key_hexes: list[str]) -> EncryptedSecretProvider:
    return EncryptedSecretProvider(key_ring=KeyRing([_parse_key_material(k) for k in key_hexes]))


def _provider_from_single(key_hex: str) -> EncryptedSecretProvider:
    class _StaticKeySource:
        def __init__(self, hexkey: str):
            self._key = _parse_key_material(hexkey)

        def get_key(self) -> bytes:
            return self._key

    return EncryptedSecretProvider(key_source=_StaticKeySource(key_hex))


@pytest.mark.asyncio
async def test_store_always_uses_active_key():
    """Ciphertext written by a ring must decrypt under the ACTIVE key alone — proving store()
    encrypts with the active key, not merely that the ring round-trips."""
    active, old = _hex_key(), _hex_key()
    ring_provider = _provider_from_keys([active, old])
    ref = await ring_provider.store("ignored", "Bearer sk-rotation-test")

    # A single-key provider holding ONLY the active key decrypts it.
    active_only = _provider_from_single(active)
    assert await active_only.resolve(ref) == "Bearer sk-rotation-test"

    # A single-key provider holding ONLY the old key cannot (it was encrypted under active).
    old_only = _provider_from_single(old)
    with pytest.raises(SecretResolutionError):
        await old_only.resolve(ref)


@pytest.mark.asyncio
async def test_pre_rotation_ciphertext_resolves_through_ring():
    """The rotation window: ciphertext written under the OLD key keeps resolving while the new
    key is active, because the old key is still in the ring."""
    active, old = _hex_key(), _hex_key()
    pre_rotation_ref = await _provider_from_single(old).store("ignored", "Bearer sk-old-key-era")

    ring_provider = _provider_from_keys([active, old])
    assert await ring_provider.resolve(pre_rotation_ref) == "Bearer sk-old-key-era"

    # And once the old key is dropped from the ring, the same ciphertext is bricked (fail-closed).
    active_only = _provider_from_single(active)
    with pytest.raises(SecretResolutionError):
        await active_only.resolve(pre_rotation_ref)


@pytest.mark.asyncio
async def test_all_keys_fail_keeps_unchanged_message():
    """When every ring key fails, the error message must be byte-identical to the single-key
    era's — log/alert greps and the fail-closed contract don't change with rotation."""
    active, old = _hex_key(), _hex_key()
    foreign = _provider_from_single(_hex_key())
    ref = await foreign.store("ignored", "Bearer sk-foreign-key")

    ring_provider = _provider_from_keys([active, old])
    with pytest.raises(SecretResolutionError) as exc_info:
        await ring_provider.resolve(ref)
    assert str(exc_info.value).endswith(
        "decryption failed (wrong key or corrupted ciphertext)"
    )
    assert "wrong key or corrupted" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ring_round_trip_returns_original():
    ring_provider = _provider_from_keys([_hex_key(), _hex_key()])
    original = "Bearer sk-ring-round-trip"
    assert await ring_provider.resolve(await ring_provider.store("ignored", original)) == original


@pytest.mark.asyncio
async def test_non_enc_prefixed_ref_still_rejected_by_ring():
    ring_provider = _provider_from_keys([_hex_key(), _hex_key()])
    with pytest.raises(SecretResolutionError):
        await ring_provider.resolve("just a literal, not ciphertext")


def test_key_source_and_key_ring_are_mutually_exclusive():
    class _StaticKeySource:
        def __init__(self, hexkey: str):
            self._key = _parse_key_material(hexkey)

        def get_key(self) -> bytes:
            return self._key

    with pytest.raises(ValueError, match="either key_source or key_ring"):
        EncryptedSecretProvider(
            key_source=_StaticKeySource(_hex_key()), key_ring=KeyRing([os.urandom(32)])
        )


def test_empty_ring_is_config_error():
    with pytest.raises(EncryptedProviderConfigError, match="empty"):
        KeyRing([])


def test_ring_validates_every_key_length():
    with pytest.raises(EncryptedProviderConfigError, match="exactly"):
        KeyRing([os.urandom(32), os.urandom(16)])


def test_build_key_ring_singular_env_is_one_key_ring(monkeypatch):
    """Compatibility: the original ACROPOLIS_SECRET_KEY env var alone must produce a working
    ring (that key active + the only decryption key) — nothing about rotation may break the
    single-key deployment that existed before it."""
    key_hex = _hex_key()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS_FILE", raising=False)
    ring = build_key_ring()
    assert ring.active == bytes.fromhex(key_hex)
    assert len(ring) == 1


def test_build_key_ring_singular_file_is_one_key_ring(monkeypatch, tmp_path):
    key_hex = _hex_key()
    key_file = tmp_path / "secret.key"
    key_file.write_text(key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY_FILE", str(key_file))
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS_FILE", raising=False)
    ring = build_key_ring()
    assert ring.active == bytes.fromhex(key_hex)
    assert len(ring) == 1


def test_build_key_ring_plural_env_first_key_is_active(monkeypatch):
    """ACROPOLIS_SECRET_KEYS: comma-separated, FIRST key active, rest decryption-only."""
    k1, k2, k3 = _hex_key(), _hex_key(), _hex_key()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEYS", f"{k1},{k2},{k3}")
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS_FILE", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    ring = build_key_ring()
    assert ring.active == bytes.fromhex(k1)
    assert ring.candidates == [bytes.fromhex(k) for k in (k1, k2, k3)]
    assert len(ring) == 3


def test_build_key_ring_plural_env_accepts_base64_mixed(monkeypatch):
    hex_key = _hex_key()
    b64_key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEYS", f"{hex_key},{b64_key}")
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS_FILE", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    ring = build_key_ring()
    assert len(ring) == 2
    assert ring.candidates[1] == base64.b64decode(b64_key)


def test_build_key_ring_plural_file_first_line_is_active(monkeypatch, tmp_path):
    k1, k2 = _hex_key(), _hex_key()
    key_file = tmp_path / "keys.ring"
    key_file.write_text(f"{k1}\n\n{k2}\n")  # blank line ignored
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS", raising=False)
    monkeypatch.setenv("ACROPOLIS_SECRET_KEYS_FILE", str(key_file))
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    ring = build_key_ring()
    assert ring.active == bytes.fromhex(k1)
    assert ring.candidates == [bytes.fromhex(k1), bytes.fromhex(k2)]


def test_build_key_ring_plural_and_singular_is_ambiguous_error(monkeypatch):
    """Both forms set = ambiguous intent. There is no sensible precedence between "the ring"
    and "the single key" — the operator must pick one, or they might believe rotation is
    configured when the active key is actually the singular one."""
    monkeypatch.setenv("ACROPOLIS_SECRET_KEYS", f"{_hex_key()},{_hex_key()}")
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", _hex_key())
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS_FILE", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    with pytest.raises(EncryptedProviderConfigError, match="not both"):
        build_key_ring()


def test_build_key_ring_neither_form_is_config_error(monkeypatch):
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEYS_FILE", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    with pytest.raises(EncryptedProviderConfigError):
        build_key_ring()


def test_ring_ciphertext_prefix_unchanged():
    """Rotation must not touch the ciphertext format — enc:v1: stays the prefix; the ring is
    key management, not a format change (a format bump to enc:v2: is a separate, optional
    future optimization)."""
    ring_provider = _provider_from_keys([_hex_key(), _hex_key()])
    ref = None

    async def _store():
        nonlocal ref
        ref = await ring_provider.store("ignored", "hello")

    import asyncio
    asyncio.run(_store())
    assert ref.startswith(PREFIX)
