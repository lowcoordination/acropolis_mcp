"""AES-GCM envelope encryption tier. Verification bar per the plan: round-trip returns the
original plaintext; the RAW ciphertext bytes never contain the plaintext; a wrong/missing key
fails cleanly (never returns garbage, never silently 'succeeds' with corrupted data)."""
from __future__ import annotations

import base64
import os

import pytest

from archon.secrets import SecretResolutionError
from archon.secrets.encrypted import (
    PREFIX,
    EncryptedProviderConfigError,
    EncryptedSecretProvider,
    _parse_key_material,
    build_key_source,
)


def _hex_key() -> str:
    return os.urandom(32).hex()


def _provider(key_hex: str | None = None) -> EncryptedSecretProvider:
    class _StaticKeySource:
        def __init__(self, hexkey: str):
            self._key = _parse_key_material(hexkey)

        def get_key(self) -> bytes:
            return self._key

    return EncryptedSecretProvider(key_source=_StaticKeySource(key_hex or _hex_key()))


@pytest.mark.asyncio
async def test_round_trip_returns_original_plaintext():
    provider = _provider()
    original = "Bearer sk-super-secret-upstream-token"
    ciphertext_ref = await provider.store("ignored", original)
    resolved = await provider.resolve(ciphertext_ref)
    assert resolved == original


@pytest.mark.asyncio
async def test_ciphertext_has_versioned_prefix():
    provider = _provider()
    ref = await provider.store("ignored", "hello")
    assert ref.startswith(PREFIX)


@pytest.mark.asyncio
async def test_ciphertext_bytes_never_contain_plaintext():
    """The plan's bar is explicit: assert on the RAW bytes, not just 'the API doesn't return
    it'. A distinctive, unlikely-to-collide-by-accident plaintext makes this a meaningful
    assertion rather than a coincidence."""
    provider = _provider()
    plaintext = "Bearer sk-CANARY-VALUE-9f3a7c21e88b4d5fa001"
    ref = await provider.store("ignored", plaintext)

    # The reference string itself (what would be written to the DB column).
    assert plaintext not in ref
    assert plaintext.encode() not in ref.encode()

    # Also decode the base64 payload and check the raw decrypted-adjacent bytes (nonce +
    # ciphertext + tag) don't contain the plaintext either, in case of an encoding coincidence.
    raw = base64.b64decode(ref[len(PREFIX):])
    assert plaintext.encode("utf-8") not in raw


@pytest.mark.asyncio
async def test_wrong_key_fails_cleanly_not_garbage():
    provider_a = _provider()
    ref = await provider_a.store("ignored", "Bearer sk-abc123")

    provider_b = _provider()  # different random key
    with pytest.raises(SecretResolutionError) as exc_info:
        await provider_b.resolve(ref)
    assert "decryption failed" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_corrupted_ciphertext_fails_cleanly():
    provider = _provider()
    ref = await provider.store("ignored", "Bearer sk-abc123")
    # Flip a character in the base64 payload to corrupt the GCM tag/ciphertext.
    tail = ref[len(PREFIX):]
    corrupted_tail = ("A" if tail[-1] != "A" else "B") + tail[1:]
    corrupted_ref = PREFIX + corrupted_tail
    with pytest.raises(SecretResolutionError):
        await provider.resolve(corrupted_ref)


@pytest.mark.asyncio
async def test_non_enc_prefixed_ref_is_rejected():
    provider = _provider()
    with pytest.raises(SecretResolutionError):
        await provider.resolve("just a literal, not ciphertext")


def test_missing_key_fails_at_construction_not_first_use(monkeypatch):
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    with pytest.raises(EncryptedProviderConfigError):
        build_key_source()


def test_key_from_env_var_hex(monkeypatch):
    key_hex = _hex_key()
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    source = build_key_source()
    assert source.get_key() == bytes.fromhex(key_hex)


def test_key_from_env_var_base64(monkeypatch):
    raw_key = os.urandom(32)
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY", base64.b64encode(raw_key).decode())
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY_FILE", raising=False)
    source = build_key_source()
    assert source.get_key() == raw_key


def test_key_from_file(monkeypatch, tmp_path):
    key_hex = _hex_key()
    key_file = tmp_path / "secret.key"
    key_file.write_text(key_hex)
    monkeypatch.delenv("ACROPOLIS_SECRET_KEY", raising=False)
    monkeypatch.setenv("ACROPOLIS_SECRET_KEY_FILE", str(key_file))
    source = build_key_source()
    assert source.get_key() == bytes.fromhex(key_hex)


def test_malformed_key_material_rejected():
    with pytest.raises(EncryptedProviderConfigError):
        _parse_key_material("not-hex-or-base64!!!")


def test_wrong_length_key_rejected():
    # Valid base64, but decodes to the wrong number of bytes.
    short_key_b64 = base64.b64encode(os.urandom(16)).decode()
    with pytest.raises(EncryptedProviderConfigError):
        _parse_key_material(short_key_b64)


@pytest.mark.asyncio
async def test_two_encryptions_of_same_plaintext_produce_different_ciphertext():
    """Nonces must be random per-encryption — a fixed/reused nonce with AES-GCM is catastrophic
    (it breaks confidentiality AND integrity). This is a coarse but real check that store()
    isn't reusing a nonce."""
    provider = _provider()
    ref1 = await provider.store("ignored", "same plaintext")
    ref2 = await provider.store("ignored", "same plaintext")
    assert ref1 != ref2


@pytest.mark.asyncio
async def test_delete_is_a_noop():
    provider = _provider()
    await provider.delete("enc:v1:whatever")
