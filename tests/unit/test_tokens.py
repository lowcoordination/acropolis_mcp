"""Unit tests for argus/tokens.py — the JWT issuer (issue #134, Task 1).

Verification bar per the issue contract: claim shape (iss/aud/exp/kid), TTL math, refresh-at-80%
with no blocking after the first mint, jwks() exposes ONLY public key material, kid is stable
across restarts, and from_settings fails loud on an unresolvable ref — while never leaking the
PEM literal (the local-tier case where the ref IS the private key).

These tests deliberately do NOT verify with a third-party JWT library — the verifier half of
this contract is the Go middleware, pinned to this implementation via the shared conformance
vectors. The signature checks below use cryptography's primitives directly (the same stdlib
shape the Go side uses), proving the tokens are real RS256 JWTs without adding a dependency.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import argus.tokens as tokens
from argus.tokens import (
    CLOCK_LEEWAY_SECONDS,
    REFRESH_FRACTION,
    TOKEN_TTL_SECONDS,
    TokenIssuer,
    TokenIssuerConfigError,
)
from archon.secrets import SecretResolutionError
from archon.secrets.local import LocalSecretProvider
from archon.settings import Settings


def _generate_rsa_key(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    return private_key, pem


def _decode_token(token: str) -> tuple[dict, dict, str, str]:
    """Split a compact JWS into (header, payload, signing_input, signature_b64)."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}"
    header = json.loads(tokens._b64url_decode(header_b64))
    payload = json.loads(tokens._b64url_decode(payload_b64))
    return header, payload, signing_input, signature_b64


class _FakeClock:
    """Deterministic stand-in for time.monotonic + time.time, patched into the module under
    test. Advancing both together mirrors real time: minted tokens change exp, cache windows
    shift — without any real sleeping or wall-clock races."""

    def __init__(self, monotonic: float = 100.0, epoch: float = 1_000_000.0):
        self._monotonic = monotonic
        self._epoch = epoch

    def monotonic(self) -> float:
        return self._monotonic

    def time(self) -> float:
        return self._epoch

    def advance(self, seconds: float) -> None:
        self._monotonic += seconds
        self._epoch += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = _FakeClock()
    monkeypatch.setattr(tokens, "_monotonic", fake.monotonic)
    monkeypatch.setattr(tokens, "_epoch_seconds", fake.time)
    return fake


def test_constants_are_the_cross_repo_contract():
    """These numbers are shared with the Go middleware via conformance vectors — a local change
    here is a cross-repo contract change, so pin them explicitly."""
    assert TOKEN_TTL_SECONDS == 600
    assert REFRESH_FRACTION == 0.8
    assert CLOCK_LEEWAY_SECONDS == 30


async def test_mint_claim_shape(clock):
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key)
    token = await issuer.get_token("mcp-fetch")
    header, payload, _, _ = _decode_token(token)

    assert header == {"alg": "RS256", "typ": "JWT", "kid": issuer.kid}
    assert payload == {
        "iss": "acropolis",
        "aud": "mcp-fetch",
        "exp": int(clock.time()) + TOKEN_TTL_SECONDS,
    }
    # A kid must exist and be non-empty (the middleware looks tokens up by it).
    assert issuer.kid


async def test_exp_uses_configured_ttl(clock):
    """TTL math: exp = now + the configured ttl, not a hardcoded 600 in the claim."""
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key, ttl_seconds=120)
    _, payload, _, _ = _decode_token(await issuer.get_token("slug"))
    assert payload["exp"] == int(clock.time()) + 120


def test_jwks_exposes_public_only():
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key)
    doc = issuer.jwks()

    assert set(doc) == {"keys"}
    assert len(doc["keys"]) == 1
    jwk = doc["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == issuer.kid
    # Public-only: no private RSA component may be serialized into the JWKS.
    assert not any(k in jwk for k in ("d", "p", "q", "dp", "dq", "qi"))

    # n/e round-trip back to the key's actual public numbers (RFC 7518 base64url).
    numbers = private_key.public_key().public_numbers()
    assert tokens._b64url_decode(jwk["n"]) == tokens._int_to_bytes(numbers.n)
    assert tokens._b64url_decode(jwk["e"]) == tokens._int_to_bytes(numbers.e)
    assert numbers.e == 65537


def test_kid_is_stable_across_reconstruction():
    """The kid must be re-derivable from reloaded key material (a restart reloads the same
    secret-provider reference) — not random per process."""
    private_key, pem = _generate_rsa_key()
    issuer1 = TokenIssuer(private_key)
    reloaded = serialization.load_pem_private_key(pem.encode(), password=None)
    issuer2 = TokenIssuer(reloaded)
    assert issuer1.kid == issuer2.kid
    assert issuer1.kid == tokens._derive_kid(private_key.public_key())


async def test_token_is_a_real_rs256_signature(clock):
    """Prove the minted token verifies under the public key and fails when tampered — the same
    RSASSA-PKCS1-v1_5 + SHA-256 shape the Go middleware checks."""
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key)
    token = await issuer.get_token("mcp-shell")
    _, _, signing_input, signature_b64 = _decode_token(token)
    signature = tokens._b64url_decode(signature_b64)

    private_key.public_key().verify(
        signature, signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(
            signature,
            (signing_input + "x").encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


async def test_get_token_reuses_cache_within_ttl(clock):
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key)
    first = await issuer.get_token("slug")
    second = await issuer.get_token("slug")
    assert first == second  # same cache entry — no re-mint


async def test_background_refresh_without_blocking(clock):
    """At 80% of TTL the cached token is still returned (never blocks) while a background task
    re-mints; once that task runs, the cache holds a fresh token."""
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key, ttl_seconds=100, refresh_fraction=0.8)
    first = await issuer.get_token("slug")

    # Into the refresh window: still the cached token, no synchronous mint.
    clock.advance(85)
    still_cached = await issuer.get_token("slug")
    assert still_cached == first

    # Let the scheduled background task run; the cache is now the freshly minted token.
    await asyncio.sleep(0.01)
    refreshed = await issuer.get_token("slug")
    assert refreshed != first

    # And the fresh token is reused without another re-mint.
    again = await issuer.get_token("slug")
    assert again == refreshed


async def test_expired_token_remints_synchronously(clock):
    """If the background refresh was starved and the token actually expired, there is no valid
    token to hand out — the next request mints synchronously rather than returning a dead one."""
    private_key, _ = _generate_rsa_key()
    issuer = TokenIssuer(private_key, ttl_seconds=100, refresh_fraction=0.8)
    first = await issuer.get_token("slug")

    clock.advance(101)  # past the full TTL
    second = await issuer.get_token("slug")
    assert second != first
    _, payload, _, _ = _decode_token(second)
    assert payload["exp"] == int(clock.time()) + 100


async def test_from_settings_returns_none_when_unset():
    assert await TokenIssuer.from_settings(Settings(), LocalSecretProvider()) is None


async def test_from_settings_resolves_pem_literal_via_local():
    private_key, pem = _generate_rsa_key()
    issuer = await TokenIssuer.from_settings(
        Settings(token_signing_key_ref=pem), LocalSecretProvider()
    )
    assert issuer is not None
    assert issuer.kid == tokens._derive_kid(private_key.public_key())
    header, payload, _, _ = _decode_token(await issuer.get_token("slug"))
    assert header["kid"] == issuer.kid
    assert payload["iss"] == "acropolis"


async def test_from_settings_resolves_reference_via_provider():
    private_key, pem = _generate_rsa_key()

    class _PemReturningProvider:
        async def resolve(self, ref):
            assert ref == "vault://acropolis/token-signing#key"
            return pem

        async def store(self, ref, value):
            raise NotImplementedError

        async def delete(self, ref):
            raise NotImplementedError

    issuer = await TokenIssuer.from_settings(
        Settings(token_signing_key_ref="vault://acropolis/token-signing#key"),
        _PemReturningProvider(),
    )
    assert issuer is not None
    assert issuer.kid == tokens._derive_kid(private_key.public_key())


async def test_from_settings_raises_on_unresolvable_ref():
    class _FailingProvider:
        async def resolve(self, ref):
            raise SecretResolutionError(ref, "Vault returned HTTP 403")

        async def store(self, ref, value):
            raise NotImplementedError

        async def delete(self, ref):
            raise NotImplementedError

    with pytest.raises(TokenIssuerConfigError) as exc_info:
        await TokenIssuer.from_settings(
            Settings(token_signing_key_ref="vault://acropolis/token-signing#key"),
            _FailingProvider(),
        )
    message = str(exc_info.value)
    # The reference is safe to echo; the reason is preserved for debugging.
    assert "vault://acropolis/token-signing#key" in message
    assert "Vault returned HTTP 403" in message


async def test_from_settings_raises_on_non_pem():
    with pytest.raises(TokenIssuerConfigError, match="PEM"):
        await TokenIssuer.from_settings(
            Settings(token_signing_key_ref="this is not a key"),
            LocalSecretProvider(),
        )


async def test_from_settings_raises_on_non_rsa_key():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    with pytest.raises(TokenIssuerConfigError, match="non-RSA"):
        await TokenIssuer.from_settings(
            Settings(token_signing_key_ref=ec_pem), LocalSecretProvider()
        )


async def test_error_message_never_leaks_pem_literal():
    """The local-tier shape is a PEM literal, where the ref IS the private key. A failure path
    must not echo it into logs/errors — use SecretResolutionError.reason, not str(exc)."""
    _, pem = _generate_rsa_key()

    class _LeakyRefProvider:
        async def resolve(self, ref):
            raise SecretResolutionError(ref, "decryption failed")

        async def store(self, ref, value):
            raise NotImplementedError

        async def delete(self, ref):
            raise NotImplementedError

    with pytest.raises(TokenIssuerConfigError) as exc_info:
        await TokenIssuer.from_settings(
            Settings(token_signing_key_ref=pem), _LeakyRefProvider()
        )
    message = str(exc_info.value)
    assert pem not in message
    assert "decryption failed" in message
    assert "<PEM literal>" in message
