"""The `encrypted` SecretProvider — AES-256-GCM envelope encryption.

> Threat model — read this before trusting this tier for anything
>
> This defends **backup and snapshot leakage**: a stolen `gateway.db` file, a leaked
> `sqlite3 .backup` copy, a volume snapshot that ends up somewhere it shouldn't. Without the key
> (which is never itself stored in the database), the ciphertext in `upstream_auth_header` is
> useless.
>
> This does **NOT** defend a live host compromise. If an attacker has code execution on the
> running Acropolis process, or read access to wherever `ACROPOLIS_SECRET_KEY` /
> `ACROPOLIS_SECRET_KEY_FILE` is configured (an env var, a mounted file, a compose/k8s secret),
> they can decrypt everything the application can decrypt — same as the application itself does
> on every call. That is not a bug or a gap to be closed later; it is what "the app needs the
> plaintext to authenticate outbound calls" necessarily means. A key file sitting in the same
> volume as `gateway.db` provides ZERO real protection — it defeats the entire point of this
> tier and is explicitly called out as an anti-pattern in docs/secrets.md. Overclaiming what this
> tier buys you is worse than not building it: state the boundary plainly, here and in the docs,
> rather than let "encrypted" imply more than AES-GCM-with-an-external-key actually provides.

Format: `enc:v1:<base64(nonce || ciphertext || tag)>`. The `v1` version tag means the format can
evolve later (a new KDF, a new AEAD, a wrapped-DEK/KMS scheme) without breaking already-encrypted
data — a future v2 provider can still decrypt v1 ciphertext by dispatching on the prefix.

Key sourcing (first match wins, checked at provider construction):
1. `ACROPOLIS_SECRET_KEY` — a 32-byte key, given as 64 hex chars or standard base64.
2. `ACROPOLIS_SECRET_KEY_FILE` — a path to a file containing the same.
3. Neither set: the provider fails to construct (see EncryptedProviderConfigError) rather than
   silently falling back to no encryption or a fixed/derived key baked into the binary — a
   missing key is a configuration error, not a default to paper over.

A real external KMS (calling out to AWS KMS / GCP KMS / age / etc. to unwrap a per-install data
key rather than reading it directly from an env var) is a documented future extension point —
`KeySource` below is the seam a KMS-backed implementation would plug into — but is explicitly
NOT required to be fully built for this item; see docs/secrets.md.
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
from pathlib import Path
from typing import Optional, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import SecretResolutionError

logger = logging.getLogger("archon.secrets.encrypted")

PREFIX = "enc:v1:"
_KEY_LENGTH_BYTES = 32  # AES-256
_NONCE_LENGTH_BYTES = 12  # standard GCM nonce size


class EncryptedProviderConfigError(Exception):
    """Raised at provider construction time when no usable key material is configured. Never
    raised mid-request — resolve()/store() failures after successful construction are
    SecretResolutionError, per the SecretProvider contract."""


class KeySource(Protocol):
    """Seam for a future KMS-backed key source. `get_key()` returns the raw 32-byte data key.
    EnvKeySource and FileKeySource below are the two built-in implementations; a KMS source
    would implement the same interface (e.g. unwrap a wrapped DEK via a KMS Decrypt call) and
    slot in without any change to EncryptedSecretProvider itself."""

    def get_key(self) -> bytes: ...


def _parse_key_material(raw: str) -> bytes:
    raw = raw.strip()
    # Try hex first (64 chars for 32 bytes) since it's unambiguous when it matches; fall back to
    # base64, which is the more compact/typical way to hand a binary key around as text.
    if len(raw) == _KEY_LENGTH_BYTES * 2:
        try:
            key = bytes.fromhex(raw)
            if len(key) == _KEY_LENGTH_BYTES:
                return key
        except ValueError:
            pass
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as e:
        raise EncryptedProviderConfigError(
            "key material is neither 64 hex chars nor valid base64 for a 32-byte AES-256 key"
        ) from e
    if len(key) != _KEY_LENGTH_BYTES:
        raise EncryptedProviderConfigError(
            f"key material decoded to {len(key)} bytes; AES-256-GCM requires exactly "
            f"{_KEY_LENGTH_BYTES}"
        )
    return key


class EnvKeySource:
    def __init__(self, env_var: str = "ACROPOLIS_SECRET_KEY"):
        raw = os.environ.get(env_var)
        if not raw:
            raise EncryptedProviderConfigError(f"{env_var} is not set")
        self._key = _parse_key_material(raw)

    def get_key(self) -> bytes:
        return self._key


class FileKeySource:
    def __init__(self, path: str):
        try:
            raw = Path(path).read_text()
        except OSError as e:
            raise EncryptedProviderConfigError(f"could not read key file {path!r}: {e}") from e
        self._key = _parse_key_material(raw)

    def get_key(self) -> bytes:
        return self._key


def build_key_source() -> KeySource:
    """Resolve a KeySource from the environment, per the module docstring's precedence order."""
    if os.environ.get("ACROPOLIS_SECRET_KEY"):
        logger.info("Initializing EncryptedSecretProvider from ACROPOLIS_SECRET_KEY environment variable")
        return EnvKeySource()
    key_file = os.environ.get("ACROPOLIS_SECRET_KEY_FILE")
    if key_file:
        logger.info("Initializing EncryptedSecretProvider from key file: %s", key_file)
        return FileKeySource(key_file)
    raise EncryptedProviderConfigError(
        "encrypted secret provider selected but neither ACROPOLIS_SECRET_KEY nor "
        "ACROPOLIS_SECRET_KEY_FILE is set — a key is required, there is no default"
    )


class EncryptedSecretProvider:
    def __init__(self, key_source: Optional[KeySource] = None):
        self._key_source = key_source or build_key_source()
        # Fail fast at construction, not on the first resolve() — a misconfigured key should
        # surface at app startup (or at test-fixture construction), not as a mysterious 500 on
        # the first real tool call.
        key = self._key_source.get_key()
        if len(key) != _KEY_LENGTH_BYTES:
            raise EncryptedProviderConfigError(
                f"key must be exactly {_KEY_LENGTH_BYTES} bytes, got {len(key)}"
            )
        self._aesgcm = AESGCM(key)

    async def resolve(self, ref: str) -> str:
        if not ref.startswith(PREFIX):
            # Not our format at all — a caller handed us something that was never encrypted by
            # this provider. Fail closed rather than guess.
            raise SecretResolutionError(ref, "not an enc:v1: ciphertext")
        raw = ref[len(PREFIX):]
        try:
            blob = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as e:
            raise SecretResolutionError(ref, f"ciphertext is not valid base64: {e}") from e
        if len(blob) < _NONCE_LENGTH_BYTES:
            raise SecretResolutionError(ref, "ciphertext too short to contain a nonce")
        nonce, ciphertext = blob[:_NONCE_LENGTH_BYTES], blob[_NONCE_LENGTH_BYTES:]
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            # Wrong key or corrupted/tampered ciphertext — GCM's authentication tag check failed.
            # This must NEVER return a garbage/partial plaintext; decrypt() either returns the
            # exact original bytes or raises. Deliberately does not distinguish "wrong key" from
            # "corrupted data" in the message — that distinction isn't recoverable from the
            # ciphertext alone, and speculating in either direction would just be guessing.
            raise SecretResolutionError(
                ref, "decryption failed (wrong key or corrupted ciphertext)"
            ) from e
        return plaintext.decode("utf-8")

    async def store(self, ref: str, value: str) -> str:
        nonce = os.urandom(_NONCE_LENGTH_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        blob = nonce + ciphertext
        return PREFIX + base64.b64encode(blob).decode("ascii")

    async def delete(self, ref: str) -> None:
        return None
