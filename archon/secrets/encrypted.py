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

Key sourcing (checked at provider construction):

1. `ACROPOLIS_SECRET_KEYS` — a key RING: comma-separated key materials, each 32 bytes given
   as 64 hex chars or standard base64. The FIRST key is the ACTIVE key (used for all new
   encryptions); the remaining keys are decryption-only. This is the rotation form.
2. `ACROPOLIS_SECRET_KEYS_FILE` — a file containing the same ring, one key material per line
   (blank lines ignored); the first non-blank line is the ACTIVE key.
3. `ACROPOLIS_SECRET_KEY` / `ACROPOLIS_SECRET_KEY_FILE` — the original SINGULAR forms,
   unchanged: equivalent to a one-key ring (that key is active AND the only decryption key).
   A key ring of length one is exactly the pre-rotation behaviour.
4. Setting BOTH a plural and a singular form is a configuration error (ambiguous intent —
   there is no sensible precedence between "the ring" and "the single key"), raised at
   construction like any other key-material error.
5. None of the above set: the provider fails to construct (see EncryptedProviderConfigError)
   rather than silently falling back to no encryption or a fixed/derived key baked into the
   binary — a missing key is a configuration error, not a default to paper over.

Rotation is the ring's only reason to exist: deploy the new key FIRST in the ring (old keys
behind it) → run the `reencrypt` CLI command to rewrite every stored credential under the new
active key → deploy with only the new key. Until re-encryption, every key in the ring remains
fully live — the ring does not shrink a key's power, it just allows ciphertext written under
older keys to keep resolving while rotation is in flight. See docs/secrets.md's rotation
runbook.

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
        # Deliberate Settings bypass: the encrypted provider bootstraps the mechanism that
        # decrypts settings, so reading the key via Settings would be a circular dependency.
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
    # Deliberate Settings bypass (both reads): the encrypted provider bootstraps the mechanism
    # that decrypts settings, so it cannot depend on fully-resolved Settings without a circular
    # dependency — the key must come straight from the environment.
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


class KeyRing:
    """An ordered set of 32-byte keys with exactly one ACTIVE key (the first) for writes.

    `keys[0]` is the active key: `store()` always encrypts under it. `resolve()` tries the
    active key first, then each remaining key in order, and only fails when ALL of them fail —
    which is what lets ciphertext written under a pre-rotation key keep resolving while the
    new key is already active for new writes (the rotation window).

    The ring deliberately does not change the threat model of this tier: every key in the ring
    is exactly as powerful as every other (all of them decrypt everything), and keys stay
    fully live until the operator REMOVES them from the ring after re-encrypting. Rotation is
    "deploy new active → re-encrypt → drop old", not "add a key and forget it".
    """

    def __init__(self, keys: list[bytes]):
        if not keys:
            raise EncryptedProviderConfigError("key ring is empty — at least one key is required")
        for key in keys:
            if len(key) != _KEY_LENGTH_BYTES:
                raise EncryptedProviderConfigError(
                    f"key ring contains a key of {len(key)} bytes; AES-256-GCM requires exactly "
                    f"{_KEY_LENGTH_BYTES}"
                )
        self._keys = list(keys)

    @property
    def active(self) -> bytes:
        """The key new ciphertext is written under (always the FIRST key in the ring)."""
        return self._keys[0]

    @property
    def candidates(self) -> list[bytes]:
        """All decryption keys, active first — resolve() iterates these in order."""
        return list(self._keys)

    def __len__(self) -> int:
        return len(self._keys)


class EnvKeyRingSource:
    """`ACROPOLIS_SECRET_KEYS`: comma-separated key materials. Safe to split on commas because
    neither hex nor standard base64 contains one. First entry = ACTIVE."""

    def __init__(self, env_var: str = "ACROPOLIS_SECRET_KEYS"):
        raw = os.environ.get(env_var)
        if not raw:
            raise EncryptedProviderConfigError(f"{env_var} is not set")
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            raise EncryptedProviderConfigError(f"{env_var} is set but contains no key material")
        self._keys = [_parse_key_material(p) for p in parts]

    def keys(self) -> list[bytes]:
        return self._keys


class FileKeyRingSource:
    """`ACROPOLIS_SECRET_KEYS_FILE`: one key material per line, blank lines ignored. First
    non-blank line = ACTIVE."""

    def __init__(self, path: str):
        try:
            text = Path(path).read_text()
        except OSError as e:
            raise EncryptedProviderConfigError(f"could not read key file {path!r}: {e}") from e
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            raise EncryptedProviderConfigError(f"key file {path!r} contains no key material")
        self._keys = [_parse_key_material(l) for l in lines]

    def keys(self) -> list[bytes]:
        return self._keys


def build_key_ring() -> KeyRing:
    """Resolve a key ring from the environment, per the module docstring's precedence:
    plural env → plural file → singular (as a one-key ring). Both plural AND singular set is
    an ambiguous-configuration error rather than a silently-chosen precedence."""
    plural_env = os.environ.get("ACROPOLIS_SECRET_KEYS")
    plural_file = os.environ.get("ACROPOLIS_SECRET_KEYS_FILE")
    singular_env = os.environ.get("ACROPOLIS_SECRET_KEY")
    singular_file = os.environ.get("ACROPOLIS_SECRET_KEY_FILE")

    if (plural_env or plural_file) and (singular_env or singular_file):
        raise EncryptedProviderConfigError(
            "both the plural (ACROPOLIS_SECRET_KEYS[_FILE]) and singular "
            "(ACROPOLIS_SECRET_KEY[_FILE]) key variables are set — use the plural form for a "
            "key ring, or the singular form for a single key, not both"
        )
    if plural_env:
        return KeyRing(EnvKeyRingSource().keys())
    if plural_file:
        return KeyRing(FileKeyRingSource(plural_file).keys())
    return KeyRing([build_key_source().get_key()])


class EncryptedSecretProvider:
    def __init__(self, key_source: Optional[KeySource] = None, key_ring: Optional[KeyRing] = None):
        """Accepts EITHER a key_ring (the rotation-aware form) OR a legacy single key_source
        (wrapped as a one-key ring for backwards compatibility), OR neither (resolve the ring
        from the environment via build_key_ring). Passing both is a programming error — the
        caller is telling us two different things about which key to write with."""
        if key_source is not None and key_ring is not None:
            raise ValueError("pass either key_source or key_ring, not both")
        if key_ring is not None:
            self._ring = key_ring
        elif key_source is not None:
            self._ring = KeyRing([key_source.get_key()])
        else:
            self._ring = build_key_ring()
        # Fail fast at construction, not on the first resolve() — a misconfigured key should
        # surface at app startup (or at test-fixture construction), not as a mysterious 500 on
        # the first real tool call. Construction validates the ACTIVE key's length (ring
        # construction validates every key, but keep the explicit check for the key_source path).
        key = self._ring.active
        if len(key) != _KEY_LENGTH_BYTES:
            raise EncryptedProviderConfigError(
                f"key must be exactly {_KEY_LENGTH_BYTES} bytes, got {len(key)}"
            )
        self._aesgcm = AESGCM(self._ring.active)
        self._aesgcms = [AESGCM(k) for k in self._ring.candidates]

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
        # Try the active key first, then each remaining ring key in order (the rotation
        # window: pre-rotation ciphertext resolves via an older key until re-encryption).
        # GCM's tag check makes each attempt safe — a wrong key simply fails the tag, it can
        # never return garbage — so trying more keys cannot weaken the fail-closed guarantee;
        # it only widens WHO counts as "having the key".
        for aesgcm in self._aesgcms:
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                return plaintext.decode("utf-8")
            except InvalidTag:
                continue
        # Every ring key failed — wrong keys or corrupted/tampered ciphertext (indistinguishable,
        # and deliberately kept indistinguishable for the same reason as before: the distinction
        # isn't recoverable from the ciphertext alone, and speculating is just guessing). The
        # message is UNCHANGED from the single-key era so log/alert greps keep working.
        raise SecretResolutionError(ref, "decryption failed (wrong key or corrupted ciphertext)")

    async def store(self, ref: str, value: str) -> str:
        nonce = os.urandom(_NONCE_LENGTH_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        blob = nonce + ciphertext
        return PREFIX + base64.b64encode(blob).decode("ascii")

    async def delete(self, ref: str) -> None:
        return None
