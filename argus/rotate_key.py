"""Signing-key rotation for the upstream-token issuer (issue #134, Task 4).

Two halves live here:

1. **``TokenKeyManager``** — what a RUNNING app uses to hold the live ``TokenIssuer`` and to
   pick up a rotation without a restart. It re-reads the persisted rotation state (the ``settings``
   table plus the env bootstrap) and rebuilds the issuer only when that state's fingerprint
   changes. The JWKS route (and, in Task 3, token injection) go through ``current()``.

2. **``rotate_signing_key``** — the operator-facing rotation sequence, wrapped by the
   ``argus rotate-signing-key`` CLI. It mirrors ``argus/reencrypt.py`` in shape: dry-run by
   default, ``--apply`` to execute, exit 0 only when the new key is live and signing.

Rotation semantics (spec §4, issue #135): JWKS carries ``kid``s; servers cache indefinitely and
refetch only on an unknown ``kid``. Rotation is therefore a sequence — generate new keypair →
publish BOTH kids → sign with the new key → drop the old kid after an overlap window of two
token TTLs (20 min). Old keys stay valid in server caches until a new-``kid`` token triggers a
refetch, so rotation is zero-downtime by construction.

Where rotation state lives: the active signing key reference boots from env
(``ACROPOLIS_TOKEN_SIGNING_KEY_REF``, validated by ``TokenIssuer.from_settings``). The rotation
CLI then persists DB settings-table keys that OVERRIDE/extend that bootstrap:

- ``token_signing_active_ref`` — the current active (signing) key reference; when present it wins
  over the env value. Written by the first rotation; the env value remains the bootstrap only.
- ``token_signing_previous_ref`` — the previously-active key reference, still published for the
  overlap window.
- ``token_signing_previous_drop_at`` — epoch seconds when the previous key may be dropped.

The DB is the source of truth for in-flight rotation state, which is what makes a rotation
survive a restart and propagate to a running app without a redeploy. The old key is dropped
lazily by the issuer itself (``TokenIssuer._drop_expired_previous``) once the deadline passes;
stale ``token_signing_previous_*`` rows are harmless and overwritten by the next rotation.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from archon.secrets import SecretResolutionError, SecretProvider, is_reference
from argus.tokens import (
    TOKEN_TTL_SECONDS,
    TokenIssuer,
    TokenIssuerConfigError,
    _b64url_decode,
    _derive_kid,
    _resolve_rsa_private_key,
)

# Overlap window: drop the old kid after two token TTLs (2 × 600s = 20 min). Pinned to the spec
# §4 sequence; changing this is a contract change, not a local tuning knob, because the rotation
# drill (Task 6) and the operator runbook both assume "two TTLs".
OVERLAP_TTLS = 2
OVERLAP_SECONDS = OVERLAP_TTLS * TOKEN_TTL_SECONDS

# DB settings-table keys (see module docstring). Kept distinct from the env field
# `token_signing_key_ref` so the bootstrap (env) and the post-rotation truth (DB) can't be
# confused by a reader of either namespace alone.
ACTIVE_REF_KEY = "token_signing_active_ref"
PREVIOUS_REF_KEY = "token_signing_previous_ref"
PREVIOUS_DROP_AT_KEY = "token_signing_previous_drop_at"


def _parse_drop_at(raw: str | None) -> float | None:
    """Coerce the persisted drop deadline to a float, or None when absent/unparseable. A None
    deadline means "no previous key to publish" — the issuer then never holds an overlap key."""
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _require_signing_capable_provider(provider: SecretProvider) -> None:
    """Fail loudly unless the provider can actually hold a signing key. The ``local`` tier's
    ``store()`` would return the PEM literal itself, which ``TokenIssuer.from_settings`` then
    refuses at boot — so refusing here (and in the dry run) is the honest early failure rather
    than writing key material into a position the boot path would reject anyway."""
    from archon.secrets.encrypted import EncryptedSecretProvider
    from archon.secrets.openbao import OpenBaoSecretProvider

    if isinstance(provider, (EncryptedSecretProvider, OpenBaoSecretProvider)):
        return
    raise TokenIssuerConfigError(
        "token signing keys require the 'encrypted' or 'openbao' secret provider; "
        f"got {type(provider).__name__}"
    )


async def _store_signing_key(
    provider: SecretProvider, current_ref: str, pem: str, now: float
) -> str:
    """Persist a freshly generated private key through the provider and return its reference.

    Tier-specific in the same spirit as ``archon.secrets.store_upstream_auth_header``:

    - ``encrypted``: ``store()`` ignores its target and returns an ``enc:v1:`` ciphertext.
    - ``openbao``: write the new key at the SAME KV path as the current reference but under a
      generation-specific key name (``key-<epoch>``), so the old key stays resolvable for the
      overlap window and the next rotation can repeat the same move.
    """
    _require_signing_capable_provider(provider)
    from archon.secrets.openbao import OpenBaoSecretProvider, parse_vault_ref

    if isinstance(provider, OpenBaoSecretProvider):
        vref = parse_vault_ref(current_ref)
        new_ref = f"vault://{vref.mount}/{vref.path}#key-{int(now)}"
        return await provider.store(new_ref, pem)
    return await provider.store("", pem)


class TokenKeyManager:
    """Owns the live ``TokenIssuer`` and re-loads it when the persisted rotation state changes.

    Constructed synchronously (no I/O); ``current()`` is the single entry point. It re-reads the
    rotation state and rebuilds the issuer only when that state's fingerprint changes, so a
    ``rotate-signing-key --apply`` run propagates to a RUNNING app without a restart — the same
    "rotation without redeploy" property the reencrypt CLI gives the encrypted tier.

    The first ``current()`` call is also the fail-loud-at-boot point: an unresolvable active key
    reference raises ``TokenIssuerConfigError`` from here, which the app lifespan lets abort
    startup exactly like a misconfigured secret provider.
    """

    def __init__(self, settings, secret_provider: SecretProvider, settings_repo) -> None:
        self._settings = settings
        self._provider = secret_provider
        self._repo = settings_repo
        self._issuer: TokenIssuer | None = None
        self._fingerprint: tuple | None = None

    async def current(self) -> TokenIssuer | None:
        """Return the current issuer, rebuilding it only when rotation state changed. Returns
        None when no signing key is configured anywhere (env unset + no DB override)."""
        fingerprint = await self._read_state()
        if fingerprint != self._fingerprint:
            self._issuer = await self._load(fingerprint)
            self._fingerprint = fingerprint
        return self._issuer

    async def reload(self) -> TokenIssuer | None:
        """Force the next ``current()`` to re-read and rebuild (used by tests and any future
        operator-facing "reload keys" affordance)."""
        self._fingerprint = None
        return await self.current()

    async def _read_state(self) -> tuple[str | None, str | None, str | None]:
        active = await self._repo.get(ACTIVE_REF_KEY) or getattr(
            self._settings, "token_signing_key_ref", None
        )
        previous = await self._repo.get(PREVIOUS_REF_KEY)
        drop_at = await self._repo.get(PREVIOUS_DROP_AT_KEY)
        return (active, previous, drop_at)

    async def _load(self, state: tuple) -> TokenIssuer | None:
        active_ref, previous_ref, drop_at_raw = state
        if not active_ref:
            return None
        if not is_reference(active_ref):
            raise TokenIssuerConfigError(
                "token signing key must be a secret-provider reference (enc:v1:... or "
                "vault://...), not inline key material"
            )
        active_key = await _resolve_rsa_private_key(active_ref, self._provider)
        previous: list[tuple[object, float]] = []
        if previous_ref:
            if not is_reference(previous_ref):
                raise TokenIssuerConfigError(
                    "persisted previous token signing key is not a secret-provider reference"
                )
            drop_at = _parse_drop_at(drop_at_raw)
            if drop_at is not None:
                # The issuer drops the key lazily once the deadline passes (its own
                # _drop_expired_previous), so a deadline already in the past is harmless here —
                # the key is loaded and immediately eligible for drop on the next JWKS/mint.
                previous_key = await _resolve_rsa_private_key(previous_ref, self._provider)
                previous.append((previous_key, drop_at))
        return TokenIssuer(active_key, previous=tuple(previous))


@dataclass
class RotateResult:
    """Outcome of a rotation attempt. ``verified`` is only True on a successful apply whose
    persisted new key was re-loaded and observed signing; ``error`` carries the failure reason."""

    previous_ref: str | None = None
    new_ref: str | None = None
    previous_kid: str | None = None
    new_kid: str | None = None
    overlap_seconds: float = OVERLAP_SECONDS
    dry_run: bool = False
    verified: bool = False
    error: str | None = None


async def rotate_signing_key(
    settings,
    secret_provider: SecretProvider,
    settings_repo,
    *,
    dry_run: bool = False,
    now: float | None = None,
) -> RotateResult:
    """Run the rotation sequence: generate a new keypair, publish BOTH kids (the old key becomes
    the overlap key), and sign with the new key — persisting the state to the ``settings`` table
    unless ``dry_run``.

    ``now`` is injectable for tests (the overlap deadline is ``now + OVERLAP_SECONDS``); it
    defaults to the real wall clock, the same clock domain the issuer's drop check uses.

    Returns a ``RotateResult``; on ``dry_run=False`` the result's ``verified`` is True only after
    the persisted new key reference is re-resolved and observed minting a token whose ``kid``
    matches — i.e. only when the new key is genuinely live and signing.
    """
    now = time.time() if now is None else now

    active_ref = await settings_repo.get(ACTIVE_REF_KEY) or getattr(
        settings, "token_signing_key_ref", None
    )
    if not active_ref:
        return RotateResult(
            dry_run=dry_run,
            error=(
                "no token signing key configured — set ACROPOLIS_TOKEN_SIGNING_KEY_REF (a "
                "enc:v1:... or vault://... reference) before rotating"
            ),
        )
    if not is_reference(active_ref):
        return RotateResult(
            dry_run=dry_run,
            error="token signing key must be a secret-provider reference (enc:v1:... or vault://...), not inline material",
        )

    try:
        current_key = await _resolve_rsa_private_key(active_ref, secret_provider)
    except TokenIssuerConfigError as exc:
        return RotateResult(dry_run=dry_run, error=f"current signing key is unusable: {exc}")

    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_pem = new_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    result = RotateResult(
        previous_ref=active_ref,
        previous_kid=_derive_kid(current_key.public_key()),
        new_kid=_derive_kid(new_key.public_key()),
        overlap_seconds=OVERLAP_SECONDS,
        dry_run=dry_run,
    )

    if dry_run:
        # Preview only: validate the provider CAN hold a signing key (fail early on 'local') but
        # persist NOTHING — no DB write and no provider store. openbao's store() is a real
        # external write and must never happen on a dry run; encrypted's store() would burn a
        # throwaway ciphertext for no reason.
        try:
            _require_signing_capable_provider(secret_provider)
        except TokenIssuerConfigError as exc:
            return RotateResult(dry_run=True, error=str(exc))
        return result

    try:
        new_ref = await _store_signing_key(secret_provider, active_ref, new_pem, now)
    except TokenIssuerConfigError as exc:
        return RotateResult(dry_run=dry_run, error=str(exc))
    except SecretResolutionError as exc:
        return RotateResult(
            dry_run=dry_run, error=f"could not store the new signing key: {exc.reason}"
        )
    result.new_ref = new_ref

    drop_at = now + OVERLAP_SECONDS
    await settings_repo.set(ACTIVE_REF_KEY, new_ref)
    await settings_repo.set(PREVIOUS_REF_KEY, active_ref)
    await settings_repo.set(PREVIOUS_DROP_AT_KEY, str(int(drop_at)))

    # "Exit 0 only when the new key is live and signing": re-resolve the PERSISTED reference (not
    # the in-memory key object) and mint a token; its header kid must match the new key. Any
    # failure here means the apply did not actually make the new key live, so report and let the
    # caller exit non-zero.
    try:
        reloaded_key = await _resolve_rsa_private_key(new_ref, secret_provider)
        reloaded = TokenIssuer(reloaded_key)
        token = await reloaded.get_token("__rotation_check__")
        header = json.loads(_b64url_decode(token.split(".")[0]))
        if header.get("kid") != result.new_kid:
            return RotateResult(
                **{
                    **result.__dict__,
                    "error": "post-rotate verification failed: minted kid does not match the new key",
                }
            )
        result.verified = True
    except TokenIssuerConfigError as exc:
        return RotateResult(
            **{**result.__dict__, "error": f"post-rotate verification failed: {exc}"}
        )
    return result
