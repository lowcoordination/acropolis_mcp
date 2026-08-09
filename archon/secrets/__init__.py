"""Pluggable secret backends (enterprise #5).

`servers.upstream_auth_header` has always been a plain TEXT column. Before this package it held
a literal Authorization header value; now it can ALSO hold a reference — `vault://path#key` —
that a `SecretProvider` resolves to the literal value at call time. This is deliberately NOT a
column-type change: the column stays TEXT, a literal is still exactly what F23 always stored, and
`parse_ref()` below is what decides whether a given string is a reference or a literal. No
migration of existing data is needed or performed — see db/migrations/ (no new migration in this
package) and _decrypted.py's / local.py's docstrings for why that's safe.

Three implementations, selected by the `secret_provider` setting ("local" | "encrypted" |
"openbao", default "local"):

- `local.py`  — pass-through. Byte-identical to pre-feature behaviour; this is the regression
  guard for the whole item (see tests/unit/test_secrets_local.py).
- `encrypted.py` — AES-GCM envelope encryption, key from an env var or file. Defends backup/
  snapshot leakage, NOT a live host compromise — see docs/secrets.md for the full threat model.
- `openbao.py` — a generic HashiCorp Vault KV v2 HTTP API client. Works against real Vault,
  OpenBao, or anything else speaking the same wire protocol; it is named "openbao" only because
  that's this codebase's terminology for "the external secret manager", not because it has any
  OpenBao-specific behaviour. See that module's docstring for the scope boundary.

Resolution happens at CALL TIME (Pipeline._forward, stoa.health.probe_server, the tools/list
path), never at startup and never on list/get control-plane responses — see
archon/schemas.py's ServerResponse, which still only ever exposes has_upstream_auth_header.
"""
from __future__ import annotations

import time
from typing import Optional, Protocol


class SecretResolutionError(Exception):
    """Raised when a SecretProvider cannot resolve a reference to its plaintext value.

    Callers on the read paths (Pipeline._forward, stoa.health.probe_server, ToolsCache) MUST
    treat this as a hard failure — an ERROR decision / unhealthy status — and must NEVER fall
    back to forwarding the call without a credential. See docs/secrets.md 'Failure model'.
    """

    def __init__(self, ref: str, reason: str):
        # `ref` here is intentionally the ORIGINAL reference string (e.g. "vault://path#key"),
        # never the resolved plaintext — this exception's message can end up in logs / audit
        # rows / HTTP error bodies on the failure paths that construct ERROR responses, so it
        # must be safe to surface by construction, not by caller discipline.
        self.ref = ref
        self.reason = reason
        super().__init__(f"failed to resolve secret {ref!r}: {reason}")


class SecretProvider(Protocol):
    """A backend that turns a reference string into (or out of) a plaintext secret value.

    `ref` is either a literal value (the `local` provider's entire job is to hand it back
    unchanged) or a provider-specific reference string such as `vault://path#key` or
    `enc:v1:<base64>`. Implementations must never log the resolved plaintext.
    """

    async def resolve(self, ref: str) -> str:
        """Return the plaintext value for `ref`. Raises SecretResolutionError on failure —
        never returns a partial/garbage value and never raises a different exception type from
        this seam, so every call site can catch exactly one thing."""
        ...

    async def store(self, ref: str, value: str) -> str:
        """Persist `value` and return the reference string that should be written to the
        `servers.upstream_auth_header` column in its place. For `local` this is the identity
        function. For `encrypted` this returns the versioned ciphertext. For `openbao` this
        writes to the KV store and returns the `vault://` reference."""
        ...

    async def delete(self, ref: str) -> None:
        """Best-effort delete of whatever `store` created. A no-op for `local` and `encrypted`
        (there's nothing external to clean up); for `openbao` this deletes the KV entry."""
        ...


def is_reference(value: Optional[str]) -> bool:
    """True if `value` is a non-secret REFERENCE (safe to export/log/display) rather than a
    literal credential. Used by config export (a reference skips the PLAINTEXT warning) and by
    the frontend hint (F23's `has_upstream_auth_header` boolean doesn't change, but this is what
    lets the UI additionally say "externalized" vs "literal").

    Deliberately an allowlist of known reference prefixes, not a denylist/heuristic — a
    literal credential that happens to start with "vault://" is not a realistic false negative
    (no real Authorization header value takes that shape), and guessing via entropy or length
    would be exactly the kind of heuristic that gets a real credential wrong in one direction or
    the other.
    """
    if value is None:
        return False
    return value.startswith("vault://") or value.startswith("enc:v1:")


class _TTLCache:
    """A tiny per-provider TTL cache for resolved plaintext values.

    Shared by encrypted (cheap, but avoids re-deriving/re-decrypting on every single call) and
    openbao (where the TTL is the actual behavioural requirement — see the module docstring
    there on why resolution happens at call time with a short cache rather than at startup).
    Never persisted, never logged; lives only in process memory for the configured TTL.
    """

    def __init__(self, ttl_seconds: float):
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[float, str]] = {}

    def get(self, key: str) -> Optional[str]:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.monotonic() >= expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: str) -> None:
        self._store[key] = (time.monotonic() + self._ttl, value)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()


async def store_upstream_auth_header(
    provider: "SecretProvider", value: Optional[str]
) -> Optional[str]:
    """Shared helper for the WRITE paths (archon/api.py's create_server/update_server) that
    decides what actually gets persisted into `servers.upstream_auth_header` for a value an
    operator just typed into the server form.

    Deliberately tier-specific in a way that's documented here rather than left to be
    rediscovered per call site:

    - None (clearing the field, or never set) passes through unchanged.
    - Anything already reference-shaped (`is_reference()` — a `vault://` or `enc:v1:` string) is
      stored EXACTLY as typed, on every tier. Re-processing an already-a-reference value would
      be wrong on every tier: under `local` it's a no-op anyway; under `encrypted` it would
      double-encrypt an already-opaque string for no benefit; under `openbao` there is no
      "store this literal at this path" operation to perform because the operator ALREADY
      pointed at a specific Vault path themselves — writing something else there would be
      surprising and out of scope of what they asked for.
    - A LITERAL under `local` is stored as-is — byte-identical to pre-feature behaviour.
    - A LITERAL under `encrypted` is automatically encrypted at write time via provider.store()
      — this is what makes `encrypted` a genuine "flip a setting, existing/new literals become
      opaque ciphertext" tier rather than something operators have to manually pre-encrypt.
    - A LITERAL typed while `openbao` is selected is stored as-is (a literal), NOT written into
      Vault on the operator's behalf — this codebase has no way to infer what KV path/key the
      operator would want that credential to live at, and guessing one would be a surprising,
      undocumented side effect. An operator using the `openbao` tier is expected to write the
      secret into Vault themselves (`vault kv put` / `bao kv put`, or their own tooling) and
      paste the resulting `vault://...` reference into the form — this is a documented
      operational step, not a gap; see docs/secrets.md.
    """
    if value is None or is_reference(value):
        return value
    from .encrypted import EncryptedSecretProvider

    if isinstance(provider, EncryptedSecretProvider):
        return await provider.store("", value)
    return value


async def resolve_upstream_auth_header(
    provider: "SecretProvider", upstream_auth_header: Optional[str]
) -> Optional[str]:
    """Shared helper for every READ path that needs the actual plaintext credential
    (Pipeline._forward, stoa.health.probe_server, ToolsCache, the initialize-handshake path) —
    resolves `server.upstream_auth_header` through the configured provider, or returns None
    unchanged if no credential is configured at all (nothing to resolve).

    Deliberately centralised here rather than reimplemented at each call site: every one of
    those call sites must react to SecretResolutionError the same way (never forward/probe
    without the credential), and a single helper is what keeps that invariant from drifting as
    new call sites are added. Callers still choose HOW to react to the exception (an ERROR
    audit decision in the pipeline, an 'unhealthy' status in the health poller) — this helper
    only does the resolution step and lets SecretResolutionError propagate.
    """
    if upstream_auth_header is None:
        return None
    return await provider.resolve(upstream_auth_header)


def provider_tier_name(provider: "SecretProvider") -> str:
    """Inverse of build_secret_provider — the tier name ("local" | "encrypted" | "openbao") for
    an already-constructed provider instance, purely for display (SettingsResponse.
    secret_provider in archon/schemas.py) — never used to make a security decision, only to hint
    the operator which shape of value the server form currently expects."""
    module = type(provider).__module__
    if module.endswith(".local"):
        return "local"
    if module.endswith(".encrypted"):
        return "encrypted"
    if module.endswith(".openbao"):
        return "openbao"
    return "unknown"


def build_secret_provider(settings) -> "SecretProvider":
    """Factory: selects a SecretProvider from `settings.secret_provider` ("local" | "encrypted" |
    "openbao", default "local" — see archon/settings.py). Imports the concrete providers lazily
    so importing this package never requires the `cryptography` dependency or reaches out over
    the network unless that tier is actually selected.
    """
    provider = getattr(settings, "secret_provider", "local")
    if provider == "local":
        from .local import LocalSecretProvider

        return LocalSecretProvider()
    if provider == "encrypted":
        from .encrypted import EncryptedSecretProvider

        return EncryptedSecretProvider()
    if provider == "openbao":
        from .openbao import OpenBaoSecretProvider

        return OpenBaoSecretProvider(
            base_url=settings.vault_addr or "",
            token=settings.vault_token,
            role_id=settings.vault_role_id,
            secret_id=settings.vault_secret_id,
            ttl_seconds=getattr(settings, "vault_ttl_seconds", 60.0),
        )
    raise ValueError(f"unknown secret_provider {provider!r} (expected 'local', 'encrypted', or 'openbao')")
