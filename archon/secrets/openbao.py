"""A generic HashiCorp Vault KV v2 HTTP API client.

Named "openbao" only because that is this codebase's existing terminology for "the external
secret manager tier" (see the plan doc and issue #6) — this file has NO OpenBao-specific
behaviour. It speaks the standard Vault KV v2 HTTP wire protocol
(`GET/POST/DELETE /v1/<mount>/data/<path>`, `X-Vault-Token` header auth) that real HashiCorp
Vault, OpenBao, and any other server implementing the same API all share. It works identically
against any of them; nothing here assumes a specific deployment, mount layout, or network
location beyond what's passed in via settings/environment. See docs/secrets.md and the PR
description for exactly how this was verified (a disposable local dev-mode server started as a
test fixture, not the operator's own infrastructure).

Reference format: `vault://<mount>/<path>#<key>`, e.g. `vault://secret/acropolis/github#token`
reads the `token` field from the secret at `secret/data/acropolis/github` (KV v2 always nests the
actual data one level under `data` server-side; this client adds that automatically — the
reference itself uses the KV v1-shaped path, matching how `vault kv get` addresses it, not the
raw HTTP path).

Auth: a static token (`ACROPOLIS_VAULT_TOKEN`) is the baseline and the only mode required by the
plan. AppRole (`ACROPOLIS_VAULT_ROLE_ID` / `ACROPOLIS_VAULT_SECRET_ID`) is supported as a
nice-to-have — if configured, the client logs in once and caches the resulting token for its
lease duration.

Caching: resolved plaintext values are cached for a short TTL (default 60s, see
`_TTLCache` in `archon/secrets/__init__.py`) — long enough that a normal request burst doesn't
hammer Vault, short enough that a rotation in Vault propagates without an Acropolis restart. This
is a REAL behavioural requirement (see tests/unit/test_secrets_openbao.py's rotation test), not
just a performance nicety — resolving at call time with this cache is what makes rotation work
and what keeps a Vault outage from being a permanent, restart-required outage (a stale cached
value simply expires and the next resolution attempt either succeeds against a recovered Vault or
raises SecretResolutionError, never silently keeps using an old value forever and never silently
forwards without one).
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import httpx

from . import SecretResolutionError, _TTLCache

logger = logging.getLogger("archon.secrets.openbao")

DEFAULT_TTL_SECONDS = 60.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0

_REF_RE = re.compile(r"^vault://(?P<mount>[^/]+)/(?P<path>[^#]+)#(?P<key>.+)$")


class VaultRefError(ValueError):
    """A `vault://...` string that doesn't match the expected shape."""


@dataclass(frozen=True)
class VaultRef:
    mount: str
    path: str
    key: str

    def __str__(self) -> str:
        return f"vault://{self.mount}/{self.path}#{self.key}"


def parse_vault_ref(ref: str) -> VaultRef:
    match = _REF_RE.match(ref)
    if not match:
        raise VaultRefError(
            f"not a valid vault:// reference (expected vault://<mount>/<path>#<key>): {ref!r}"
        )
    mount, path, key = match.group("mount"), match.group("path"), match.group("key")
    # Defense in depth: `path` is deliberately permissive (KV paths are legitimately
    # slash-separated, e.g. "acropolis/github"), but a "." or ".." PATH SEGMENT would let the
    # request URL built from it (f"{base}/v1/{mount}/data/{path}") escape the intended mount's
    # data/ namespace after Vault-side normalisation — e.g. "secret/../sys/mounts" reaching
    # /v1/secret/sys/mounts instead of /v1/secret/data/.... Setting this reference already
    # requires the "admin" role (require_role("admin") on the server create/update routes),
    # which can already register any upstream URL and edit any policy, so this is defense in
    # depth rather than a privilege-escalation fix — but it's cheap and correct to reject
    # outright rather than rely on Vault's own ACLs being the only thing standing in the way.
    segments = path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise VaultRefError(f"path must not contain empty, '.', or '..' segments: {path!r}")
    return VaultRef(mount=mount, path=path, key=key)


class OpenBaoConfigError(Exception):
    """Raised at provider construction time for missing/invalid configuration — a base URL is
    required, and at least one auth mode (token or AppRole) must be configured."""


class OpenBaoSecretProvider:
    """Generic Vault KV v2 client. `base_url` is the server's address (e.g.
    'http://127.0.0.1:8200') — validated only for shape, never hardcoded to any particular host,
    so this same class targets a disposable local dev server in tests and a real Vault/OpenBao
    cluster in production identically."""

    def __init__(
        self,
        base_url: str,
        *,
        token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ):
        if not base_url:
            raise OpenBaoConfigError("base_url is required")
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise OpenBaoConfigError(f"base_url must be an http(s) URL, got {base_url!r}")
        if not token and not (role_id and secret_id):
            raise OpenBaoConfigError(
                "either a token or both role_id and secret_id (AppRole) must be configured"
            )

        self._base_url = base_url.rstrip("/")
        self._static_token = token
        self._role_id = role_id
        self._secret_id = secret_id
        self._request_timeout = request_timeout_seconds
        # A dedicated client (rather than the app-wide shared http_client) so this provider's
        # short, fixed request timeout can never be affected by — or affect — the generous
        # upstream-call timeout budget the rest of the gateway uses. Tests may inject their own
        # client pointed at a disposable dev server.
        self._client = client or httpx.AsyncClient(timeout=self._request_timeout)
        self._owns_client = client is None

        self._cache = _TTLCache(ttl_seconds)
        self._approle_token: Optional[str] = None
        self._approle_token_expires_at: float = 0.0

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _login_approle(self) -> str:
        assert self._role_id and self._secret_id
        try:
            resp = await self._client.post(
                f"{self._base_url}/v1/auth/approle/login",
                json={"role_id": self._role_id, "secret_id": self._secret_id},
            )
        except httpx.HTTPError as e:
            raise SecretResolutionError("<approle-login>", f"AppRole login request failed: {e}") from e
        if resp.status_code != 200:
            raise SecretResolutionError(
                "<approle-login>", f"AppRole login returned HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
            auth = data["auth"]
            token = auth["client_token"]
            lease_seconds = float(auth.get("lease_duration") or 3600)
        except (ValueError, KeyError, TypeError) as e:
            raise SecretResolutionError("<approle-login>", f"AppRole login response malformed: {e}") from e
        self._approle_token = token
        # Refresh a bit before actual expiry so a resolve() never races a just-expired token.
        self._approle_token_expires_at = time.monotonic() + max(lease_seconds - 30.0, 5.0)
        return token

    async def _current_token(self) -> str:
        if self._static_token:
            return self._static_token
        if self._approle_token and time.monotonic() < self._approle_token_expires_at:
            return self._approle_token
        return await self._login_approle()

    async def resolve(self, ref: str) -> str:
        cached = self._cache.get(ref)
        if cached is not None:
            return cached

        try:
            vref = parse_vault_ref(ref)
        except VaultRefError as e:
            raise SecretResolutionError(ref, str(e)) from e

        try:
            token = await self._current_token()
        except SecretResolutionError:
            raise
        except Exception as e:  # defense in depth — token acquisition must never escape raw
            raise SecretResolutionError(ref, f"could not obtain a Vault token: {e}") from e

        url = f"{self._base_url}/v1/{vref.mount}/data/{vref.path}"
        try:
            resp = await self._client.get(url, headers={"X-Vault-Token": token})
        except httpx.HTTPError as e:
            # Covers connection refused, DNS failure, TLS error, and timeout alike — an outage
            # or an unreachable address must surface as ONE clear, catchable error type, never
            # propagate as a raw httpx exception past this seam (which the read paths would not
            # know how to turn into an ERROR decision / unhealthy status).
            raise SecretResolutionError(ref, f"could not reach Vault at {self._base_url}: {e}") from e

        if resp.status_code == 404:
            raise SecretResolutionError(ref, f"no secret found at {vref.mount}/{vref.path}")
        if resp.status_code in (401, 403):
            raise SecretResolutionError(ref, f"Vault denied access (HTTP {resp.status_code})")
        if resp.status_code != 200:
            raise SecretResolutionError(ref, f"Vault returned HTTP {resp.status_code}")

        try:
            body = resp.json()
            fields = body["data"]["data"]
        except (ValueError, KeyError, TypeError) as e:
            raise SecretResolutionError(ref, f"unexpected KV v2 response shape: {e}") from e

        if vref.key not in fields:
            raise SecretResolutionError(
                ref, f"key {vref.key!r} not present in secret at {vref.mount}/{vref.path}"
            )
        value = fields[vref.key]
        if not isinstance(value, str):
            raise SecretResolutionError(ref, f"key {vref.key!r} is not a string value")

        self._cache.set(ref, value)
        return value

    async def store(self, ref: str, value: str) -> str:
        """`ref` here is the vault:// TARGET to write to (chosen by the caller — e.g. derived
        from the server slug), not something this method invents. Returns the same reference
        string back, since that (not the value) is what belongs in `upstream_auth_header`."""
        try:
            vref = parse_vault_ref(ref)
        except VaultRefError as e:
            raise SecretResolutionError(ref, str(e)) from e

        token = await self._current_token()
        url = f"{self._base_url}/v1/{vref.mount}/data/{vref.path}"
        try:
            # KV v2 write is a merge-unaware PUT of the whole `data` object at that path in this
            # client — callers that want to preserve sibling keys under the same path must read
            # first. Acceptable for this feature: one Acropolis-managed key per path is the
            # documented convention (see docs/secrets.md).
            resp = await self._client.post(url, headers={"X-Vault-Token": token}, json={"data": {vref.key: value}})
        except httpx.HTTPError as e:
            raise SecretResolutionError(ref, f"could not reach Vault at {self._base_url}: {e}") from e
        if resp.status_code not in (200, 204):
            raise SecretResolutionError(ref, f"Vault write returned HTTP {resp.status_code}")

        self._cache.invalidate(ref)
        return str(vref)

    async def delete(self, ref: str) -> None:
        try:
            vref = parse_vault_ref(ref)
        except VaultRefError as e:
            raise SecretResolutionError(ref, str(e)) from e
        token = await self._current_token()
        # Metadata delete (not just a soft-delete of the latest version) — a "delete" from
        # Acropolis's point of view means the reference is gone; leaving old versions
        # recoverable via KV v2's versioning is Vault's own retention policy to manage, not a
        # concern of this thin client.
        url = f"{self._base_url}/v1/{vref.mount}/metadata/{vref.path}"
        try:
            await self._client.delete(url, headers={"X-Vault-Token": token})
        except httpx.HTTPError as e:
            raise SecretResolutionError(ref, f"could not reach Vault at {self._base_url}: {e}") from e
        self._cache.invalidate(ref)
