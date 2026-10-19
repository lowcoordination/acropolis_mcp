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

Auth, three ways, all opt-in and none tied to a platform (the client only does HTTP and reads
files):

  * a static token (`ACROPOLIS_VAULT_TOKEN`), the baseline;
  * AppRole (`ACROPOLIS_VAULT_ROLE_ID` plus the secret_id, inline in `ACROPOLIS_VAULT_SECRET_ID` or
    read from the file named by `ACROPOLIS_VAULT_SECRET_ID_FILE`, so Docker secrets, Kubernetes
    Secret mounts and systemd credentials can keep it out of the process environment, where it
    is readable through /proc/<pid>/environ and `docker inspect`);
  * Kubernetes auth (`ACROPOLIS_VAULT_AUTH_METHOD=kubernetes` plus `ACROPOLIS_VAULT_K8S_ROLE`),
    where the credential is the pod's own short-lived service-account token read from a file, so
    no static secret exists at all. No Kubernetes client library is involved: it is one HTTP POST
    of a file's contents.

The login token is cached for its lease, and credential files are re-read on EVERY login, because
the platforms that rotate them (kubelet's projected tokens, a re-mounted Docker secret) rewrite the
file in place. With no auth method selected, the method is inferred from what is configured, as
it always was.

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

import asyncio
import logging
import os
import re
import stat
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import httpx

from . import SecretResolutionError, _TTLCache

logger = logging.getLogger("archon.secrets.openbao")

DEFAULT_TTL_SECONDS = 60.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0

# The in-cluster location Kubernetes projects the pod's service-account token at. A default for
# convenience, not a dependency: nothing reads it unless Kubernetes auth is selected.
DEFAULT_K8S_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"
DEFAULT_K8S_MOUNT = "kubernetes"
AUTH_METHODS = ("token", "approle", "kubernetes")
# A credential file holds a token or an id, never a document. The cap stops a mis-pointed path
# (a log, a device) from being read into memory; a real projected JWT is about 1 KiB.
MAX_CREDENTIAL_FILE_BYTES = 16 * 1024
# After a failed login (endpoint down or hung, credential rejected, file missing), further requests
# fail fast with the same error for this long instead of each retrying in turn behind the login
# lock. Without it, N waiters against a hung endpoint take N x the request timeout and hammer the
# endpoint (with Kubernetes auth, the API server). Short, so a fixed credential is picked up quickly.
LOGIN_FAILURE_BACKOFF_SECONDS = 2.0

def _read(fd: int, n: int) -> bytes:
    """os.read, as a seam: a test makes it return short reads, which a local file never does."""
    return os.read(fd, n)


# The auth mount name is interpolated into the login URL, so it is restricted the way a Vault
# path segment list reasonably is: no empty, "." or ".." segments, no query/fragment/whitespace
# characters, no percent-encoding. Matched with fullmatch: "$" would accept a trailing newline.
_MOUNT_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")

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
    required, and exactly one consistent auth mode (token, AppRole or Kubernetes) must be
    configured. Conflicting or half-given credentials fail here, at startup, never at first use."""


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
        secret_id_file: Optional[str] = None,
        auth_method: Optional[str] = None,
        k8s_role: Optional[str] = None,
        k8s_token_file: str = DEFAULT_K8S_TOKEN_FILE,
        k8s_mount: str = DEFAULT_K8S_MOUNT,
        client: Optional[httpx.AsyncClient] = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ):
        if not base_url:
            raise OpenBaoConfigError("base_url is required")
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise OpenBaoConfigError(f"base_url must be an http(s) URL, got {base_url!r}")

        if secret_id and secret_id_file:
            raise OpenBaoConfigError(
                "set either the AppRole secret_id or secret_id_file, not both"
            )
        has_approle = bool(role_id and (secret_id or secret_id_file))
        inferred = auth_method is None
        if auth_method is None:
            # Unchanged historical behaviour: infer from what is configured. Kubernetes auth is
            # never inferred; it must be selected, so a stray ACROPOLIS_VAULT_K8S_ROLE cannot
            # change how an existing deployment logs in.
            if token:
                auth_method = "token"
            elif has_approle:
                auth_method = "approle"
            else:
                raise OpenBaoConfigError(
                    "configure one auth method: a token, or an AppRole (role_id plus secret_id or "
                    "secret_id_file), or auth_method='kubernetes' with a role"
                )
        if auth_method not in AUTH_METHODS:
            raise OpenBaoConfigError(
                f"unknown auth_method {auth_method!r} (expected one of {', '.join(AUTH_METHODS)})"
            )
        wants = {"token": bool(token), "approle": has_approle, "kubernetes": bool(k8s_role)}
        if not wants[auth_method]:
            raise OpenBaoConfigError(
                f"auth_method {auth_method!r} is selected but its settings are missing or incomplete"
            )
        # Conflicts are only an error when the method was SELECTED. With none selected the old
        # rule stands (a static token wins over AppRole), so no existing deployment changes.
        conflicting = [] if inferred else [m for m in AUTH_METHODS if m != auth_method and (
            wants[m] or (m == "approle" and (role_id or secret_id or secret_id_file))
        )]
        if conflicting:
            raise OpenBaoConfigError(
                f"auth_method {auth_method!r} is selected but credentials for "
                f"{', '.join(sorted(set(conflicting)))} are also configured; give exactly one"
            )
        if auth_method == "kubernetes" and not _MOUNT_RE.fullmatch(k8s_mount or ""):
            raise OpenBaoConfigError(
                f"k8s_mount must be a plain auth mount name like 'kubernetes' or 'team/k8s', got {k8s_mount!r}"
            )

        self._base_url = base_url.rstrip("/")
        self._auth_method = auth_method
        self._static_token = token if auth_method == "token" else None
        self._role_id = role_id
        self._secret_id = secret_id
        self._secret_id_file = secret_id_file
        self._k8s_role = k8s_role
        self._k8s_token_file = k8s_token_file
        self._k8s_mount = k8s_mount
        self._request_timeout = request_timeout_seconds
        # A dedicated client (rather than the app-wide shared http_client) so this provider's
        # short, fixed request timeout can never be affected by — or affect — the generous
        # upstream-call timeout budget the rest of the gateway uses. Tests may inject their own
        # client pointed at a disposable dev server.
        self._client = client or httpx.AsyncClient(timeout=self._request_timeout)
        self._owns_client = client is None

        self._cache = _TTLCache(ttl_seconds)
        self._login_token: Optional[str] = None
        self._login_token_expires_at: float = 0.0
        # One login at a time: when the cached token expires, every in-flight request would
        # otherwise log in separately (with Kubernetes auth each login is a TokenReview call).
        self._login_lock = asyncio.Lock()
        self._login_failed_until: float = 0.0
        self._login_failure: Optional[tuple[str, str]] = None  # (ref label, reason) of the last failure

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _read_credential_file(self, path: str, label: str, what: str) -> str:
        """Read a credential from a file, fresh each time. Errors name the path and the problem
        and NEVER include the file's contents."""
        def read() -> Optional[bytes]:
            # Opened non-blocking and checked with fstat BEFORE reading: a FIFO with no writer would
            # otherwise block this thread forever while the login lock is held, freezing every
            # secret resolution. Only a regular file is a credential file.
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return None
                # os.read may legally return fewer bytes than the file holds (network filesystems,
                # signals); a silently truncated credential is worse than an error, so read to EOF
                # or one byte past the cap.
                chunks, total = [], 0
                while total <= MAX_CREDENTIAL_FILE_BYTES:
                    chunk = _read(fd, MAX_CREDENTIAL_FILE_BYTES + 1 - total)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                return b"".join(chunks)
            finally:
                os.close(fd)

        try:
            raw = await asyncio.to_thread(read)
        except OSError as e:
            raise SecretResolutionError(
                label, f"could not read the {what} file {path!r}: {e.strerror or type(e).__name__}"
            ) from e
        if raw is None:
            raise SecretResolutionError(label, f"the {what} file {path!r} is not a regular file")
        if len(raw) > MAX_CREDENTIAL_FILE_BYTES:
            raise SecretResolutionError(
                label, f"the {what} file {path!r} is too large to be a credential "
                       f"(over {MAX_CREDENTIAL_FILE_BYTES} bytes)"
            )
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeDecodeError as e:
            raise SecretResolutionError(label, f"the {what} file {path!r} is not UTF-8 text") from e
        if not value:
            raise SecretResolutionError(label, f"the {what} file {path!r} is empty")
        return value

    async def _login(self) -> str:
        """Log in by the selected method, cache the resulting token for its lease, return it."""
        if self._auth_method == "kubernetes":
            label, name = "<kubernetes-login>", "Kubernetes auth"
            jwt = await self._read_credential_file(
                self._k8s_token_file, label, "service-account token"
            )
            url = f"{self._base_url}/v1/auth/{self._k8s_mount}/login"
            payload = {"role": self._k8s_role, "jwt": jwt}
        else:
            label, name = "<approle-login>", "AppRole"
            secret_id = self._secret_id
            if self._secret_id_file:
                secret_id = await self._read_credential_file(
                    self._secret_id_file, label, "AppRole secret_id"
                )
            url = f"{self._base_url}/v1/auth/approle/login"
            payload = {"role_id": self._role_id, "secret_id": secret_id}

        try:
            resp = await self._client.post(url, json=payload)
        except httpx.HTTPError as e:
            raise SecretResolutionError(label, f"{name} login request failed: {e}") from e
        if resp.status_code != 200:
            raise SecretResolutionError(label, f"{name} login returned HTTP {resp.status_code}")
        try:
            data = resp.json()
            auth = data["auth"]
            token = auth["client_token"]
            lease_seconds = float(auth.get("lease_duration") or 3600)
        except (ValueError, KeyError, TypeError) as e:
            raise SecretResolutionError(label, f"{name} login response malformed: {e}") from e
        self._login_token = token
        self._login_failed_until = 0.0
        self._login_failure = None
        # Refresh a bit before actual expiry so a resolve() never races a just-expired token.
        self._login_token_expires_at = time.monotonic() + max(lease_seconds - 30.0, 5.0)
        return token

    def _cached_login_token(self) -> Optional[str]:
        if self._login_token and time.monotonic() < self._login_token_expires_at:
            return self._login_token
        return None

    async def _current_token(self) -> str:
        if self._static_token:
            return self._static_token
        token = self._cached_login_token()
        if token:
            return token
        async with self._login_lock:
            # Re-check: another request may have logged in while this one waited.
            token = self._cached_login_token()
            if token:
                return token
            # ...or may have just failed: fail fast with the same error rather than retry in turn.
            if self._login_failure and time.monotonic() < self._login_failed_until:
                raise SecretResolutionError(*self._login_failure)
            try:
                return await self._login()
            except SecretResolutionError as e:
                self._login_failure = (e.ref, e.reason)
                self._login_failed_until = time.monotonic() + LOGIN_FAILURE_BACKOFF_SECONDS
                raise

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
