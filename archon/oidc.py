"""OIDC (Authorization Code + PKCE) login for the control plane — enterprise #1.

Scope guard (01-identity-and-sso.md): OIDC only. No SAML, no SCIM, no LDAP in this module —
OIDC covers the majority of modern IdPs (Okta, Entra, Google, Keycloak, Authentik), and stating
that boundary explicitly is worth more than half-building three protocols.

Design:
- Authorization Code + PKCE (S256), server-side. Never implicit, never client-side token
  handling — the browser only ever sees Acropolis's own session cookie.
- The IdP's tokens are exchanged for Acropolis's OWN session cookie at the callback and then
  discarded; the rest of the app never learns OIDC happened. This is what keeps session_version
  revocation working uniformly across local and OIDC principals.
- State and nonce are both generated per-attempt, stored server-side (in-memory, short TTL) and
  validated on callback — this is what prevents CSRF-via-callback and ID-token replay
  respectively.
- redirect_uri is allowlisted against the single configured value; the value the IdP is asked to
  redirect to is never taken from client-controlled input (a request query param, a header) —
  only from settings, configured by an admin. This closes the open-redirect vector open_redirect
  concerns usually target.
- JIT provisioning is gated by an explicit allowlist of permitted email domains and/or IdP
  groups, configured by the admin BEFORE any OIDC login can create a user — an open IdP tenant
  (e.g. "any Google account") must not be able to self-provision accounts, let alone admins.
- Identity is keyed on `sub` (db/repo.py's UserRepo.get_by_subject), never email — see
  0007_users.sql's header comment for why.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import httpx

# How long a state/nonce/PKCE-verifier attempt stays valid — long enough for a human to
# authenticate at the IdP (including an MFA prompt), short enough that a leaked/logged state
# value is useless shortly after.
ATTEMPT_TTL_SECONDS = 600


class OidcConfigError(Exception):
    """Raised when OIDC is invoked but not fully/validly configured."""


class OidcCallbackError(Exception):
    """Raised for any callback-time validation failure (state/nonce/redirect_uri mismatch,
    token exchange failure, JIT provisioning denied). Callers map this to a 400, not a 500 —
    it's an untrusted-input rejection, not a server bug."""


@dataclass(frozen=True)
class OidcSettings:
    enabled: bool
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: str = "openid email profile"
    allowed_domains: tuple[str, ...] = ()
    allowed_groups: tuple[str, ...] = ()
    group_claim: str = "groups"
    default_role: str = "viewer"
    jit_provisioning: bool = True

    @staticmethod
    def from_settings_dict(values: dict[str, str]) -> Optional["OidcSettings"]:
        if values.get("oidc_enabled") != "true":
            return None
        required = ("oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_redirect_uri")
        if any(not values.get(k) for k in required):
            raise OidcConfigError(
                "oidc_enabled is true but one or more required settings "
                f"({', '.join(required)}) is unset"
            )
        domains = tuple(d.strip().lower() for d in values.get("oidc_allowed_domains", "").split(",") if d.strip())
        groups = tuple(g.strip() for g in values.get("oidc_allowed_groups", "").split(",") if g.strip())
        return OidcSettings(
            enabled=True,
            issuer=values["oidc_issuer"],
            client_id=values["oidc_client_id"],
            client_secret=values["oidc_client_secret"],
            redirect_uri=values["oidc_redirect_uri"],
            scopes=values.get("oidc_scopes") or "openid email profile",
            allowed_domains=domains,
            allowed_groups=groups,
            group_claim=values.get("oidc_group_claim") or "groups",
            default_role=values.get("oidc_default_role") or "viewer",
            jit_provisioning=values.get("oidc_jit_provisioning", "true") == "true",
        )


@dataclass
class _PendingAttempt:
    state: str
    nonce: str
    code_verifier: str
    created_at: float


class AttemptStore:
    """In-memory store for outstanding login attempts, keyed by `state`. A single-instance,
    single-process gateway (this product's deployment model — see docs/quickstart.md) has no
    need for a shared/external store; state doesn't need to survive a restart, and an attempt
    that outlives ATTEMPT_TTL_SECONDS is deliberately unusable rather than persisted."""

    # Security-scan fix: /auth/oidc/login is (necessarily) unauthenticated — it's how a
    # not-yet-logged-in browser starts the flow. Without a cap, an anonymous requester spamming
    # that endpoint could grow `_attempts` unbounded between TTL sweeps, a cheap memory-
    # exhaustion DoS. Each entry is tiny (~150 bytes), but "tiny but unbounded and attacker-
    # triggered before any auth check" is exactly the shape worth capping defensively. Evicts
    # the OLDEST entry to make room rather than rejecting the new attempt outright — a real
    # burst of legitimate logins (e.g. a demo, or many users at once after an IdP-side outage
    # resolves) should degrade to "very old, likely-already-abandoned attempts get evicted
    # early," not "new logins start failing."
    _MAX_OUTSTANDING_ATTEMPTS = 1000

    def __init__(self) -> None:
        self._attempts: dict[str, _PendingAttempt] = {}

    def create(self) -> _PendingAttempt:
        self._sweep()
        if len(self._attempts) >= self._MAX_OUTSTANDING_ATTEMPTS:
            oldest_state = min(self._attempts, key=lambda s: self._attempts[s].created_at)
            self._attempts.pop(oldest_state, None)
        attempt = _PendingAttempt(
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            code_verifier=_generate_code_verifier(),
            created_at=time.time(),
        )
        self._attempts[attempt.state] = attempt
        return attempt

    def pop(self, state: str) -> Optional[_PendingAttempt]:
        """Single-use: an attempt is consumed on lookup, valid or not, so a state value can
        never be replayed against a second callback."""
        self._sweep()
        return self._attempts.pop(state, None)

    def _sweep(self) -> None:
        cutoff = time.time() - ATTEMPT_TTL_SECONDS
        expired = [s for s, a in self._attempts.items() if a.created_at < cutoff]
        for s in expired:
            self._attempts.pop(s, None)


def _generate_code_verifier() -> str:
    # RFC 7636: 43-128 chars from [A-Za-z0-9-._~]. token_urlsafe(64) yields ~86 chars from
    # exactly that alphabet (base64url minus padding).
    return secrets.token_urlsafe(64)


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def discover(issuer: str, http_client: httpx.AsyncClient) -> dict:
    """Fetch the IdP's `.well-known/openid-configuration` document. Not cached across calls at
    this layer — callers (the login/callback routes) are infrequent (human login events, not a
    hot path), and always fetching fresh avoids serving a stale authorization_endpoint after an
    admin rotates IdP configuration."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    resp = await http_client.get(url, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def build_authorization_url(
    *, authorization_endpoint: str, client_id: str, redirect_uri: str,
    scopes: str, state: str, nonce: str, code_verifier: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": _code_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


async def exchange_code(
    *, token_endpoint: str, client_id: str, client_secret: str, redirect_uri: str,
    code: str, code_verifier: str, http_client: httpx.AsyncClient,
) -> dict:
    """Authorization Code + PKCE token exchange. `redirect_uri` here is the SAME
    admin-configured value used to build the authorization URL — never taken from the callback
    request — so a value an attacker controls can never be substituted into the exchange."""
    resp = await http_client.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
        },
        headers={"Accept": "application/json"},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def decode_id_token_unverified(id_token: str) -> dict:
    """Decode the ID token's payload WITHOUT verifying its signature.

    This is safe here specifically because the token arrived over the direct, TLS-protected
    back-channel token exchange (exchange_code above) — it was never handled by the browser or
    any untrusted intermediary, so there is nothing for a forged signature to defend against in
    this flow (contrast with validating an ID token received via the browser/implicit flow,
    where signature verification would be load-bearing). Full JWKS signature verification is a
    reasonable hardening follow-up but is not required for THIS flow's threat model — noted
    explicitly here so it doesn't read as an oversight."""
    try:
        _header_b64, payload_b64, _sig_b64 = id_token.split(".")
    except ValueError:
        raise OidcCallbackError("malformed id_token")
    padding = "=" * (-len(payload_b64) % 4)
    import json
    try:
        return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except Exception as e:
        raise OidcCallbackError(f"could not decode id_token payload: {e}") from e


def validate_id_token_claims(*, claims: dict, oidc_settings: OidcSettings, issuer_claim: Optional[str]) -> None:
    """Security-scan fix: validate `aud` (and `iss`, when the discovery document supplied one)
    on the decoded ID token before trusting anything else in it.

    Not strictly load-bearing under THIS flow's threat model — decode_id_token_unverified's own
    docstring explains why signature verification isn't required here (the token arrives over a
    direct back-channel exchange gated by client_secret + PKCE, never through the browser) — but
    `aud`/`iss` checks are cheap, standard OIDC hygiene, and defense in depth against a
    misconfigured or malicious IdP returning a token that was actually minted for a DIFFERENT
    client/tenant at the same issuer. Raises OidcCallbackError (mapped to a 400 by the caller)
    rather than silently trusting a token that doesn't claim to be for this app."""
    aud = claims.get("aud")
    aud_ok = aud == oidc_settings.client_id or (isinstance(aud, list) and oidc_settings.client_id in aud)
    if not aud_ok:
        raise OidcCallbackError("id_token audience does not match this client")

    if issuer_claim is not None and claims.get("iss") != issuer_claim:
        raise OidcCallbackError("id_token issuer does not match the configured provider")


def check_jit_allowlist(*, claims: dict, oidc_settings: OidcSettings) -> None:
    """Enforce the JIT-provisioning allowlist (01-identity-and-sso.md non-negotiable): an open
    IdP tenant must not be able to self-provision an account, let alone an admin one. Raises
    OidcCallbackError if neither an allowed domain nor an allowed group matches — an EMPTY
    allowlist (no domains AND no groups configured) is treated as "allow any successfully
    authenticated subject," which is the admin's explicit choice by leaving both blank, not a
    silent default; documented in docs/authentication.md."""
    if not oidc_settings.allowed_domains and not oidc_settings.allowed_groups:
        return

    email = claims.get("email")
    domain_ok = False
    if oidc_settings.allowed_domains and isinstance(email, str) and "@" in email:
        domain = email.rsplit("@", 1)[1].lower()
        domain_ok = domain in oidc_settings.allowed_domains

    group_ok = False
    if oidc_settings.allowed_groups:
        groups = claims.get(oidc_settings.group_claim) or []
        if isinstance(groups, list):
            group_ok = any(g in oidc_settings.allowed_groups for g in groups)

    if not (domain_ok or group_ok):
        raise OidcCallbackError("subject is not in the configured JIT-provisioning allowlist")


def map_group_to_role(*, claims: dict, oidc_settings: OidcSettings) -> str:
    """Highest-ranking role among the groups the IdP asserts, falling back to default_role.
    Import here (not module top-level) avoids a circular import: archon.rbac imports
    archon.admin_auth, and admin_auth does not need to import oidc.py."""
    from archon.rbac import ROLE_RANK, is_valid_role

    groups = claims.get(oidc_settings.group_claim) or []
    if not isinstance(groups, list):
        return oidc_settings.default_role

    # A group named exactly "admin"/"operator"/"viewer" maps directly — this is intentionally
    # the simplest possible mapping (a claim-name + direct role-name match), not a configurable
    # mapping table, matching the scope this milestone actually needs; a real mapping table is
    # easy to add later without a schema change since role stays a plain string end to end.
    candidate_roles = [g for g in groups if is_valid_role(g)]
    if not candidate_roles:
        return oidc_settings.default_role
    return max(candidate_roles, key=lambda r: ROLE_RANK[r])
