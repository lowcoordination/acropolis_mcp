from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Request

from archon.sessions import (
    DEFAULT_SESSION_VERSION,
    SESSION_COOKIE_NAME,
    decode_session_payload,
    verify_session_token,
)
from db.repo import SettingsRepo, UserRepo


@dataclass(frozen=True)
class Principal:
    """The authenticated actor behind a control-plane request (enterprise #1/#2).

    `user_id` is None for the two non-user-table auth paths that stay permanent regardless of
    migration state: the `admin_token` break-glass bearer, and the first-run window before the
    setup wizard has created an admin at all (no `users` row can exist yet, by construction).
    `role` is always populated — even those two paths resolve to "admin" — so every route can
    depend on `require_role` uniformly instead of special-casing "no principal.role."

    Issue #33 (R6): a THIRD user_id=None path used to exist here — a session cookie with no
    user_id, verified against the legacy admin_password_hash session_secret/session_version,
    covering a partially-applied upgrade where 0007_users.sql had run but nobody had logged in
    with a fresh user-bearing token yet. Retired once GET /api/v1/diagnostics/legacy-session
    confirmed it unreachable: no argus deployment has ever run with real users, so no cookie
    predating the identity milestone can exist to protect. See that endpoint's docstring and
    docs/authentication.md's retirement runbook for the general procedure this specific
    retirement skipped past (there was no history to bump session_version against).
    """

    role: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    auth_source: str = "local"  # 'local' | 'oidc' | 'admin-token' | 'legacy-admin'

    @property
    def actor(self) -> str:
        """String form for admin_audit.py's `actor` column. Prefers a real username once one
        exists; falls back to a source label for the break-glass/legacy paths, matching the
        placeholder strings admin_events already used pre-identity-milestone ('admin-session',
        'admin-token') so old rows and new rows read consistently in the audit log."""
        if self.username:
            return self.username
        if self.auth_source == "admin-token":
            return "admin-token"
        return "admin-session"


_LEGACY_ADMIN_PRINCIPAL = Principal(role="admin", auth_source="legacy-admin")
_ADMIN_TOKEN_PRINCIPAL = Principal(role="admin", auth_source="admin-token")


async def require_admin(
    request: Request, authorization: str | None = Header(default=None)
) -> Principal:
    """Control-plane auth for /api/v1. Resolves to a Principal (never returns None) — every
    route that needs attribution or a role takes it as a FastAPI dependency, directly or via
    archon/rbac.py's require_role, which itself depends on this.

    Three independent ways in, tried in this order:

    1. `settings.admin_token` env var as a bearer token — the documented CI/automation
       override, and critically also the BREAK-GLASS path if the `users` table or its role
       data is ever wrong. Maps to a synthetic admin-token actor, never blocked by user state.
    2. A session cookie carrying a `user_id` — the normal path once `users` is populated
       (which is always, post-first-run-setup — see path 3 below). Resolves the live user row
       (role, enabled, per-user session_version) on every request, same "DB is authoritative"
       pattern auth_mode and the global session_version already use.
    3. Nothing valid presented, `users` table empty, no admin_token configured — the narrow
       "open until first-run wizard completes" window. Every session issued from here on
       carries a real user_id (setup mints one), so this is the only user_id=None state a
       fresh cookie can ever be in.

    Issue #33 (R6): a fourth path used to exist — a session cookie with NO user_id, verified
    against the legacy admin_password_hash session_secret/session_version, for a
    partially-applied upgrade where the users migration had run but nobody had logged back in
    with a fresh token yet. Retired: no argus deployment has ever carried real users through
    that migration boundary, so the condition it existed for has never occurred and cannot
    retroactively occur now. See Principal's docstring and
    GET /api/v1/diagnostics/legacy-session (docs/authentication.md) for the general-case
    retirement procedure a deployment WITH history would need to run first.
    """
    settings = request.app.state.settings

    if settings.admin_token and authorization and authorization.lower().startswith("bearer "):
        presented = authorization[len("Bearer "):]
        # §26 fix (review 2026-08-04): hmac.compare_digest raises TypeError on a `str` argument
        # containing non-ASCII characters. `presented` is attacker-controlled (straight off the
        # Authorization header) — a malformed token must fail closed, not crash the request.
        if presented.isascii() and hmac.compare_digest(presented, settings.admin_token):
            return _ADMIN_TOKEN_PRINCIPAL

    settings_repo: SettingsRepo = request.app.state.settings_repo
    user_repo: Optional[UserRepo] = getattr(request.app.state, "user_repo", None)

    admin_password_hash = await settings_repo.get("admin_password_hash")

    if admin_password_hash is None:
        if settings.admin_token:
            # An admin_token IS configured but wasn't presented/matched above, and no admin
            # has been set up via the wizard either — there is no valid path in.
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")
        # No admin configured yet, and no admin_token override — only reachable before the
        # first-run wizard completes.
        return _LEGACY_ADMIN_PRINCIPAL

    session_secret = await settings_repo.get("session_secret")
    if session_secret is None:
        raise HTTPException(status_code=401, detail="server misconfigured: no session secret")

    stored_version = await settings_repo.get("session_version")
    current_session_version = int(stored_version) if stored_version is not None else DEFAULT_SESSION_VERSION

    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="not authenticated")

    payload = decode_session_payload(cookie)
    user_id = payload.get("user_id") if payload else None

    # Issue #33 (R6): the legacy user-less fallback that used to live here (verify against
    # admin_password_hash's session_secret directly) is retired. Once admin_password_hash is
    # set (checked above), every session this app issues carries a real user_id — there is no
    # code path left that mints a user_id=None token post-first-run. A cookie with no user_id
    # reaching this point is therefore either forged, or a genuine relic of a pre-identity
    # deployment, which by issue #33's diagnostic does not exist for this codebase. Reject it
    # the same as any other malformed credential rather than falling back to a special case.
    if user_id is None or user_repo is None:
        raise HTTPException(status_code=401, detail="not authenticated")

    # A user-bearing token. Resolve the live row — role, enabled, per-user version are all read
    # fresh every request (same DB-is-authoritative pattern as auth_mode).
    try:
        user = await user_repo.get_by_id(int(user_id))
    except Exception:
        raise HTTPException(status_code=401, detail="not authenticated")

    if not verify_session_token(
        cookie, session_secret, current_session_version,
        current_user_session_version=user.session_version,
    ):
        raise HTTPException(status_code=401, detail="not authenticated")

    if not user.enabled:
        raise HTTPException(status_code=401, detail="account disabled")

    return Principal(role=user.role, user_id=user.id, username=user.username, auth_source=user.auth_source)
