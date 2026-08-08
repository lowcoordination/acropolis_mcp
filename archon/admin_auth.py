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

    `user_id` is None for the two non-user-table auth paths that must keep working regardless
    of migration state: the `admin_token` break-glass bearer and the legacy single-admin session
    (a pre-identity-milestone cookie, or any cookie issued while `users` is empty/absent).
    `role` is always populated — even the legacy/break-glass paths resolve to "admin", since
    that's what they always implicitly meant before roles existed — so every route can depend on
    `require_role` uniformly instead of special-casing "no principal.role."
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

    Four independent ways in, tried in this order:

    1. `settings.admin_token` env var as a bearer token — the documented CI/automation
       override, and critically also the BREAK-GLASS path if the `users` table or its role
       data is ever wrong. Maps to a synthetic admin-token actor, never blocked by user state.
    2. A session cookie carrying a `user_id` — the normal post-migration path once `users` is
       populated. Resolves the live user row (role, enabled, per-user session_version) on
       every request, same "DB is authoritative" pattern auth_mode and the global
       session_version already use.
    3. A session cookie with NO `user_id` (issued before the identity milestone, or by the
       legacy settings-only login while `users` was empty) — verified against the legacy
       admin_password_hash session_secret/session_version exactly as before. This is what
       makes a partially-applied upgrade degrade to "still works" instead of "locked out."
    4. Nothing valid presented, `users` table absent/empty, no admin_token configured — the
       narrow "open until first-run wizard completes" window, unchanged from before.
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

    # Path 3: no user table, or a legacy/user-less token — same check as pre-identity-milestone,
    # so a partial upgrade (0007_users.sql applied but nobody's logged in with a fresh
    # user-bearing token yet, or `users` genuinely empty for some other reason) still works.
    if user_id is None or user_repo is None:
        if not verify_session_token(cookie, session_secret, current_session_version):
            raise HTTPException(status_code=401, detail="not authenticated")
        return _LEGACY_ADMIN_PRINCIPAL

    # Path 2: a user-bearing token. Resolve the live row — role, enabled, per-user version are
    # all read fresh every request (same DB-is-authoritative pattern as auth_mode).
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
