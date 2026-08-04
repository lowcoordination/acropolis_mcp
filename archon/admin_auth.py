from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request

from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, verify_session_token
from db.repo import SettingsRepo


async def require_admin(
    request: Request, authorization: str | None = Header(default=None)
) -> None:
    """Admin auth for the /api/v1 control plane. Two independent ways in — either is
    sufficient, so an operator can use one, the other, or both concurrently:

    1. `settings.admin_token` env var as a bearer token — an automation/CI override, not
       shown anywhere in the UI.
    2. A valid session cookie, signed with the per-instance secret generated at first-run
       setup (see archon/setup.py) and stored in the settings table.

    If `admin_token` is configured, its presence means the operator has explicitly opted into
    enforcing auth — so once it's set, a request with neither a valid bearer token NOR a valid
    session is rejected outright; it must NOT silently fall through to "no admin set up yet, so
    it's open" (that open state is only for the narrow window between first boot and finishing
    the wizard, and configuring admin_token is a clear signal that window should be closed).
    """
    settings = request.app.state.settings

    if settings.admin_token and authorization and authorization.lower().startswith("bearer "):
        presented = authorization[len("Bearer "):]
        if hmac.compare_digest(presented, settings.admin_token):
            return

    settings_repo: SettingsRepo = request.app.state.settings_repo
    admin_password_hash = await settings_repo.get("admin_password_hash")

    if admin_password_hash is None:
        if settings.admin_token:
            # An admin_token IS configured but wasn't presented/matched above, and no admin
            # has been set up via the wizard either — there is no valid path in.
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")
        # No admin configured yet, and no admin_token override — only reachable before the
        # first-run wizard completes.
        return

    session_secret = await settings_repo.get("session_secret")
    if session_secret is None:
        raise HTTPException(status_code=401, detail="server misconfigured: no session secret")

    # F18: current_session_version is read live from settings on every request, same DB-is-
    # authoritative pattern as auth_mode — a version bump (logout-all, password change) must
    # invalidate outstanding tokens on the very next request, not require a restart.
    stored_version = await settings_repo.get("session_version")
    current_session_version = int(stored_version) if stored_version is not None else DEFAULT_SESSION_VERSION

    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie or not verify_session_token(cookie, session_secret, current_session_version):
        raise HTTPException(status_code=401, detail="not authenticated")
