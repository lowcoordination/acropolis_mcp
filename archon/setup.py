from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request, Response

from archon.passwords import hash_password, verify_password
from archon.schemas import LoginRequest, SetupRequest, SetupStatusResponse
from archon.sessions import SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECONDS, create_session_token
from db.repo import SettingsRepo


def _request_is_https(request: Request) -> bool:
    """Acropolis itself always speaks plain HTTP (see docs/tls-and-reverse-proxy.md) — TLS, if
    any, is terminated by a reverse proxy in front of it. Trust X-Forwarded-Proto (set by any
    reasonable proxy config, including the ones documented) in addition to request.url.scheme,
    so the session cookie gets the Secure flag once a real deployment is behind HTTPS, without
    breaking the plain-HTTP-on-localhost quickstart flow this app defaults to."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    return forwarded_proto == "https" or request.url.scheme == "https"


def build_setup_router(settings_repo: SettingsRepo) -> APIRouter:
    """Setup and login endpoints — deliberately NOT behind require_admin, since they're how
    an admin gets established (setup) or authenticated (login) in the first place."""
    router = APIRouter(prefix="/api/v1")

    @router.get("/setup/status", response_model=SetupStatusResponse)
    async def setup_status():
        admin_password_hash = await settings_repo.get("admin_password_hash")
        return SetupStatusResponse(setup_complete=admin_password_hash is not None)

    @router.post("/setup", response_model=SetupStatusResponse)
    async def complete_setup(body: SetupRequest, request: Request, response: Response):
        existing = await settings_repo.get("admin_password_hash")
        if existing is not None:
            raise HTTPException(status_code=409, detail="setup has already been completed")
        if len(body.admin_password) < 8:
            raise HTTPException(status_code=400, detail="password must be at least 8 characters")
        if body.auth_mode not in ("open", "keyed"):
            raise HTTPException(status_code=400, detail="auth_mode must be 'open' or 'keyed'")

        session_secret = secrets.token_hex(32)
        await settings_repo.set_many({
            "admin_password_hash": hash_password(body.admin_password),
            "session_secret": session_secret,
            "auth_mode": body.auth_mode,
        })

        token = create_session_token(session_secret)
        response.set_cookie(
            SESSION_COOKIE_NAME, token, max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True, samesite="lax", secure=_request_is_https(request),
        )
        return SetupStatusResponse(setup_complete=True)

    @router.post("/login")
    async def login(body: LoginRequest, request: Request, response: Response):
        stored_hash = await settings_repo.get("admin_password_hash")
        if stored_hash is None:
            raise HTTPException(status_code=400, detail="setup has not been completed yet")
        if not verify_password(body.admin_password, stored_hash):
            raise HTTPException(status_code=401, detail="incorrect password")

        session_secret = await settings_repo.get("session_secret")
        assert session_secret is not None  # set alongside admin_password_hash at setup time

        token = create_session_token(session_secret)
        response.set_cookie(
            SESSION_COOKIE_NAME, token, max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True, samesite="lax", secure=_request_is_https(request),
        )
        return {"status": "ok"}

    @router.post("/logout")
    async def logout(response: Response):
        response.delete_cookie(SESSION_COOKIE_NAME)
        return {"status": "ok"}

    return router
