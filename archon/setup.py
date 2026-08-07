from __future__ import annotations

import asyncio
import secrets
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response

from archon.passwords import hash_password, verify_password
from archon.schemas import LoginRequest, PasswordChangeRequest, SetupRequest, SetupStatusResponse
from archon.sessions import (
    DEFAULT_SESSION_VERSION,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    create_session_token,
    decode_session_payload,
)
from db.repo import SettingsRepo, UserRepo

# F16 fix (review 2026-08-04): no throttling existed on /login or /setup at all. PBKDF2-SHA256
# at 600k iterations costs ~67ms/attempt — correct, OWASP-compliant work, but with no lockout it
# still permits ~15 guesses/sec sustained against an 8-character-minimum password that is the
# SOLE credential for the entire gateway. Per-source-IP token bucket, reusing the same
# RateLimiterRegistry the data plane already uses. Generous enough not to lock out a legitimate
# admin who mistypes a password a few times, tight enough to make sustained guessing impractical.
_LOGIN_RATE_LIMIT_SPEC = "10/minute"


def _request_is_https(request: Request) -> bool:
    """Acropolis itself always speaks plain HTTP (see docs/tls-and-reverse-proxy.md) — TLS, if
    any, is terminated by a reverse proxy in front of it. Trust X-Forwarded-Proto (set by any
    reasonable proxy config, including the ones documented) in addition to request.url.scheme,
    so the session cookie gets the Secure flag once a real deployment is behind HTTPS, without
    breaking the plain-HTTP-on-localhost quickstart flow this app defaults to."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    return forwarded_proto == "https" or request.url.scheme == "https"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _current_session_version(settings_repo: SettingsRepo) -> int:
    stored = await settings_repo.get("session_version")
    return int(stored) if stored is not None else DEFAULT_SESSION_VERSION


def build_setup_router(
    settings_repo: SettingsRepo,
    rate_limiter: Optional[RateLimiterRegistry] = None,
    user_repo: Optional[UserRepo] = None,
) -> APIRouter:
    """Setup and login endpoints — deliberately NOT behind require_admin, since they're how
    an admin gets established (setup) or authenticated (login) in the first place.

    `rate_limiter` is optional only so existing direct-construction call sites (tests) don't
    break; every real deployment via create_app() passes the shared RateLimiterRegistry.

    `user_repo` (enterprise #1): when provided, setup/login/change-password write through to
    the `users` table (local users first — see 01-identity-and-sso.md design decision 1) IN
    ADDITION to the legacy settings.admin_password_hash write, which is kept as a fallback read
    path per that plan's non-negotiables. Optional so tests constructing this router directly
    without a full app (pre-identity-milestone style) keep working unmodified."""
    router = APIRouter(prefix="/api/v1")

    @router.get("/health")
    async def health():
        # F21 fix (review 2026-08-04): moved here from archon/api.py's control-plane router,
        # which sits behind require_admin — both the Dockerfile HEALTHCHECK and the k8s
        # liveness/readiness probes need this reachable with no credentials, at every point in
        # the app's lifecycle (before AND after first-run setup completes). Deliberately just a
        # liveness check (the process is up and answering HTTP), not a readiness/dependency
        # check — it must stay this simple to be trustworthy as the thing a probe kills the
        # pod over.
        return {"status": "ok"}

    @router.get("/setup/status", response_model=SetupStatusResponse)
    async def setup_status():
        admin_password_hash = await settings_repo.get("admin_password_hash")
        return SetupStatusResponse(setup_complete=admin_password_hash is not None)

    @router.post("/setup", response_model=SetupStatusResponse)
    async def complete_setup(body: SetupRequest, request: Request, response: Response):
        # F16: rate-limit setup attempts per source IP too — the pre-setup window is the
        # highest-value target of all (whoever completes it first becomes the admin).
        if rate_limiter is not None:
            key = f"setup:{_client_ip(request)}"
            if not rate_limiter.is_registered(key):
                rate_limiter.register(key, _LOGIN_RATE_LIMIT_SPEC)
            if not await rate_limiter.check(key):
                raise HTTPException(status_code=429, detail="too many setup attempts, slow down")

        existing = await settings_repo.get("admin_password_hash")
        if existing is not None:
            raise HTTPException(status_code=409, detail="setup has already been completed")
        if len(body.admin_password) < 8:
            raise HTTPException(status_code=400, detail="password must be at least 8 characters")
        if body.auth_mode not in ("open", "keyed"):
            raise HTTPException(status_code=400, detail="auth_mode must be 'open' or 'keyed'")

        session_secret = secrets.token_hex(32)
        # F16: hash_password runs PBKDF2-HMAC-SHA256 at 600k iterations synchronously — ~67ms
        # of pure CPU with the GIL held. Called directly inside `async def`, that blocks the
        # SINGLE event loop thread for the duration, stalling every other in-flight request
        # (data plane included) for as long as the hash takes. run_in_executor moves it off
        # the loop thread; a burst of concurrent setup/login attempts then costs thread-pool
        # contention instead of blocking the whole gateway.
        loop = asyncio.get_running_loop()
        password_hash = await loop.run_in_executor(None, hash_password, body.admin_password)
        await settings_repo.set_many({
            "admin_password_hash": password_hash,
            "session_secret": session_secret,
            "auth_mode": body.auth_mode,
        })

        user_id: Optional[int] = None
        if user_repo is not None:
            # Local users first (01-identity-and-sso.md design decision 1): first-run setup
            # creates the real `users` row directly, same hash, so a fresh install never has to
            # rely on the legacy fallback path at all — that path exists for UPGRADES of an
            # existing pre-identity-milestone instance, not new ones.
            user = await user_repo.create(
                username="admin", role="admin", password_hash=password_hash,
            )
            user_id = user.id

        token = create_session_token(
            session_secret, session_version=DEFAULT_SESSION_VERSION,
            user_id=user_id, user_session_version=DEFAULT_SESSION_VERSION,
        )
        response.set_cookie(
            SESSION_COOKIE_NAME, token, max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True, samesite="lax", secure=_request_is_https(request),
        )
        return SetupStatusResponse(setup_complete=True)

    @router.post("/login")
    async def login(body: LoginRequest, request: Request, response: Response):
        # F16: per-source-IP token bucket ahead of the password check — an unthrottled login
        # guarding the sole credential for the entire gateway is not an acceptable posture,
        # especially once anything is reachable off a trusted LAN.
        if rate_limiter is not None:
            key = f"login:{_client_ip(request)}"
            if not rate_limiter.is_registered(key):
                rate_limiter.register(key, _LOGIN_RATE_LIMIT_SPEC)
            if not await rate_limiter.check(key):
                raise HTTPException(status_code=429, detail="too many login attempts, slow down")

        stored_hash = await settings_repo.get("admin_password_hash")
        if stored_hash is None:
            raise HTTPException(status_code=400, detail="setup has not been completed yet")

        # enterprise #1: the login form is still single-credential (just a password, no
        # username field) — this endpoint's request shape is unchanged. What changed is WHERE
        # the hash it verifies against comes from: prefer the `users` table's 'admin' row (the
        # normal post-migration/post-setup state) and fall back to the legacy
        # settings.admin_password_hash read for a not-yet-migrated or partially-migrated
        # instance (0007_users.sql non-negotiable: partial upgrade degrades to "still works").
        user = await user_repo.get_by_username("admin") if user_repo is not None else None
        verify_against = user.password_hash if (user is not None and user.password_hash) else stored_hash

        # F16: see the identical run_in_executor note on /setup above — verify_password runs
        # the same synchronous PBKDF2 work and must not block the event loop either.
        loop = asyncio.get_running_loop()
        password_ok = await loop.run_in_executor(None, verify_password, body.admin_password, verify_against)
        if not password_ok:
            raise HTTPException(status_code=401, detail="incorrect password")
        if user is not None and not user.enabled:
            raise HTTPException(status_code=401, detail="account disabled")

        session_secret = await settings_repo.get("session_secret")
        if session_secret is None:
            # F26 (§26 cleanup, folded in here since it's a one-line change on a line already
            # being touched): the old `assert session_secret is not None` is stripped entirely
            # under `python -O`, after which create_session_token(None) raises a confusing
            # AttributeError instead of a clear error. Explicit raise survives -O.
            raise HTTPException(status_code=500, detail="server misconfigured: no session secret")

        current_version = await _current_session_version(settings_repo)
        if user is not None:
            await user_repo.touch_last_login(user.id)
            token = create_session_token(
                session_secret, session_version=current_version,
                user_id=user.id, user_session_version=user.session_version,
            )
        else:
            token = create_session_token(session_secret, session_version=current_version)
        response.set_cookie(
            SESSION_COOKIE_NAME, token, max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True, samesite="lax", secure=_request_is_https(request),
        )
        return {"status": "ok"}

    @router.post("/logout")
    async def logout(response: Response):
        response.delete_cookie(SESSION_COOKIE_NAME)
        return {"status": "ok"}

    @router.post("/change-password")
    async def change_password(body: PasswordChangeRequest, request: Request, response: Response):
        # F18: a password change is the clearest possible signal that any outstanding session
        # tokens — including a stolen cookie the admin doesn't know about — should stop working.
        # Bumping session_version invalidates every previously-issued token in one write.
        stored_hash = await settings_repo.get("admin_password_hash")
        if stored_hash is None:
            raise HTTPException(status_code=400, detail="setup has not been completed yet")

        # Same users-table-preferred / settings-fallback resolution as /login.
        user = await user_repo.get_by_username("admin") if user_repo is not None else None
        verify_against = user.password_hash if (user is not None and user.password_hash) else stored_hash

        loop = asyncio.get_running_loop()
        password_ok = await loop.run_in_executor(
            None, verify_password, body.current_password, verify_against
        )
        if not password_ok:
            raise HTTPException(status_code=401, detail="incorrect current password")
        if len(body.new_password) < 8:
            raise HTTPException(status_code=400, detail="password must be at least 8 characters")

        new_hash = await loop.run_in_executor(None, hash_password, body.new_password)
        # Global session_version bump keeps invalidating any outstanding LEGACY (user-less)
        # tokens, same as before the identity milestone. settings.admin_password_hash is kept
        # in sync too — it's the fallback read path require_admin/login use when `users` is
        # empty/absent, and this is the natural place to update it since it's already being
        # written for compatibility.
        new_version = await _current_session_version(settings_repo) + 1
        await settings_repo.set_many({
            "admin_password_hash": new_hash,
            "session_version": str(new_version),
        })

        new_user_version = DEFAULT_SESSION_VERSION
        user_id = None
        if user is not None:
            await user_repo.set_password_hash(user.id, new_hash)
            new_user_version = await user_repo.bump_session_version(user.id)
            user_id = user.id

        # Issue the caller a fresh, valid-under-the-new-version token so THEY aren't logged out
        # by their own password change — only every OTHER outstanding session is invalidated.
        session_secret = await settings_repo.get("session_secret")
        if session_secret is not None:
            token = create_session_token(
                session_secret, session_version=new_version,
                user_id=user_id, user_session_version=new_user_version,
            )
            response.set_cookie(
                SESSION_COOKIE_NAME, token, max_age=SESSION_MAX_AGE_SECONDS,
                httponly=True, samesite="lax", secure=_request_is_https(request),
            )
        return {"status": "ok"}

    @router.post("/logout-all")
    async def logout_all():
        # F18: explicit "invalidate every session, including this one" — bumps the version
        # without issuing a fresh token, unlike change-password's self-preserving bump.
        new_version = await _current_session_version(settings_repo) + 1
        await settings_repo.set("session_version", str(new_version))
        return {"status": "ok"}

    return router
