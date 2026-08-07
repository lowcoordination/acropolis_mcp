from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from archon.oidc import (
    AttemptStore,
    OidcCallbackError,
    OidcConfigError,
    OidcSettings,
    build_authorization_url,
    check_jit_allowlist,
    decode_id_token_unverified,
    discover,
    exchange_code,
    map_group_to_role,
    validate_id_token_claims,
)
from archon.passwords import hash_password, verify_password
from archon.schemas import (
    LoginRequest,
    OidcStatusResponse,
    PasswordChangeRequest,
    SetupRequest,
    SetupStatusResponse,
)
from archon.sessions import (
    DEFAULT_SESSION_VERSION,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    create_session_token,
    decode_session_payload,
)
from db.repo import SettingsRepo, UserRepo

_logger = logging.getLogger("archon.setup")

# F16 fix (review 2026-08-04): no throttling existed on /login or /setup at all. PBKDF2-SHA256
# at 600k iterations costs ~67ms/attempt — correct, OWASP-compliant work, but with no lockout it
# still permits ~15 guesses/sec sustained against an 8-character-minimum password that is the
# SOLE credential for the entire gateway. Per-source-IP token bucket, reusing the same
# RateLimiterRegistry the data plane already uses. Generous enough not to lock out a legitimate
# admin who mistypes a password a few times, tight enough to make sustained guessing impractical.
_LOGIN_RATE_LIMIT_SPEC = "10/minute"

# Bug-fix follow-up (coordinator review of PR #16, 2026-08-07): a correctly-formatted-but-
# unrelated hash for the "no such user" timing-safety branch in /login below. Generated once at
# import time via the real hash_password() (not hand-written) so it has the exact same
# iteration count and format as a genuine stored hash — verify_password against it costs the
# same ~67ms PBKDF2 work as a real wrong-password check, which is the property that actually
# matters here (constant password, not secret; this is not a credential).
_DUMMY_HASH_FOR_TIMING = hash_password("not-a-real-account-timing-decoy")


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
    http_client: Optional[httpx.AsyncClient] = None,
    oidc_attempts: Optional[AttemptStore] = None,
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

        # Bug fix (found in coordinator review of PR #16, 2026-08-07): this used to hardcode
        # user_repo.get_by_username("admin") regardless of body.username (which didn't even
        # exist as a field) -- ANY locally-created operator/viewer user was silently checked
        # against the ADMIN's password hash and could never log in. Fixed to resolve by
        # body.username. The legacy settings.admin_password_hash fallback is now scoped
        # specifically to username == "admin" with no matching users-table row -- that's the
        # exact partial-migration case 0007_users.sql's non-negotiable ("partial upgrade
        # degrades to still works") is about, and it must NOT silently extend to every other
        # username (a request for a NONEXISTENT non-admin username has no business succeeding
        # against the admin's hash just because verify_against would otherwise be undefined).
        user = await user_repo.get_by_username(body.username) if user_repo is not None else None
        if user is not None:
            verify_against = user.password_hash
        elif body.username == "admin":
            verify_against = stored_hash
        else:
            verify_against = None

        if verify_against is None:
            # No such user AND not the legacy-fallback-eligible "admin" case. Still run a dummy
            # verify_password call against a syntactically-valid-but-unrelated hash so this
            # branch takes roughly the same time as a real failed check — a login endpoint that
            # returns instantly for "unknown username" and slowly for "wrong password" leaks
            # username validity via timing.
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, verify_password, body.admin_password, _DUMMY_HASH_FOR_TIMING)
            raise HTTPException(status_code=401, detail="incorrect password")

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

        # Bug fix (found alongside the /login fix, coordinator review of PR #16, 2026-08-07):
        # this had the SAME hardcoded-to-"admin" bug as /login, but for a different underlying
        # reason -- this route is deliberately NOT behind require_admin (its security model is
        # "knowing the current password IS the proof of identity," same as it always was for
        # the single-admin flow), so there was never a Principal to read a real username from.
        # Now: if a session cookie is present, resolve the CALLER'S OWN user_id from it
        # (best-effort, not a hard auth requirement — a forged/expired cookie just means we
        # fall through to the legacy admin-only path below, same as no cookie at all) and change
        # THEIR password. A caller with no session cookie (or one carrying no user_id) is
        # assumed to be the legacy single admin, exactly as before this identity milestone.
        user = None
        if user_repo is not None:
            cookie = request.cookies.get(SESSION_COOKIE_NAME)
            payload = decode_session_payload(cookie) if cookie else None
            cookie_user_id = payload.get("user_id") if payload else None
            if cookie_user_id is not None:
                try:
                    user = await user_repo.get_by_id(int(cookie_user_id))
                except Exception:
                    user = None
            else:
                user = await user_repo.get_by_username("admin")
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
        # tokens, same as before the identity milestone.
        new_version = await _current_session_version(settings_repo) + 1
        settings_updates = {"session_version": str(new_version)}
        if user is None or user.username == "admin":
            # settings.admin_password_hash is kept in sync ONLY when the admin's own password
            # is what changed — it's the fallback read path require_admin/login use when
            # `users` is empty/absent, and must keep reflecting the admin account specifically,
            # not whichever non-admin user happened to call this route.
            settings_updates["admin_password_hash"] = new_hash
        await settings_repo.set_many(settings_updates)

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

    # --- OIDC (enterprise #1) --- deliberately NOT behind require_admin: /auth/oidc/login is
    # how a not-yet-authenticated browser starts the flow, and /auth/oidc/callback is where the
    # IdP redirects an equally not-yet-authenticated browser back to. Both are registered only
    # when the pieces they need (user_repo, http_client, oidc_attempts) were actually wired in —
    # tests constructing this router directly for local-auth-only coverage are unaffected.
    if user_repo is not None and http_client is not None and oidc_attempts is not None:

        async def _load_oidc_settings() -> OidcSettings:
            values = await settings_repo.get_all()
            try:
                oidc_settings = OidcSettings.from_settings_dict(values)
            except OidcConfigError as e:
                raise HTTPException(status_code=500, detail=str(e))
            if oidc_settings is None:
                raise HTTPException(status_code=404, detail="OIDC is not configured")
            return oidc_settings

        @router.get("/auth/oidc/status", response_model=OidcStatusResponse)
        async def oidc_status():
            values = await settings_repo.get_all()
            try:
                oidc_settings = OidcSettings.from_settings_dict(values)
            except OidcConfigError:
                # Misconfigured (enabled=true but incomplete) reads as "not available" to an
                # unauthenticated caller — the real error is only surfaced to whoever tries to
                # actually start the flow, and belongs in server logs, not a public status probe.
                return OidcStatusResponse(enabled=False)
            if oidc_settings is None:
                return OidcStatusResponse(enabled=False)
            return OidcStatusResponse(enabled=True, login_url="/api/v1/auth/oidc/login")

        @router.get("/auth/oidc/login")
        async def oidc_login():
            oidc_settings = await _load_oidc_settings()
            try:
                discovery_doc = await discover(oidc_settings.issuer, http_client)
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {e}")

            authorization_endpoint = discovery_doc.get("authorization_endpoint")
            if not authorization_endpoint:
                raise HTTPException(
                    status_code=502, detail="OIDC discovery document missing authorization_endpoint"
                )

            attempt = oidc_attempts.create()
            url = build_authorization_url(
                authorization_endpoint=authorization_endpoint,
                client_id=oidc_settings.client_id,
                redirect_uri=oidc_settings.redirect_uri,
                scopes=oidc_settings.scopes,
                state=attempt.state,
                nonce=attempt.nonce,
                code_verifier=attempt.code_verifier,
            )
            return RedirectResponse(url, status_code=302)

        @router.get("/auth/oidc/callback")
        async def oidc_callback(
            request: Request, response: Response,
            code: Optional[str] = None, state: Optional[str] = None,
            error: Optional[str] = None, error_description: Optional[str] = None,
        ):
            if error:
                raise HTTPException(
                    status_code=400, detail=f"OIDC provider returned an error: {error} ({error_description})"
                )
            if not code or not state:
                raise HTTPException(status_code=400, detail="missing code or state")

            # Single-use lookup: `pop` removes the attempt regardless of outcome, so the same
            # state value can never be replayed against a second callback (session-fixation /
            # replay guard).
            attempt = oidc_attempts.pop(state)
            if attempt is None:
                raise HTTPException(status_code=400, detail="unknown or expired state")

            oidc_settings = await _load_oidc_settings()
            try:
                discovery_doc = await discover(oidc_settings.issuer, http_client)
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {e}")
            token_endpoint = discovery_doc.get("token_endpoint")
            if not token_endpoint:
                raise HTTPException(
                    status_code=502, detail="OIDC discovery document missing token_endpoint"
                )

            try:
                tokens = await exchange_code(
                    token_endpoint=token_endpoint, client_id=oidc_settings.client_id,
                    client_secret=oidc_settings.client_secret, redirect_uri=oidc_settings.redirect_uri,
                    code=code, code_verifier=attempt.code_verifier, http_client=http_client,
                )
            except httpx.HTTPStatusError as e:
                _logger.warning("OIDC token exchange failed: %s", e)
                raise HTTPException(status_code=400, detail="OIDC token exchange failed")
            except httpx.HTTPError as e:
                raise HTTPException(status_code=502, detail=f"OIDC token exchange failed: {e}")

            id_token = tokens.get("id_token")
            if not id_token:
                raise HTTPException(status_code=502, detail="OIDC token response missing id_token")

            try:
                claims = decode_id_token_unverified(id_token)
                # Security-scan fix: aud/iss hygiene, defense in depth on top of the PKCE +
                # client_secret exchange that's the actual security boundary for this flow (see
                # validate_id_token_claims's own docstring for why this isn't load-bearing but
                # is still worth doing).
                validate_id_token_claims(
                    claims=claims, oidc_settings=oidc_settings,
                    issuer_claim=discovery_doc.get("issuer"),
                )
            except OidcCallbackError as e:
                raise HTTPException(status_code=400, detail=str(e))

            # Nonce validation: the value embedded in the ID token must match the one THIS
            # server generated for THIS attempt — this is what stops a replayed/substituted ID
            # token (e.g. one obtained via a different, attacker-initiated flow) from being
            # accepted as if it belonged to this browser's login.
            if claims.get("nonce") != attempt.nonce:
                raise HTTPException(status_code=400, detail="nonce mismatch")

            subject = claims.get("sub")
            if not subject or not isinstance(subject, str):
                raise HTTPException(status_code=400, detail="id_token missing sub claim")

            existing = await user_repo.get_by_subject(subject)
            if existing is None:
                if not oidc_settings.jit_provisioning:
                    raise HTTPException(
                        status_code=403,
                        detail="no local account for this identity and JIT provisioning is disabled",
                    )
                try:
                    check_jit_allowlist(claims=claims, oidc_settings=oidc_settings)
                except OidcCallbackError as e:
                    raise HTTPException(status_code=403, detail=str(e))
                role = map_group_to_role(claims=claims, oidc_settings=oidc_settings)
                user = await user_repo.get_or_create_from_oidc(
                    subject=subject, email=claims.get("email"), default_role=role,
                    preferred_username=claims.get("preferred_username"),
                )
            else:
                user = existing

            if not user.enabled:
                raise HTTPException(status_code=401, detail="account disabled")

            session_secret = await settings_repo.get("session_secret")
            if session_secret is None:
                raise HTTPException(status_code=500, detail="server misconfigured: no session secret")

            await user_repo.touch_last_login(user.id)
            current_version = await _current_session_version(settings_repo)
            token = create_session_token(
                session_secret, session_version=current_version,
                user_id=user.id, user_session_version=user.session_version,
            )
            response = RedirectResponse("/", status_code=302)
            response.set_cookie(
                SESSION_COOKIE_NAME, token, max_age=SESSION_MAX_AGE_SECONDS,
                httponly=True, samesite="lax", secure=_request_is_https(request),
            )
            return response

    return router
