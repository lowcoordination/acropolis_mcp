"""End-to-end tests for the first-run setup / login / session-cookie flow."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database


pytestmark = pytest.mark.parametrize("app_env", [{"probe_on_create": False}], indirect=True)


async def test_setup_status_initially_incomplete(api_client):
    resp = await api_client.get("/api/v1/setup/status")
    assert resp.status_code == 200
    assert resp.json()["setup_complete"] is False


async def test_before_setup_control_plane_is_open(api_client):
    # No admin configured yet, no admin_token — the narrow "open until wizard runs" window.
    resp = await api_client.get("/api/v1/servers")
    assert resp.status_code == 200


async def test_complete_setup_sets_cookie_and_marks_complete(api_client):
    resp = await api_client.post("/api/v1/setup", json={"admin_password": "hunter22", "auth_mode": "keyed"})
    assert resp.status_code == 200
    assert resp.json()["setup_complete"] is True
    assert "acropolis_session" in resp.cookies

    status = await api_client.get("/api/v1/setup/status")
    assert status.json()["setup_complete"] is True


def _cookie_attrs(resp: httpx.Response, name: str) -> str:
    """httpx's cookie jar doesn't expose flags like HttpOnly/Secure — read the raw
    Set-Cookie header instead."""
    raw = resp.headers.get("set-cookie", "")
    assert name in raw, f"{name} not found in Set-Cookie: {raw!r}"
    return raw


async def test_session_cookie_is_httponly_and_samesite_lax(api_client):
    resp = await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    raw = _cookie_attrs(resp, "acropolis_session")
    assert "httponly" in raw.lower()
    assert "samesite=lax" in raw.lower()


async def test_session_cookie_is_not_secure_over_plain_http(api_client):
    # The quickstart's default flow is docker compose up -> http://localhost:8000 — the
    # cookie must NOT carry Secure here, or the browser would silently refuse to send it
    # back on the very next request and nobody could ever log in.
    resp = await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    raw = _cookie_attrs(resp, "acropolis_session")
    assert "secure" not in raw.lower()


async def test_session_cookie_is_secure_behind_a_tls_terminating_proxy(api_client):
    # Simulates the documented reverse-proxy setup (docs/tls-and-reverse-proxy.md): Acropolis
    # itself only ever speaks plain HTTP, so the proxy is the only thing that can tell it
    # the original request arrived over HTTPS, via X-Forwarded-Proto.
    resp = await api_client.post(
        "/api/v1/setup", json={"admin_password": "hunter22"},
        headers={"X-Forwarded-Proto": "https"},
    )
    raw = _cookie_attrs(resp, "acropolis_session")
    assert "secure" in raw.lower()


async def test_setup_rejects_short_password(api_client):
    resp = await api_client.post("/api/v1/setup", json={"admin_password": "short"})
    assert resp.status_code == 400


async def test_setup_cannot_run_twice(api_client):
    await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    resp = await api_client.post("/api/v1/setup", json={"admin_password": "different-pass"})
    assert resp.status_code == 409


async def test_after_setup_control_plane_requires_auth(api_client, app_env):
    await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    # A fresh client (no cookie jar carried over) should be rejected now.
    async with app_env.client() as fresh:
        resp = await fresh.get("/api/v1/servers")
        assert resp.status_code == 401


async def test_health_endpoint_reachable_unauthenticated_after_setup(api_client, app_env):
    """F21 regression (review 2026-08-04): /api/v1/health used to live behind require_admin.
    Empirically confirmed against a real container: it returned 200 unauthenticated BEFORE
    setup and 401 AFTER — exactly backwards from what the Dockerfile HEALTHCHECK and k8s
    liveness/readiness probes need, since they run continuously and specifically need it to
    keep working once the gateway is actually configured and in real use. The k8s
    livenessProbe (periodSeconds=30, failureThreshold=3) kills the pod ~90s after setup
    completes, and CrashLoopBackOffs indefinitely from there."""
    await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    async with app_env.client() as fresh:
        resp = await fresh.get("/api/v1/health")
        assert resp.status_code == 200, (
            f"health check must stay reachable with NO credentials even after setup "
            f"completes, got {resp.status_code}"
        )
        assert resp.json() == {"status": "ok"}


async def test_session_cookie_grants_access_after_setup(api_client):
    setup_resp = await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    assert setup_resp.status_code == 200
    # httpx.AsyncClient persists cookies across requests on the same client automatically.
    resp = await api_client.get("/api/v1/servers")
    assert resp.status_code == 200


async def test_login_with_correct_password_grants_session(api_client, app_env):
    await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})

    async with app_env.client() as fresh:
        login = await fresh.post("/api/v1/login", json={"admin_password": "hunter22"})
        assert login.status_code == 200
        assert "acropolis_session" in login.cookies

        resp = await fresh.get("/api/v1/servers")
        assert resp.status_code == 200


async def test_login_with_wrong_password_rejected(api_client, app_env):
    await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})

    async with app_env.client() as fresh:
        login = await fresh.post("/api/v1/login", json={"admin_password": "wrong-password"})
        assert login.status_code == 401


async def test_login_before_setup_rejected(api_client):
    resp = await api_client.post("/api/v1/login", json={"admin_password": "anything"})
    assert resp.status_code == 400


async def test_login_rate_limited_after_repeated_wrong_passwords(api_client, app_env):
    """F16 regression (review 2026-08-04): /login had NO throttling at all — an unthrottled
    single-password login guarding the sole credential for the entire gateway. This fires more
    than the configured bucket size (10/minute) of wrong-password attempts and asserts a 429
    eventually replaces the 401s, proving the rate limiter is actually wired into this route."""
    await api_client.post("/api/v1/setup", json={"admin_password": "correct-horse-battery"})

    statuses = []
    async with app_env.client() as fresh:
        for _ in range(15):
            resp = await fresh.post("/api/v1/login", json={"admin_password": "wrong"})
            statuses.append(resp.status_code)

        assert 401 in statuses, "expected some wrong-password attempts to be rejected normally"
        assert 429 in statuses, (
            "expected the login rate limiter to kick in after repeated attempts — got: " + str(statuses)
        )
        # Once rate-limited, the correct password must ALSO be rejected (429, not 200) — the
        # limit gates the endpoint, not just wrong-password guesses, which is what makes it
        # effective against a credential-stuffing style attack.
        final = await fresh.post("/api/v1/login", json={"admin_password": "correct-horse-battery"})
        assert final.status_code == 429


async def test_logout_clears_session(api_client):
    await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    assert (await api_client.get("/api/v1/servers")).status_code == 200

    logout = await api_client.post("/api/v1/logout")
    assert logout.status_code == 200

    resp = await api_client.get("/api/v1/servers")
    assert resp.status_code == 401


async def test_logout_all_invalidates_a_different_sessions_cookie(api_client, app_env):
    """F18 regression (review 2026-08-04): pre-fix, POST /logout only cleared the CALLER's
    cookie — the token itself stayed cryptographically valid server-side for its full 7 days.
    A stolen cookie could not be invalidated short of hand-editing the settings table. This is
    the actual security property F18 buys: revoking a session another client is still holding."""
    setup = await api_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    stolen_cookie = setup.cookies.get("acropolis_session")
    assert stolen_cookie is not None

    # A second, independent client presenting the SAME cookie value — simulating an attacker
    # who exfiltrated it via some other means (this is what F1/F5 in Plan 1 closed off, but the
    # cookie could leak via other channels too — this test is specifically about revocation).
    async with httpx.AsyncClient(
        transport=app_env.transport, base_url="http://argus.test", cookies={"acropolis_session": stolen_cookie},
    ) as attacker:
        assert (await attacker.get("/api/v1/servers")).status_code == 200  # cookie is valid

        # The real admin invalidates every outstanding session, including their own.
        revoke = await api_client.post("/api/v1/logout-all")
        assert revoke.status_code == 200

        # The stolen cookie — same bytes, never touched — is now rejected.
        assert (await attacker.get("/api/v1/servers")).status_code == 401


async def test_change_password_invalidates_other_sessions_but_not_the_caller(api_client, app_env):
    """F18: change-password bumps session_version (revoking every OTHER outstanding session)
    but issues the caller a fresh token at the new version, so changing your own password
    doesn't lock yourself out."""
    await api_client.post("/api/v1/setup", json={"admin_password": "old-password-123"})
    original_cookie = api_client.cookies.get("acropolis_session")

    resp = await api_client.post(
        "/api/v1/change-password",
        json={"current_password": "old-password-123", "new_password": "new-password-456"},
    )
    assert resp.status_code == 200

    # The caller's own client (httpx auto-updates its cookie jar from Set-Cookie) still works.
    assert (await api_client.get("/api/v1/servers")).status_code == 200

    # A DIFFERENT client holding the pre-change cookie is now rejected.
    async with httpx.AsyncClient(
        transport=app_env.transport, base_url="http://argus.test", cookies={"acropolis_session": original_cookie},
    ) as other:
        assert (await other.get("/api/v1/servers")).status_code == 401

    # The new password logs in fine; the old one is rejected.
    async with app_env.client() as fresh:
        assert (await fresh.post("/api/v1/login", json={"admin_password": "old-password-123"})).status_code == 401
        assert (await fresh.post("/api/v1/login", json={"admin_password": "new-password-456"})).status_code == 200


async def test_change_password_rejects_wrong_current_password(api_client):
    await api_client.post("/api/v1/setup", json={"admin_password": "correct-current"})
    resp = await api_client.post(
        "/api/v1/change-password",
        json={"current_password": "wrong-current", "new_password": "new-password-456"},
    )
    assert resp.status_code == 401
