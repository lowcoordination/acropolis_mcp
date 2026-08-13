"""Legacy user-less session auth path — retired (issue #33, R6).

archon/admin_auth.py's former path 3 (a session cookie carrying no user_id, verified against
the legacy admin_password_hash session_secret/session_version) has been removed. No argus
deployment ever ran with real users through the identity-migration boundary, so the condition
that path existed for never occurred — see Principal's docstring in archon/admin_auth.py.

GET /api/v1/diagnostics/legacy-session is kept as a historical record and regression tripwire
rather than deleted; it always reports retirable=True now. These tests cover both: the endpoint
reporting the retired state, and the underlying auth path actually being gone (the thing that
matters — a passing diagnostic that lied would be worse than no diagnostic at all).
"""

from __future__ import annotations

from db.repo import SettingsRepo


async def test_diagnostic_always_reports_retired(admin_client, app_env):
    resp = await admin_client.get("/api/v1/diagnostics/legacy-session")
    assert resp.status_code == 200
    body = resp.json()

    assert body["retirable"] is True
    assert body["user_count"] >= 1
    assert "REMOVED" in body["reason"]


async def test_diagnostic_reports_retired_regardless_of_session_version_state(admin_client, app_env):
    """The endpoint used to gate `retirable` on session_version vs. a recorded retirement bump.
    That logic is gone: the path itself is removed, so no session_version state can make it
    reachable again. Proves the response doesn't accidentally still depend on those settings."""
    settings_repo = SettingsRepo(app_env.db)
    await settings_repo.set("session_version", "0")
    await settings_repo.set("legacy_session_retired_at_version", "99")  # nonsensical: > current

    resp = await admin_client.get("/api/v1/diagnostics/legacy-session")
    assert resp.json()["retirable"] is True


async def test_requires_authentication(admin_client, app_env):
    """Admin-only: it discloses auth-path history.

    Takes `admin_client` purely to force the first-run wizard to have completed — without it,
    require_admin's first-run window legitimately admits everyone, and this would assert the
    wrong thing about a window that is open by design."""
    async with app_env.client() as anon:
        resp = await anon.get("/api/v1/diagnostics/legacy-session")
    assert resp.status_code == 401


async def test_does_not_mutate_session_version(admin_client, app_env):
    """A GET must not invalidate every session in the fleet as a side effect."""
    settings_repo = SettingsRepo(app_env.db)
    before = await settings_repo.get("session_version")

    await admin_client.get("/api/v1/diagnostics/legacy-session")
    await admin_client.get("/api/v1/diagnostics/legacy-session")

    assert await settings_repo.get("session_version") == before


async def test_user_less_session_cookie_is_rejected(admin_client, app_env):
    """The thing that actually matters: a session cookie carrying no user_id, correctly signed,
    is rejected by require_admin. This is the real proof of retirement — the diagnostic above
    reports on this fact, but this test verifies the fact itself, independent of whether the
    diagnostic's own logic is right.

    See tests/integration/test_identity.py::
    test_legacy_user_less_session_is_rejected_post_retirement for the full end-to-end version
    (hand-crafted session_secret, admin_password_hash set, no users row) — this one exercises
    it through the ordinary app_env/admin_client fixtures for a quicker, complementary check."""
    from archon.sessions import DEFAULT_SESSION_VERSION, SESSION_COOKIE_NAME, create_session_token

    settings_repo = SettingsRepo(app_env.db)
    session_secret = await settings_repo.get("session_secret")
    assert session_secret is not None, "admin_client fixture should have completed setup"

    stored_version = await settings_repo.get("session_version")
    version = int(stored_version) if stored_version is not None else DEFAULT_SESSION_VERSION

    user_less_token = create_session_token(
        session_secret, session_version=version, user_id=None,
        user_session_version=DEFAULT_SESSION_VERSION,
    )

    async with app_env.client() as client:
        client.cookies.set(SESSION_COOKIE_NAME, user_less_token)
        resp = await client.get("/api/v1/servers")

    assert resp.status_code == 401, "a correctly-signed but user-id-less cookie must be rejected"
