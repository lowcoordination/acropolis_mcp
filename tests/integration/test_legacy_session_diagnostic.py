"""Diagnostic for retiring the legacy user-less session auth path (issue #33).

The path being reported on (archon/admin_auth.py's path 3) exists so a partially-applied
upgrade degrades to "still works" rather than "locked out". It can only be deleted once no
user-less cookie can still verify — a DATA condition, which is what this endpoint answers.
"""

from __future__ import annotations

from db.repo import SettingsRepo


async def test_reports_not_retirable_before_a_retirement_bump(admin_client, app_env):
    """The default state for any existing deployment: users exist (the wizard ran), but nobody
    has bumped session_version to invalidate legacy cookies, so the path must stay."""
    resp = await admin_client.get("/api/v1/diagnostics/legacy-session")
    assert resp.status_code == 200
    body = resp.json()

    assert body["retirable"] is False
    assert body["user_count"] >= 1
    assert body["retired_at_session_version"] is None
    assert "has not been bumped" in body["reason"]


async def _relogin(app_env):
    """Re-authenticate after a session_version bump.

    Bumping session_version invalidates EVERY outstanding cookie including the test client's own
    — which is the whole mechanism that makes a surviving legacy cookie provably dead, so a test
    exercising the bumped state has to log in again afterwards rather than treat the logout as a
    surprise."""
    client = app_env.client()
    resp = await client.post(
        "/api/v1/login", json={"admin_password": "test-admin-password-1"}
    )
    assert resp.status_code == 200, f"re-login failed: {resp.text}"
    return client


async def test_reports_retirable_once_bumped_and_recorded(admin_client, app_env):
    """The condition that actually makes the path unreachable: a session_version bump recorded
    as the retirement point, so every cookie predating it is invalid."""
    settings_repo = SettingsRepo(app_env.db)
    stored = await settings_repo.get("session_version")
    current = int(stored) if stored is not None else 0

    await settings_repo.set("session_version", str(current + 1))
    await settings_repo.set("legacy_session_retired_at_version", str(current + 1))

    client = await _relogin(app_env)
    try:
        resp = await client.get("/api/v1/diagnostics/legacy-session")
        body = resp.json()
    finally:
        await client.aclose()

    assert body["retirable"] is True
    assert body["session_version"] == current + 1
    assert body["retired_at_session_version"] == current + 1
    assert "safe to remove" in body["reason"]


async def test_rolled_back_session_version_is_not_retirable(admin_client, app_env):
    """A session_version BELOW the recorded retirement bump means the bump was rolled back —
    cookies it invalidated would verify again, so the path is not safe to remove. Catching this
    is the point of recording the bump rather than just checking "is the version > 0"."""
    settings_repo = SettingsRepo(app_env.db)
    await settings_repo.set("legacy_session_retired_at_version", "5")
    await settings_repo.set("session_version", "3")

    client = await _relogin(app_env)
    try:
        resp = await client.get("/api/v1/diagnostics/legacy-session")
        body = resp.json()
    finally:
        await client.aclose()

    assert body["retirable"] is False
    assert "rolled back" in body["reason"]


async def test_requires_authentication(admin_client, app_env):
    """Admin-only: it discloses whether an auth fallback is live.

    Takes `admin_client` purely to force the first-run wizard to have completed — without it,
    require_admin's path 4 ("no admin configured yet") legitimately admits everyone, and this
    would assert the wrong thing about a window that is open by design."""
    async with app_env.client() as anon:
        resp = await anon.get("/api/v1/diagnostics/legacy-session")
    assert resp.status_code == 401


async def test_does_not_mutate_session_version(admin_client, app_env):
    """A GET must not invalidate every session in the fleet as a side effect — bumping is the
    operator's explicit step, not something a diagnostic does for them."""
    settings_repo = SettingsRepo(app_env.db)
    before = await settings_repo.get("session_version")

    await admin_client.get("/api/v1/diagnostics/legacy-session")
    await admin_client.get("/api/v1/diagnostics/legacy-session")

    assert await settings_repo.get("session_version") == before
