"""OIDC (Authorization Code + PKCE) tests — enterprise #1.

No real IdP is available in this environment (no local Keycloak/Authentik container), so these
tests exercise the flow against a MOCKED IdP built with httpx.MockTransport (an established
pattern in this codebase — see tests/integration/test_bridge.py, tests/unit/test_upstream.py).
The mock serves a real `.well-known/openid-configuration` document, a real token endpoint, and
constructs real (unsigned-appropriate-for-this-flow, per archon/oidc.py's own documented
reasoning) ID tokens, so the actual PKCE/state/nonce/allowlist code under test never knows it
isn't talking to a real provider.

What this proves: the OIDC handshake logic itself (state, nonce, PKCE, redirect_uri handling,
JIT allowlist, sub-based identity) is correct. What it CANNOT prove: interop with any specific
real-world IdP's exact response shape/quirks (Okta, Entra, Google, Keycloak, Authentik all differ
slightly). That gap is called out explicitly in the PR description.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from archon.oidc import AttemptStore
from archon.setup import build_setup_router
from db.database import Database
from db.repo import SettingsRepo, UserRepo

_ISSUER = "https://idp.test"
_CLIENT_ID = "acropolis-client"
_CLIENT_SECRET = "acropolis-secret"
_REDIRECT_URI = "http://argus.test/api/v1/auth/oidc/callback"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _fake_id_token(*, sub: str, nonce: str, email: Optional[str] = None, groups: Optional[list[str]] = None) -> str:
    """An unsigned-but-correctly-shaped JWT. archon/oidc.py's decode_id_token_unverified()
    deliberately does not check the signature for THIS flow (see its docstring) — the header/
    signature segments just need to be base64 segments, not a valid signature."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    claims = {"sub": sub, "nonce": nonce, "aud": _CLIENT_ID, "iss": _ISSUER}
    if email:
        claims["email"] = email
    if groups is not None:
        claims["groups"] = groups
    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.fakesig"


class MockIdp:
    """Stateful mock: records the last authorization request's params so the token endpoint can
    mint an ID token whose `nonce` matches whatever the client actually sent — a real IdP does
    exactly this (nonce round-trips through it), so the mock must too for the nonce-validation
    test to mean anything."""

    def __init__(self):
        self.last_nonce: Optional[str] = None
        self.next_sub = "idp-subject-123"
        self.next_email: Optional[str] = "person@example.com"
        self.next_groups: Optional[list[str]] = None
        self.corrupt_nonce = False
        self.fail_token_exchange = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "authorization_endpoint": f"{_ISSUER}/authorize",
                "token_endpoint": f"{_ISSUER}/token",
                "issuer": _ISSUER,
            })
        if path == "/token":
            if self.fail_token_exchange:
                return httpx.Response(400, json={"error": "invalid_grant"})
            form = dict(parse_qs(request.content.decode()))
            # parse_qs returns lists; flatten single values.
            form = {k: v[0] for k, v in form.items()}
            assert form.get("grant_type") == "authorization_code"
            assert form.get("redirect_uri") == _REDIRECT_URI
            assert form.get("client_id") == _CLIENT_ID
            assert form.get("client_secret") == _CLIENT_SECRET
            assert "code_verifier" in form
            nonce = self.last_nonce if not self.corrupt_nonce else "wrong-nonce"
            id_token = _fake_id_token(
                sub=self.next_sub, nonce=nonce, email=self.next_email, groups=self.next_groups,
            )
            return httpx.Response(200, json={
                "access_token": "fake-access-token", "id_token": id_token, "token_type": "Bearer",
            })
        return httpx.Response(404)


@pytest.fixture
async def oidc_env(tmp_path: Path):
    """A minimal FastAPI app wrapping ONLY archon.setup's router, wired with a mocked IdP
    http_client — this exercises the exact route handlers used in production without going
    through create_app()'s real httpx.AsyncClient (which has no injection point for a mock
    transport)."""
    db = Database(tmp_path)
    await db.connect()
    settings_repo = SettingsRepo(db)
    user_repo = UserRepo(db)

    idp = MockIdp()
    mock_transport = httpx.MockTransport(idp.handler)
    http_client = httpx.AsyncClient(transport=mock_transport)
    oidc_attempts = AttemptStore()

    await settings_repo.set_many({
        "admin_password_hash": "unused-placeholder-hash",
        "session_secret": "test-session-secret-for-oidc",
        "oidc_enabled": "true",
        "oidc_issuer": _ISSUER,
        "oidc_client_id": _CLIENT_ID,
        "oidc_client_secret": _CLIENT_SECRET,
        "oidc_redirect_uri": _REDIRECT_URI,
    })

    router = build_setup_router(settings_repo, None, user_repo, http_client, oidc_attempts)
    app = FastAPI()
    app.include_router(router)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test", follow_redirects=False) as client:
        yield client, idp, settings_repo, user_repo

    await http_client.aclose()
    await db.close()


async def _start_login_and_capture_state(client: httpx.AsyncClient) -> tuple[str, str]:
    """Follows /auth/oidc/login, returns (state, nonce) parsed out of the redirect URL — the
    test acts as the browser that would otherwise carry these round-trip through the IdP."""
    resp = await client.get("/api/v1/auth/oidc/login")
    assert resp.status_code == 302
    location = resp.headers["location"]
    qs = parse_qs(urlparse(location).query)
    assert qs["response_type"] == ["code"]
    assert qs["code_challenge_method"] == ["S256"]
    return qs["state"][0], qs["nonce"][0]


async def test_oidc_status_reports_enabled(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    resp = await client.get("/api/v1/auth/oidc/status")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True


async def test_oidc_status_reports_disabled_when_unconfigured(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    settings_repo = SettingsRepo(db)
    user_repo = UserRepo(db)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    router = build_setup_router(settings_repo, None, user_repo, http_client, AttemptStore())
    app = FastAPI()
    app.include_router(router)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        resp = await client.get("/api/v1/auth/oidc/status")
        assert resp.json()["enabled"] is False
    await http_client.aclose()
    await db.close()


async def test_full_login_flow_creates_user_and_session(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    idp.next_sub = "sub-alice"
    idp.next_email = "alice@example.com"

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce

    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 302
    assert "acropolis_session" in resp.cookies

    user = await user_repo.get_by_subject("sub-alice")
    assert user is not None
    assert user.auth_source == "oidc"
    assert user.email == "alice@example.com"


async def test_state_mismatch_rejected(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce

    resp = await client.get(
        "/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": "totally-different-state"}
    )
    assert resp.status_code == 400
    assert "state" in resp.json()["detail"].lower()


async def test_nonce_mismatch_rejected(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    idp.corrupt_nonce = True
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce  # ignored by the mock when corrupt_nonce=True

    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 400
    assert "nonce" in resp.json()["detail"].lower()


async def test_state_is_single_use(oidc_env):
    """A replayed state (same value, second callback) must be rejected — proves AttemptStore.pop
    actually consumes the attempt rather than merely reading it."""
    client, idp, settings_repo, user_repo = oidc_env
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce

    first = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert first.status_code == 302

    replay = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert replay.status_code == 400
    assert "state" in replay.json()["detail"].lower()


async def test_redirect_uri_is_never_taken_from_the_request(oidc_env):
    """Open-redirect guard: nothing in the callback request can influence what redirect_uri is
    sent to the token endpoint — it's always the admin-configured settings value. The mock IdP's
    token handler itself asserts redirect_uri == _REDIRECT_URI (see MockIdp.handler); this test
    additionally proves a client-supplied redirect_uri-shaped param is simply ignored rather
    than erroring, since the route doesn't even accept one."""
    client, idp, settings_repo, user_repo = oidc_env
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce

    resp = await client.get(
        "/api/v1/auth/oidc/callback",
        params={
            "code": "auth-code-1", "state": state,
            "redirect_uri": "https://attacker.example/steal",
        },
    )
    # Succeeds normally — the attacker-supplied redirect_uri param is simply not a field this
    # route reads; MockIdp.handler's own assertion (redirect_uri == _REDIRECT_URI) is what
    # actually proves it was never forwarded to the token endpoint.
    assert resp.status_code == 302


async def test_unknown_subject_rejected_when_jit_disabled(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    await settings_repo.set("oidc_jit_provisioning", "false")
    idp.next_sub = "brand-new-subject"

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 403


async def test_jit_provisioning_denied_outside_domain_allowlist(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    await settings_repo.set("oidc_allowed_domains", "trusted-corp.example")
    idp.next_sub = "outsider-subject"
    idp.next_email = "person@untrusted.example"

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 403

    assert await user_repo.get_by_subject("outsider-subject") is None


async def test_jit_provisioning_allowed_within_domain_allowlist(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    await settings_repo.set("oidc_allowed_domains", "trusted-corp.example")
    idp.next_sub = "insider-subject"
    idp.next_email = "person@trusted-corp.example"

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 302

    assert await user_repo.get_by_subject("insider-subject") is not None


async def test_two_users_same_email_different_subject_resolve_to_different_accounts(oidc_env):
    """Keyed on sub, never email — an IdP that (mis)allows email reuse across two distinct
    accounts must still produce two distinct local users, not a silent merge/takeover."""
    client, idp, settings_repo, user_repo = oidc_env

    idp.next_sub = "subject-one"
    idp.next_email = "shared@example.com"
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp1 = await client.get("/api/v1/auth/oidc/callback", params={"code": "code-1", "state": state})
    assert resp1.status_code == 302

    idp.next_sub = "subject-two"
    idp.next_email = "shared@example.com"
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp2 = await client.get("/api/v1/auth/oidc/callback", params={"code": "code-2", "state": state})
    assert resp2.status_code == 302

    user1 = await user_repo.get_by_subject("subject-one")
    user2 = await user_repo.get_by_subject("subject-two")
    assert user1 is not None and user2 is not None
    assert user1.id != user2.id
    assert user1.email == user2.email == "shared@example.com"
    # Usernames must have been disambiguated rather than colliding/overwriting.
    assert user1.username != user2.username


async def test_group_claim_maps_to_role(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    await settings_repo.set("oidc_group_claim", "groups")
    idp.next_sub = "operator-subject"
    idp.next_groups = ["some-other-group", "operator"]

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 302

    user = await user_repo.get_by_subject("operator-subject")
    assert user.role == "operator"


async def test_existing_oidc_user_reauthenticates_without_reprovisioning(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    idp.next_sub = "returning-subject"
    idp.next_email = "returning@example.com"

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    await client.get("/api/v1/auth/oidc/callback", params={"code": "code-a", "state": state})
    first_user = await user_repo.get_by_subject("returning-subject")

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "code-b", "state": state})
    assert resp.status_code == 302
    second_user = await user_repo.get_by_subject("returning-subject")
    assert first_user.id == second_user.id


async def test_disabled_oidc_user_rejected_at_callback(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    idp.next_sub = "to-be-disabled"

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    await client.get("/api/v1/auth/oidc/callback", params={"code": "code-a", "state": state})
    user = await user_repo.get_by_subject("to-be-disabled")
    await user_repo.set_enabled(user.id, False)

    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "code-b", "state": state})
    assert resp.status_code == 401


async def test_token_exchange_failure_returns_400(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    idp.fail_token_exchange = True
    state, nonce = await _start_login_and_capture_state(client)
    idp.last_nonce = nonce
    resp = await client.get("/api/v1/auth/oidc/callback", params={"code": "auth-code-1", "state": state})
    assert resp.status_code == 400


async def test_idp_error_response_rejected(oidc_env):
    client, idp, settings_repo, user_repo = oidc_env
    resp = await client.get(
        "/api/v1/auth/oidc/callback",
        params={"error": "access_denied", "error_description": "user cancelled"},
    )
    assert resp.status_code == 400
