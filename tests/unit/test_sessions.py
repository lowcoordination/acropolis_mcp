from __future__ import annotations

import time

from archon.sessions import create_session_token, verify_session_token


def test_create_and_verify_roundtrip():
    token = create_session_token("my-secret")
    assert verify_session_token(token, "my-secret")


def test_verify_rejects_wrong_secret():
    token = create_session_token("secret-a")
    assert not verify_session_token(token, "secret-b")


def test_verify_rejects_tampered_payload():
    token = create_session_token("secret")
    payload_b64, sig_b64 = token.split(".", 1)
    tampered = "x" + payload_b64[1:] + "." + sig_b64
    assert not verify_session_token(tampered, "secret")


def test_verify_rejects_malformed_token():
    assert not verify_session_token("not-a-valid-token", "secret")
    assert not verify_session_token("", "secret")


def test_verify_rejects_expired_token():
    old_token = create_session_token("secret", issued_at=time.time() - 999_999_999)
    assert not verify_session_token(old_token, "secret")


def test_verify_accepts_freshly_issued_token():
    token = create_session_token("secret", issued_at=time.time())
    assert verify_session_token(token, "secret")


def test_verify_rejects_token_issued_under_an_older_session_version():
    """F18 regression (review 2026-08-04): this is the entire mechanism session revocation
    relies on — a token signed under version N must be rejected once the current version is
    N+1, even though its signature and age are both still perfectly valid."""
    token = create_session_token("secret", session_version=1)
    assert verify_session_token(token, "secret", current_session_version=1)
    assert not verify_session_token(token, "secret", current_session_version=2)


def test_verify_accepts_token_matching_current_session_version_after_bump():
    """The self-preserving half of F18: a token freshly issued AT the new version (what
    change-password does for the caller's own session) must still verify."""
    token = create_session_token("secret", session_version=5)
    assert verify_session_token(token, "secret", current_session_version=5)


def test_pre_f18_token_with_no_session_version_still_verifies_against_default():
    """Tokens issued before this fix carry no session_version key at all. payload.get(
    "session_version", DEFAULT_SESSION_VERSION) must read as DEFAULT_SESSION_VERSION for such a
    token, so it isn't retroactively invalidated the moment this fix ships against a
    freshly-initialized (version-0) settings table."""
    import base64
    import hashlib
    import hmac
    import json

    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    secret = "secret"
    payload = json.dumps({"iat": time.time()}).encode()  # no session_version key at all
    payload_b64 = _b64(payload)
    signature = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    legacy_token = f"{payload_b64}.{_b64(signature)}"

    assert verify_session_token(legacy_token, secret, current_session_version=0)
