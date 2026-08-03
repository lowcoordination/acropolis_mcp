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
