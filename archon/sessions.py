from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

SESSION_COOKIE_NAME = "acropolis_session"
SESSION_MAX_AGE_SECONDS = 7 * 24 * 3600  # 7 days


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# F18 fix (review 2026-08-04): the token used to be validated purely by signature plus a 7-day
# age check — no session id, no version, no subject. POST /logout only cleared the client's
# cookie; the token stayed cryptographically valid server-side for its full 7 days, and there
# was no way to invalidate a stolen cookie without hand-editing the settings table. Fixed by
# embedding a `session_version` int in the payload, compared against a value stored in
# settings (key "session_version", default 0 when absent/unset). Bumping the stored version
# invalidates every previously-issued token in one write, without touching session_secret
# (which would also break anything else keyed on it). The default of 0 for an absent setting
# means existing tokens issued before this fix (which never carried a version) still verify —
# `payload.get("session_version", 0)` on a token with no such key reads as 0, matching a
# freshly-initialized counter.
DEFAULT_SESSION_VERSION = 0


def create_session_token(
    secret: str, issued_at: Optional[float] = None, session_version: int = DEFAULT_SESSION_VERSION
) -> str:
    """A minimal signed session token: base64(payload).base64(hmac-sha256).
    No external dependency (itsdangerous, etc.) — deliberately small footprint for a
    self-hostable product. Payload carries an issued-at timestamp and a session_version (F18);
    there is a single admin per instance in v1, so there's no subject/user id to encode."""
    payload = json.dumps({
        "iat": issued_at if issued_at is not None else time.time(),
        "session_version": session_version,
    }).encode()
    payload_b64 = _b64encode(payload)
    signature = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64encode(signature)}"


def verify_session_token(
    token: str, secret: str, current_session_version: int = DEFAULT_SESSION_VERSION
) -> bool:
    try:
        payload_b64, signature_b64 = token.split(".", 1)
    except ValueError:
        return False

    expected_signature = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    try:
        actual_signature = _b64decode(signature_b64)
    except Exception:
        return False

    if not hmac.compare_digest(expected_signature, actual_signature):
        return False

    try:
        payload = json.loads(_b64decode(payload_b64))
    except Exception:
        return False

    issued_at = payload.get("iat")
    if not isinstance(issued_at, (int, float)):
        return False
    if time.time() - issued_at > SESSION_MAX_AGE_SECONDS:
        return False

    # F18: a token issued under an older session_version (bumped on logout-all / password
    # change) is invalid even if its signature and age both check out — this is what makes
    # revocation possible at all.
    token_version = payload.get("session_version", DEFAULT_SESSION_VERSION)
    if not isinstance(token_version, int) or token_version != current_session_version:
        return False

    return True
