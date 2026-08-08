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
    secret: str,
    issued_at: Optional[float] = None,
    session_version: int = DEFAULT_SESSION_VERSION,
    user_id: Optional[int] = None,
    user_session_version: int = DEFAULT_SESSION_VERSION,
) -> str:
    """A minimal signed session token: base64(payload).base64(hmac-sha256).
    No external dependency (itsdangerous, etc.) — deliberately small footprint for a
    self-hostable product. Payload carries an issued-at timestamp and a session_version (F18).

    enterprise #1/#2: `user_id` + `user_session_version` identify WHICH principal this token
    asserts, on top of the existing global `session_version`. `user_id` is Optional and defaults
    to None so tokens issued before the identity milestone (or by the legacy settings-only auth
    path, still supported as a fallback — see archon/admin_auth.py) keep verifying exactly as
    before; a None-subject token is understood as "the legacy single admin," not a distinct
    principal. `user_session_version` is the PER-USER analogue of the global counter — bumping a
    single user's version revokes only their sessions, not everyone's (the property 02-rbac.md
    and 01-identity-and-sso.md both require: disabling/demoting one user must not log out the
    other four)."""
    payload = json.dumps({
        "iat": issued_at if issued_at is not None else time.time(),
        "session_version": session_version,
        "user_id": user_id,
        "user_session_version": user_session_version,
    }).encode()
    payload_b64 = _b64encode(payload)
    signature = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64encode(signature)}"


def verify_session_token(
    token: str,
    secret: str,
    current_session_version: int = DEFAULT_SESSION_VERSION,
    current_user_session_version: Optional[int] = None,
) -> bool:
    """`current_user_session_version` is the CALLER's job to look up (from the user_id embedded
    in the token, which the caller must extract via decode_session_payload first — this function
    stays a pure boolean check on a version it's TOLD is current, same shape as the existing
    global-version check, rather than reaching into a repo itself). Pass None when the token is
    known/expected to be a legacy admin-only token (no user_id) — the per-user check is then
    skipped, matching pre-identity-milestone behavior exactly."""
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

    if current_user_session_version is not None:
        token_user_version = payload.get("user_session_version", DEFAULT_SESSION_VERSION)
        if not isinstance(token_user_version, int) or token_user_version != current_user_session_version:
            return False

    return True


def decode_session_payload(token: str) -> Optional[dict]:
    """Extract the (unverified-signature) payload dict from a token, or None if malformed.
    Used to read `user_id` BEFORE signature verification would normally gate access — this is
    safe because the value is only ever used to look up which user's session_version to compare
    against; verify_session_token's HMAC check still runs and still rejects any token whose
    payload was tampered with, so a forged user_id can't grant a forged session, only cause a
    lookup for the wrong user (which then fails signature verification anyway)."""
    try:
        payload_b64, _signature_b64 = token.split(".", 1)
    except ValueError:
        return None
    try:
        payload = json.loads(_b64decode(payload_b64))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None
