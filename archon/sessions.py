from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

SESSION_COOKIE_NAME = "argus_session"
SESSION_MAX_AGE_SECONDS = 7 * 24 * 3600  # 7 days


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_session_token(secret: str, issued_at: Optional[float] = None) -> str:
    """A minimal signed session token: base64(payload).base64(hmac-sha256).
    No external dependency (itsdangerous, etc.) — deliberately small footprint for a
    self-hostable product. Payload only carries an issued-at timestamp; there is a single
    admin per instance in v1, so there's no subject/user id to encode."""
    payload = json.dumps({"iat": issued_at if issued_at is not None else time.time()}).encode()
    payload_b64 = _b64encode(payload)
    signature = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64encode(signature)}"


def verify_session_token(token: str, secret: str) -> bool:
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

    return True
