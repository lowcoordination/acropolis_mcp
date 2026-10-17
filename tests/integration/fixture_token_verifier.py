"""Python-side JWT verifier mirroring the ``mcp-authn`` Go middleware's contract (issue #134, T5).

Used by ``test_upstream_tokens.py`` to prove the token Acropolis sends on the upstream hop is a
real, audience-bound RS256 JWT — the same claim set the Go middleware will enforce in the fleet.
This is NOT the thing that ships (the Go middleware is); it's the test-only mirror that pins the
issuer to the shared contract until T5's conformance vectors land.

Deliberately self-contained (stdlib + ``cryptography`` only, no ``argus`` imports): it verifies the
WIRE format, not the issuer's own helpers, so a drift between the two implementations fails here
rather than silently passing on both sides.
"""
from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Shared with the Go middleware via conformance vectors (see issue #134) — kept as a literal here
# (not imported from argus.tokens) so a change to the issuer's constant doesn't silently move this
# verifier's notion of "expired".
CLOCK_LEEWAY_SECONDS = 30


def _b64url_decode(data: str) -> bytes:
    """RFC 7515 base64url decode, accepting padded and unpadded input alike."""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def verify_request_token(
    token: str,
    *,
    audience: str,
    issuer: str,
    public_key,
    leeway_seconds: int = CLOCK_LEEWAY_SECONDS,
) -> dict:
    """Verify a compact RS256 JWS against the middleware contract.

    Returns the decoded payload on success; raises on a bad signature, a non-RS256 header, an
    audience/issuer mismatch, or a missing/expired ``exp`` — the same fail-closed checks the Go
    middleware performs, in the same order of importance (signature first, then claims).
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise AssertionError(f"token is not a 3-part compact JWS: {token[:24]!r}...")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    # Raises cryptography.exceptions.InvalidSignature on tamper — deliberately NOT caught, so a
    # forged/tampered token fails the test loudly rather than reading as "claims were fine".
    public_key.verify(
        _b64url_decode(signature_b64), signing_input, padding.PKCS1v15(), hashes.SHA256()
    )

    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))

    if header.get("alg") != "RS256":
        raise AssertionError(f"alg must be RS256, got {header.get('alg')!r}")
    if payload.get("iss") != issuer:
        raise AssertionError(f"iss {payload.get('iss')!r} != {issuer!r}")
    if payload.get("aud") != audience:
        raise AssertionError(f"aud {payload.get('aud')!r} != {audience!r}")
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()) - leeway_seconds:
        raise AssertionError(f"exp missing or expired: {exp!r}")
    return payload
