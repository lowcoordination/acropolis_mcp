"""Python-side JWT verifier mirroring the ``mcp-authn`` Go middleware's contract (issue #134, T5).

Used by ``test_upstream_tokens.py`` to prove the token Acropolis sends on the upstream hop is a
real, audience-bound RS256 JWT — the same claim set the Go middleware will enforce in the fleet.
This is NOT the thing that ships (the Go middleware is); it's the test-only mirror of the contract,
now pinned to the shared conformance vectors (``testdata/conformance.json``, byte-identical to the
Go repo) rather than to prose.

Deliberately self-contained (stdlib + ``cryptography`` only, no ``argus`` imports): it verifies the
WIRE format, not the issuer's own helpers, so a drift between the two implementations fails here
rather than silently passing on both sides.

The check order and predicates below mirror ``mcpauthn.verify``:

  1. structural parse (three base64url segments, JSON header/payload);
  2. ``alg`` must be exactly ``RS256`` — reject before touching a key, so ``alg:none`` and the
     HS256 key-confusion attack fail on the header, never reach a signature check;
  3. ``kid`` must be present, and (when a key set is supplied) name a known key;
  4. RS256 signature over ``header.payload`` against that key;
  5. claims: ``aud`` contains the configured audience (string OR array spelling), ``iss`` matches
     when an issuer is configured, and ``exp`` holds at the supplied clock.

Every failure is raised as ``AssertionError`` — the one exception type callers already catch — so a
forged/expired token reads as "rejected", not as an uncaught ``InvalidSignature``.
"""
from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Shared with the Go middleware via conformance vectors (see issue #134) — kept as a literal here
# (not imported from argus.tokens) so a change to the issuer's constant doesn't silently move this
# verifier's notion of "expired". ``test_conformance.py`` asserts it equals the vectors' constant.
CLOCK_LEEWAY_SECONDS = 30


def _b64url_decode(data: str) -> bytes:
    """RFC 7515 base64url decode, accepting padded and unpadded input alike."""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _select_public_key(public_key, kid):
    """Resolve the verification key for ``kid``.

    ``public_key`` is either a single key object (the ``test_upstream_tokens.py`` shape, where the
    caller knows the issuer) or a ``{kid: key}`` mapping standing in for a fetched JWKS. In the
    mapping shape the header's kid is load-bearing — absent or unknown is a rejection, matching the
    Go middleware's ``errMissingKeyID``/``errUnknownKeyID``. A bare key carries no kid to match
    against, so it is used as-is; that is the pre-conformance call shape and its tokens always
    carry a kid anyway.
    """
    if isinstance(public_key, Mapping):
        if not kid:
            raise AssertionError("token header carries no kid; the key cannot be identified")
        key = public_key.get(kid)
        if key is None:
            raise AssertionError(f"unknown kid {kid!r}: not in the published key set")
        return key
    return public_key


def _audience_matches(aud, audience: str) -> bool:
    """RFC 7519 allows ``aud`` as a single string or an array of strings; pass iff the configured
    audience is among them. Any other JSON type is a mismatch (mirrors ``audienceMatches``)."""
    if isinstance(aud, str):
        return aud == audience
    if isinstance(aud, list):
        return any(isinstance(a, str) and a == audience for a in aud)
    return False


def verify_request_token(
    token: str,
    *,
    audience: str,
    issuer: str,
    public_key,
    leeway_seconds: int = CLOCK_LEEWAY_SECONDS,
    now: float | None = None,
) -> dict:
    """Verify a compact RS256 JWS against the middleware contract.

    Returns the decoded payload on success; raises ``AssertionError`` on a malformed token, a
    non-RS256 header, a missing/unknown kid, a bad signature, an audience/issuer mismatch, or a
    missing/expired ``exp``.

    ``now`` is Unix epoch seconds and defaults to ``time.time()``. Tests pass the conformance file's
    ``constants.fixed_now`` so the expiry boundary is deterministic; the predicate is exactly the
    contract's ``pass iff now < exp + leeway_seconds`` (note the strict ``<``: a token expiring
    exactly at the leeway boundary FAILS).
    """
    if now is None:
        now = time.time()

    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except (AttributeError, ValueError):
        raise AssertionError(f"token is not a 3-part compact JWS: {token[:24]!r}...")

    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))

    # alg first: reject non-RS256 before any key is consulted (alg:none / HS256 confusion).
    if header.get("alg") != "RS256":
        raise AssertionError(f"alg must be RS256, got {header.get('alg')!r}")

    key = _select_public_key(public_key, header.get("kid"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        key.verify(
            _b64url_decode(signature_b64), signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature as exc:
        # Normalised to the caller-facing failure type; a tampered/forged token is a rejection.
        raise AssertionError("signature verification failed") from exc

    # Claims, in the middleware's order: audience, then issuer, then expiry.
    if not _audience_matches(payload.get("aud"), audience):
        raise AssertionError(f"aud {payload.get('aud')!r} does not contain {audience!r}")
    if issuer and payload.get("iss") != issuer:
        raise AssertionError(f"iss {payload.get('iss')!r} != {issuer!r}")
    exp = payload.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise AssertionError(f"exp missing or not an integer: {exp!r}")
    if not now < exp + leeway_seconds:
        raise AssertionError(f"expired beyond leeway: {exp!r} + {leeway_seconds}s <= now {now!r}")
    return payload
