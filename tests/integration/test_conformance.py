"""Issue #134 T5: byte-identical conformance vectors shared with the ``mcp-authn`` Go middleware.

``testdata/conformance.json`` is generated in the Go repo and committed here **byte-identical** —
it is the cross-language contract, not a copy that may drift. This module loads it, rebuilds the
RSA public key(s) from its ``jwks`` section and replays every pass/fail vector through the
Python-side verifier mirror (``fixture_token_verifier``) at the file's deterministic ``fixed_now``.
A disagreement means the Python mirror is wrong; the vector file is never edited to fit.

Pure — no database, no network — but it still runs under this suite's pytest, whose conftest
provisions the session Postgres.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from .fixture_token_verifier import CLOCK_LEEWAY_SECONDS, verify_request_token

CONFORMANCE_PATH = Path(__file__).parent / "testdata" / "conformance.json"


def _b64url_to_int(value: str) -> int:
    """RFC 7517 base64url integer (``n``/``e``), accepting padded and unpadded spellings."""
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def _public_keys(jwks: dict) -> dict[str, rsa.RSAPublicKey]:
    """Rebuild the JWKS as a ``{kid: public_key}`` map — the shape ``verify_request_token`` uses to
    enforce kid lookups (missing/unknown kid must fail, as the Go middleware's does)."""
    keys: dict[str, rsa.RSAPublicKey] = {}
    for jwk in jwks["keys"]:
        assert jwk["kty"] == "RSA", jwk
        numbers = rsa.RSAPublicNumbers(_b64url_to_int(jwk["e"]), _b64url_to_int(jwk["n"]))
        keys[jwk["kid"]] = numbers.public_key()
    assert keys, "conformance jwks carries no keys"
    return keys


def _bearer_token(authorization: str | None) -> str | None:
    """Reproduce the middleware's ``authorized()`` split: ``scheme SP credential``, scheme
    ``Bearer`` case-insensitively, credential non-empty. ``None`` means "no usable bearer token",
    which every caller treats as a failure — so ``null``, a bare ``Bearer``, and ``Basic ...`` all
    collapse to a rejection before the verifier is ever called."""
    if authorization is None:
        return None
    scheme, sep, credential = authorization.partition(" ")
    if not sep or scheme.lower() != "bearer" or credential == "":
        return None
    return credential


@pytest.fixture(scope="module")
def conformance() -> dict:
    doc = json.loads(CONFORMANCE_PATH.read_text(encoding="utf-8"))
    # Pin the file's own shape and the one cross-repo constant, so a regenerated file that moved
    # the leeway can't silently make both implementations agree on the wrong number.
    assert doc["version"] == 1, doc["version"]
    assert doc["algorithm"] == "RS256", doc["algorithm"]
    assert doc["constants"]["leeway_seconds"] == CLOCK_LEEWAY_SECONDS, (
        f"conformance leeway {doc['constants']['leeway_seconds']}s != verifier "
        f"CLOCK_LEEWAY_SECONDS {CLOCK_LEEWAY_SECONDS}s: drift"
    )
    return doc


def test_conformance_vectors(conformance: dict) -> None:
    config = conformance["config"]
    constants = conformance["constants"]
    public_keys = _public_keys(conformance["jwks"])
    vectors = conformance["vectors"]
    assert vectors, "conformance file carries no vectors"

    seen: set[str] = set()
    mismatches: list[str] = []
    passes = fails = 0

    for vector in vectors:
        name = vector["name"]
        assert name not in seen, f"duplicate vector name {name!r}"
        seen.add(name)

        token = _bearer_token(vector["authorization"])
        if token is None:
            outcome = "fail"
        else:
            try:
                verify_request_token(
                    token,
                    audience=config["audience"],
                    issuer=config["issuer"],
                    public_key=public_keys,
                    now=constants["fixed_now"],
                )
                outcome = "pass"
            except AssertionError:
                outcome = "fail"

        if outcome == "pass":
            passes += 1
        else:
            fails += 1

        if outcome != vector["expect"]:
            mismatches.append(
                f"vector {name!r}: want {vector['expect']}, got {outcome} "
                f"(note: {vector['note']})"
            )

    assert not mismatches, "\n".join(mismatches)
    # The file must exercise both outcomes, or a verifier that always rejects (or always accepts)
    # would pass it vacuously.
    assert passes and fails, f"need both passing and failing vectors, got {passes}/{fails}"
