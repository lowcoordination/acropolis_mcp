"""JWTs for the Acropolis→upstream hop (issue #134, Task 1).

Acropolis is the ISSUER of the short-lived, audience-bound tokens that the fleet's shared Go
middleware (``mcp-authn``, Task 5) verifies. This module is the issuer half of that contract;
the verifier half is the middleware, and the two are pinned to one behaviour by a shared
conformance-vector file (see the issue's "Conformance note") so a drift between the
implementations fails a test on either side rather than a rollout.

Algorithm choice — deliberate, recorded here because the spec's Open questions left it open:
**RS256**, not EdDSA. The deciding constraint is stdlib-compatibility on BOTH sides of the hop:
this side signs with ``cryptography``'s RSA (RSASSA-PKCS1-v1_5 + SHA-256, already a base
dependency), and the Go middleware verifies with ``crypto/rsa`` + ``crypto/sha256`` — both part
of each language's standard library, no extra JWT library required on either side. EdDSA was the
only serious alternative (smaller signatures, faster), but Go's stdlib has no Ed25519-in-JWS
helpers and every JWT-capable Go library that adds them drags in a dependency for one signature
per 10 minutes — a cost with no benefit at this scale. RSA key size: whatever the operator
provisions (2048+ recommended); the code is size-agnostic.

Token shape (pinned in the issue so the Go middleware could start in parallel):

- header: ``{"alg": "RS256", "typ": "JWT", "kid": <derived>}``
- claims: ``{"iss": "acropolis", "aud": <server slug>, "exp": now + 600}``

``kid`` is the base64url SHA-256 of the public key's DER SubjectPublicKeyInfo. It is derived
from the key rather than stored (the keypair is a secret-provider reference, so a restart
reloads the same material and must derive the same id), deterministic (rotation publishes
multiple kids and the middleware refetches only on an unknown kid — a random id would break
that), and never secret (it appears in the token header and the public JWKS). It is NOT an
RFC 7638 JWK thumbprint — that canonical-JWK hash is unnecessary because the two implementations
share literal kid strings via conformance vectors rather than recomputing them from the JWK.

Cache semantics — why "a request never blocks on a mint after the first": one token per slug.
The first request for a slug mints synchronously (the key is already in memory, so this is a
local RSA sign, not a secret-provider round-trip). Subsequent requests return the cached token;
once a token is ``REFRESH_FRACTION`` (80%) of the way to expiry, a BACKGROUND task re-mints it
so a live slug's token is re-issued before it can expire and no later request has to wait on a
mint. Only two paths mint synchronously: no token yet, and a token that actually expired
(refresh failed or was starved) — in that case there is no valid token to hand out, so blocking
is the only honest option. The per-slug ``refreshing`` flag deduplicates the background task so
a burst of requests inside the refresh window schedules ONE re-mint, not one per request.

``CLOCK_LEEWAY_SECONDS`` is enforced middleware-side; the constant lives HERE so both sides share
the number via the conformance vectors rather than re-deriving it independently.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from time import monotonic as _monotonic
from time import time as _epoch_seconds

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from archon.secrets import SecretProvider, SecretResolutionError, is_reference

# Shared constants — the middleware-side leeway uses the same number via conformance vectors, so
# changing these here is a cross-repo contract change, not a local tuning knob.
TOKEN_TTL_SECONDS = 600
REFRESH_FRACTION = 0.8
CLOCK_LEEWAY_SECONDS = 30

_ISSUER = "acropolis"
_ALGORITHM = "RS256"
_HEADER_TYPE = "JWT"
_KEY_TYPE = "RSA"
_KEY_USE = "sig"


class TokenIssuerConfigError(Exception):
    """Raised at construction time when ``token_signing_key_ref`` is set but cannot be resolved
    to a usable RSA private key.

    Deliberately a separate type from ``SecretResolutionError``: the secret provider already has
    its own fail-loud contract (one exception type per seam, never a partial value), and wrapping
    it here lets ``create_app`` (Task 3) report "token signing key misconfigured" as a distinct
    boot failure from "a server credential couldn't be resolved at call time". Never raised
    mid-request — ``get_token`` mints with an already-loaded in-memory key, so a misconfiguration
    surfaces at boot, not on the first tool call.
    """


def _b64url(data: bytes) -> str:
    """RFC 7515 base64url, unpadded — the on-the-wire form JWT consumers expect."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Inverse of ``_b64url`` for tests / the conformance-vector loader. Accepts padded and
    unpadded input alike."""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _int_to_bytes(value: int) -> bytes:
    """Big-endian, minimal-length encoding of a non-negative integer — exactly what RFC 7518's
    RSA JWK ``n``/``e`` fields require (no leading zero byte, matching every major JWT library's
    serialization)."""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _derive_kid(public_key) -> str:
    """A stable, non-secret key id: base64url(SHA-256(DER SubjectPublicKeyInfo)).

    Must be re-derivable after a restart (same key material → same kid) and never secret (it is
    published in the token header and the JWKS). SHA-256 of the DER form is collision-resistant
    for this purpose and trivial to reproduce anywhere if cross-checking is ever needed.
    """
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _b64url(hashlib.sha256(der).digest())


def _build_jwk(public_key, kid: str) -> dict:
    """Serialize a public key as its RFC 7517/7518 RSA JWK (public material only — ``kty``/``n``/
    ``e``/``alg``/``use``/``kid``; never ``d``/``p``/``q``/...).

    Shared by the active key and by previously-active keys still in their rotation overlap window.
    """
    numbers = public_key.public_numbers()
    return {
        "kty": _KEY_TYPE,
        "use": _KEY_USE,
        "alg": _ALGORITHM,
        "kid": kid,
        "n": _b64url(_int_to_bytes(numbers.n)),
        "e": _b64url(_int_to_bytes(numbers.e)),
    }


async def _resolve_rsa_private_key(ref: str, secret_provider: SecretProvider):
    """Resolve a secret-provider reference to a validated RSA private key.

    Shared by ``TokenIssuer.from_settings`` (the env-driven boot path) and the rotation manager
    in ``argus/rotate_key.py`` (the DB-driven re-load path) so both fail the SAME way: resolve
    failures and non-PEM/non-RSA material raise ``TokenIssuerConfigError`` that names the ref
    and the reason but never the key material. The per-step comments carry the discipline from
    ``from_settings``'s original inline implementation (why ``exc.reason``, not ``str(exc)``; why
    the PEM error message is safe to include).
    """
    try:
        pem = await secret_provider.resolve(ref)
    except SecretResolutionError as exc:
        # Deliberately exc.reason, NOT str(exc): SecretResolutionError's message embeds the
        # original ref, which is verbose ciphertext/path noise we don't want in a boot
        # failure; reason is the concise operator-facing cause by construction.
        raise TokenIssuerConfigError(
            f"token signing key {ref} is unresolvable: {exc.reason}"
        ) from exc
    try:
        private_key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        # These messages are generic ("could not deserialize", "password was not given but
        # private key is encrypted") — safe to include, and the encrypted-PEM case is exactly
        # the operator hint we want to surface rather than swallow.
        raise TokenIssuerConfigError(
            f"token signing key {ref} did not resolve to a usable PEM private key: {exc}"
        ) from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TokenIssuerConfigError(
            f"token signing key {ref} resolved to a non-RSA key; RS256 "
            "requires an RSA keypair"
        )
    return private_key


class _CachedToken:
    """Per-slug cache entry. ``refreshing`` deduplicates the background refresh task so N
    concurrent requests inside the refresh window schedule ONE re-mint, not N."""

    __slots__ = ("token", "refresh_at", "expires_at", "refreshing")

    def __init__(self, token: str, refresh_at: float, expires_at: float):
        self.token = token
        self.refresh_at = refresh_at
        self.expires_at = expires_at
        self.refreshing = False


class TokenIssuer:
    """Mints cached, per-slug JWTs for the upstream hop. Construct via ``from_settings``; never
    pass key material in a form that could be repr'd — the constructor takes an already-loaded
    ``cryptography`` key object, not a string."""

    def __init__(
        self,
        private_key,
        *,
        ttl_seconds: float = TOKEN_TTL_SECONDS,
        refresh_fraction: float = REFRESH_FRACTION,
        previous: tuple[tuple[object, float], ...] = (),
    ):
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TokenIssuerConfigError("TokenIssuer requires an RSA private key (RS256)")
        if ttl_seconds <= 0:
            raise TokenIssuerConfigError("ttl_seconds must be positive")
        if not 0 < refresh_fraction < 1:
            raise TokenIssuerConfigError("refresh_fraction must be between 0 and 1")
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._ttl = ttl_seconds
        self._refresh_after = ttl_seconds * refresh_fraction
        self._kid = _derive_kid(self._public_key)
        self._public_jwk = _build_jwk(self._public_key, self._kid)
        # One token per slug; values are _CachedToken entries. Never persisted, never logged.
        self._cache: dict[str, _CachedToken] = {}
        # Previously-active keys still PUBLISHED (not signing) for the rotation overlap window,
        # keyed by kid -> (public_jwk, drop_at_epoch). Dropped lazily once the overlap elapses —
        # see _drop_expired_previous. The constructor takes these so a restarted app re-loads an
        # in-flight overlap from the rotation state (argus/rotate_key.py) rather than losing it.
        self._previous: dict[str, tuple[dict, float]] = {}
        for prev_key, drop_at in previous:
            self._add_previous(prev_key, drop_at)

    @classmethod
    async def from_settings(
        cls, settings, secret_provider: SecretProvider
    ) -> "TokenIssuer | None":
        """Build an issuer from ``settings.token_signing_key_ref``, or return None when it is
        unset (no issuer configured — Task 3 treats that as "token mode is unavailable").

        Resolution happens HERE, at boot, through the same ``SecretProvider`` every other
        credential uses — so ``enc:v1:``/``vault://`` references work identically, and a
        misconfigured ref raises ``TokenIssuerConfigError`` before the app starts rather than on
        the first tool call (the fail-loud-at-boot posture).

        The ref must be a REFERENCE, never inline key material: a PEM literal in this field
        would put the long-lived signing key in a pydantic Settings field populated from the
        process environment — the exact k3s#66 exposure issue #134 exists to close — so a
        non-reference ref is rejected outright below. Token signing therefore requires the
        ``encrypted`` or ``openbao`` secret provider; the default ``local`` provider (an
        identity resolve) has no reference to resolve and cannot hold a signing key.
        """
        ref = getattr(settings, "token_signing_key_ref", None)
        if not ref:
            return None
        if not is_reference(ref):
            # Deliberately do NOT echo `ref` — at this point it is (or could be) inline key
            # material, so the message states the contract without quoting the value.
            raise TokenIssuerConfigError(
                "token_signing_key_ref must be a secret-provider reference (enc:v1:... or "
                "vault://...), not inline key material. An inline PEM would place the "
                "long-lived signing key in the process environment (readable from "
                "/proc/<pid>/environ — see issue #134, k3s#66). Use the 'encrypted' or "
                "'openbao' secret provider and reference the key there."
            )
        return cls(await _resolve_rsa_private_key(ref, secret_provider))

    @property
    def kid(self) -> str:
        """The issuer's current key id — the value stamped into every token header."""
        return self._kid

    def jwks(self) -> dict:
        """The public half of every published keypair as a standard JWKS document
        (``{"keys": [...]}``) — the ACTIVE key first, then any previously-active keys still in
        their overlap window. During rotation that is BOTH ``kid``s, which is what lets a server
        that cached the old key keep verifying until it sees a new-``kid`` token and refetches.

        Contains ONLY public material (``kty``/``n``/``e``/``alg``/``use``/``kid``); the private
        components (``d``/``p``/``q``/...) are never serialized. Task 4 serves this at
        ``/.well-known/jwks.json`` unauthenticated — it is public by definition.
        """
        self._drop_expired_previous()
        return {"keys": [self._public_jwk] + [jwk for jwk, _ in self._previous.values()]}

    def _add_previous(self, private_key, drop_at: float) -> None:
        """Register a previously-active key to stay PUBLISHED (not signing) until ``drop_at``.

        Validated as RSA at add time — the same fail-loud discipline as the active key — so a
        misconfigured previous-key reference surfaces when the issuer is (re)loaded, not on the
        first JWKS request.
        """
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TokenIssuerConfigError(
                "TokenIssuer previous keys must be RSA private keys (RS256)"
            )
        public_key = private_key.public_key()
        kid = _derive_kid(public_key)
        self._previous[kid] = (_build_jwk(public_key, kid), float(drop_at))

    def _drop_expired_previous(self) -> None:
        """Drop any previously-active key whose overlap window has elapsed.

        Lazy by design: rotation is a rare operator event and JWKS/mint are hot paths, so the
        drop is folded into those calls rather than a dedicated timer. The comparison uses the
        same wall-clock source (``_epoch_seconds``) the overlap deadline was computed from, so
        tests can advance it deterministically.
        """
        now = _epoch_seconds()
        expired = [kid for kid, (_jwk, drop_at) in self._previous.items() if drop_at <= now]
        for kid in expired:
            del self._previous[kid]

    def replace_keys(self, active_private_key, previous: tuple[tuple[object, float], ...] = ()) -> None:
        """Atomically swap the signing key and published-keys set IN PLACE.

        This is the rotation hook: the manager (``argus/rotate_key.py``) mutates the SAME issuer
        object it handed to the pipeline and health poller at boot, so those fixed references pick
        up a ``rotate-signing-key`` run with no restart and no re-wiring. Replacing the object
        instead would orphan every collaborator still holding the old one.

        ``ttl_seconds``/``refresh_fraction`` are deliberately NOT touched — they are issuer-wide
        config, not per-key material. The token cache is cleared so the next mint signs with the
        new key; tokens already minted under the old key remain verifiable until the old kid is
        dropped (the overlap window).
        """
        if not isinstance(active_private_key, rsa.RSAPrivateKey):
            raise TokenIssuerConfigError("TokenIssuer requires an RSA private key (RS256)")
        self._private_key = active_private_key
        self._public_key = active_private_key.public_key()
        self._kid = _derive_kid(self._public_key)
        self._public_jwk = _build_jwk(self._public_key, self._kid)
        self._previous = {}
        for prev_key, drop_at in previous:
            self._add_previous(prev_key, drop_at)
        self._cache.clear()

    async def get_token(self, slug: str) -> str:
        """Return the slug's current token, minting only when necessary (see module docstring's
        cache semantics). Never raises SecretResolutionError — the key is already in memory."""
        self._drop_expired_previous()
        now = _monotonic()
        entry = self._cache.get(slug)
        if entry is None or now >= entry.expires_at:
            return self._cache_token(slug, now)
        if now >= entry.refresh_at and not entry.refreshing:
            entry.refreshing = True
            asyncio.create_task(self._refresh(slug))
        return entry.token

    def _cache_token(self, slug: str, now: float) -> str:
        token = self._mint(slug)
        self._cache[slug] = _CachedToken(
            token=token,
            refresh_at=now + self._refresh_after,
            expires_at=now + self._ttl,
        )
        return token

    async def _refresh(self, slug: str) -> None:
        """Background re-mint scheduled once the cached token crosses the refresh threshold. Runs
        as a fire-and-forget task; the ``finally`` clears the dedupe flag so a later window (or a
        failed mint) can schedule again."""
        try:
            self._cache_token(slug, _monotonic())
        finally:
            entry = self._cache.get(slug)
            if entry is not None:
                entry.refreshing = False

    def mint_uncached(self, audience: str) -> str:
        """Mint a correctly-signed token for ``audience`` WITHOUT touching the per-slug cache.

        For the health poller's wrong-audience probe (``stoa.health``), which needs a token that is
        genuine in every respect except that no server should accept its audience. It must not
        enter the cache (the next real request for a slug would otherwise be handed a probe token)
        and the caller must not log or store the result."""
        return self._mint(audience)

    def _mint(self, slug: str) -> str:
        header = {"alg": _ALGORITHM, "typ": _HEADER_TYPE, "kid": self._kid}
        payload = {"iss": _ISSUER, "aud": slug, "exp": int(_epoch_seconds() + self._ttl)}
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("ascii"))
            + "."
            + _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii"))
        )
        signature = self._private_key.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{signing_input}.{_b64url(signature)}"


