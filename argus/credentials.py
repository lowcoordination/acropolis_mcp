"""Resolve the credential Acropolis must present to an upstream, per ``server.credential_mode``.

This is the resolver for callers that have no request to audit: the control plane's tool-catalog
fetch (``GET /servers/{slug}/tools`` and the catalog refresh behind ``POST /servers/{slug}/probe``).
It exists because those paths used to hand ``ToolsCache`` the RAW ``server.upstream_auth_header``
(issue #146), which is wrong in two ways:

  * ``credential_mode='token'`` keeps the header NULL, so the upstream got no credential, 401'd, and
    ``get_raw_tools`` swallowed the failure and served a stale/empty list;
  * ``static`` with a reference (``enc:v1:...``, ``vault://...``) put the unresolved reference string
    on the wire as the Authorization header.

Two other places resolve the same three modes and are deliberately NOT routed through here:
``Pipeline._resolve_credential`` (data plane — it must turn a failure into an audited ERROR response)
and ``stoa.health.probe_server`` (turns a failure into an ``unhealthy`` reason). They report failure
differently, and rewriting the hot path was out of scope for #146. The behaviour is the same on
purpose, and ``tests/integration/test_control_plane_credentials.py`` pins this resolver to what the
upstream actually receives. Change one, change all three.

Failure is always explicit: ``UpstreamCredentialError``, never a silent fall-through to "no
credential" — forwarding unauthenticated would turn a Vault blip or a missing signing key into a
401 storm or, worse, a request sent to an upstream that expected to be authenticated.
"""
from __future__ import annotations

import logging
from typing import Optional

from archon.secrets import SecretProvider, SecretResolutionError
from argus.tokens import TokenIssuer
from db.models import ServerRecord

logger = logging.getLogger(__name__)


class UpstreamCredentialError(Exception):
    """The credential for this upstream could not be produced. ``reason`` is safe to show an
    operator and to log: it is built only from static text and the secret's *reference*, never from
    resolved plaintext or key material (SecretResolutionError's own contract)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


async def resolve_upstream_credential(
    server: ServerRecord, *, secrets: SecretProvider, token_issuer: Optional[TokenIssuer],
) -> Optional[str]:
    """The Authorization header value for ``server``, or ``None`` when it has no credential.

    ``token``: ``"Bearer <jwt>"`` from the startup-wired issuer (ignores ``upstream_auth_header``).
    ``static`` / ``none``: ``upstream_auth_header`` resolved through the secret provider (a literal
    passes through; a reference is resolved) — ``none`` is the migration default and a legacy row
    that still carries a header keeps working, exactly as on the data plane.
    """
    if server.credential_mode == "token":
        if token_issuer is None:
            raise UpstreamCredentialError("token signing is not configured (ACROPOLIS_TOKEN_SIGNING_KEY_REF)")
        try:
            return f"Bearer {await token_issuer.get_token(server.slug)}"
        except Exception:
            # The key is already in memory, so a mint should never fail. Log the traceback
            # (get_token never touches the PEM string) but keep the operator-facing reason generic.
            logger.exception("token mint failed for server '%s'", server.slug)
            raise UpstreamCredentialError("token mint failed")

    if server.upstream_auth_header is None:
        return None
    try:
        return await secrets.resolve(server.upstream_auth_header)
    except SecretResolutionError as e:
        raise UpstreamCredentialError(f"secret resolution failed: {e.reason}")
