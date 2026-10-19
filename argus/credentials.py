"""Resolve the credential Acropolis must present to an upstream, per ``server.credential_mode``.

This is the resolver for callers that have no request to audit: the control plane's tool-catalog
fetch (``GET /servers/{slug}/tools`` and the catalog refresh behind ``POST /servers/{slug}/probe``).
It exists because those paths used to hand ``ToolsCache`` the RAW ``server.upstream_auth_header``
(issue #146), which is wrong in two ways:

  * ``credential_mode='token'`` keeps the header NULL, so the upstream got no credential, 401'd, and
    ``get_raw_tools`` swallowed the failure and served a stale/empty list;
  * ``static`` with a reference (``enc:v1:...``, ``vault://...``) put the unresolved reference string
    on the wire as the Authorization header.

This is the ONE place the rule lives (issue #155). The three planes that need a credential all call
it and differ only in how they report a failure: the control plane lets ``UpstreamCredentialError``
surface as its own error, ``Pipeline._resolve_credential`` (data plane) turns it into an audited 502,
and ``stoa.health.probe_server`` turns it into an ``unhealthy`` reason. ``kind`` tells them apart
without parsing ``reason``. ``tests/integration/test_credential_resolution_planes.py`` pins all three
to the same answer over the whole mode matrix.

Failure is always explicit: ``UpstreamCredentialError``, never a silent fall-through to "no
credential" — forwarding unauthenticated would turn a Vault blip or a missing signing key into a
401 storm or, worse, a request sent to an upstream that expected to be authenticated.
"""
from __future__ import annotations

import logging
from contextlib import AbstractContextManager
from typing import Callable, Optional

from archon.secrets import SecretProvider, SecretResolutionError, is_reference
from argus.tokens import TokenIssuer
from db.models import ServerRecord

logger = logging.getLogger(__name__)


# Why a credential could not be produced. Callers that report failure in their own words (the health
# probe) switch on this rather than on ``reason`` text.
TOKEN_NOT_CONFIGURED = "token_not_configured"
TOKEN_MINT_FAILED = "token_mint_failed"
SECRET_RESOLUTION_FAILED = "secret_resolution_failed"


class UpstreamCredentialError(Exception):
    """The credential for this upstream could not be produced. ``reason`` is safe to show an
    operator and to log: it is built only from static text and the secret's *reference*, never from
    resolved plaintext or key material (SecretResolutionError's own contract). ``kind`` is one of
    the constants above."""

    def __init__(self, reason: str, kind: str):
        super().__init__(reason)
        self.reason = reason
        self.kind = kind


async def resolve_upstream_credential(
    server: ServerRecord, *, secrets: SecretProvider, token_issuer: Optional[TokenIssuer],
    resolve_span: Optional[Callable[[], AbstractContextManager]] = None,
) -> Optional[str]:
    """The Authorization header value for ``server``, or ``None`` when it has no credential.

    ``token``: ``"Bearer <jwt>"`` from the startup-wired issuer (ignores ``upstream_auth_header``).
    ``static`` / ``none``: ``upstream_auth_header`` resolved through the secret provider (a literal
    passes through; a reference is resolved) — ``none`` is the migration default and a legacy row
    that still carries a header keeps working, exactly as on the data plane.

    ``resolve_span``, when given, is called to open a tracing span around the secret-provider call,
    and only when ``upstream_auth_header`` is a REFERENCE (a literal resolves in-process with no I/O,
    so a span there would be noise). The data plane passes one; callers with no tracer omit it.
    """
    if server.credential_mode == "token":
        if token_issuer is None:
            raise UpstreamCredentialError(
                "token signing is not configured (ACROPOLIS_TOKEN_SIGNING_KEY_REF)", TOKEN_NOT_CONFIGURED,
            )
        try:
            return f"Bearer {await token_issuer.get_token(server.slug)}"
        except Exception:
            # The key is already in memory, so a mint should never fail. Log the traceback
            # (get_token never touches the PEM string) but keep the operator-facing reason generic.
            logger.exception("token mint failed for server '%s'", server.slug)
            raise UpstreamCredentialError("token mint failed", TOKEN_MINT_FAILED)

    if server.upstream_auth_header is None:
        return None
    # SECURITY: ``e.reason`` is built only from the reference and static text (SecretResolutionError's
    # contract), never the resolved plaintext, so it is safe to audit-log and to let a span record.
    try:
        if resolve_span is not None and is_reference(server.upstream_auth_header):
            with resolve_span():
                return await secrets.resolve(server.upstream_auth_header)
        return await secrets.resolve(server.upstream_auth_header)
    except SecretResolutionError as e:
        raise UpstreamCredentialError(f"secret resolution failed: {e.reason}", SECRET_RESOLUTION_FAILED)
