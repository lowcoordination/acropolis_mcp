from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request


def require_admin(request: Request, authorization: str | None = Header(default=None)) -> None:
    """M1: single admin bearer token from settings.admin_token (env var).
    M3 replaces this with a first-run wizard + hashed admin password + session cookie."""
    settings = request.app.state.settings
    if not settings.admin_token:
        # No admin token configured — control plane is unauthenticated. Acceptable for M1
        # local dev; M3's first-run wizard makes this state unreachable in practice.
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    presented = authorization[len("Bearer "):]
    if not hmac.compare_digest(presented, settings.admin_token):
        raise HTTPException(status_code=401, detail="invalid admin token")
