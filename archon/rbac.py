"""Role-based access control for the /api/v1 control plane (Enterprise #2).

Three deliberately coarse roles — viewer < operator < admin — replacing the blanket
`dependencies=[Depends(require_admin)]` gate that used to sit on the whole router (anyone who
could log in could do anything). See archon/api.py for the per-route annotations this enables.

Fail-closed is the load-bearing property here: an unrecognized role string (a typo, a row from
a future version's migration this binary doesn't know about, a hand-edited DB) must resolve to
NO ACCESS everywhere, never a permissive default. This is the same bug class as historical
finding F26 — an unvalidated `mode` string in argus/policy.py silently fell through every
`if mode == ...` check and behaved as passthrough, so enforcement the operator thought they'd
configured simply never ran. ROLE_RANK.get(role) returning None (rather than some catch-all
default rank) is what makes fail-closed the actual behavior instead of an intention.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException

from archon.admin_auth import Principal, require_admin

# Rank, not membership — require_role compares ranks so the hierarchy (viewer < operator <
# admin) is enforced by a single ">=" comparison rather than N-way equality checks, which is
# exactly the shape of bug that produces "admin can't do what operator can."
ROLE_RANK: dict[str, int] = {"viewer": 10, "operator": 20, "admin": 30}

VALID_ROLES = frozenset(ROLE_RANK)


def is_valid_role(role: str) -> bool:
    return role in ROLE_RANK


def require_role(minimum: str):
    """Dependency factory: `Depends(require_role("operator"))` on a single route, not a blanket
    router-level gate. Explicit at each call site, greppable (`grep require_role archon/api.py`
    enumerates every protected route and its floor), and testable route-by-route — see
    02-rbac.md's design decision 2 for why checking role inside handler bodies was rejected
    (invisible in the route signature, trivially forgotten on a new route).

    Raises 403 (not 404, not 401) for authenticated-but-unauthorized: the resource exists and
    the caller IS authenticated (require_admin already ran and would have raised 401 otherwise);
    they simply lack permission. Masking as 404 is defensible for secret-existence resources but
    wrong here, and makes the UI's job of explaining "why can't I do this" impossible.
    """
    if minimum not in ROLE_RANK:
        # Programmer error — a route annotated with a role that doesn't exist. Fail at import/
        # wiring time, not per-request, so this can never ship silently.
        raise ValueError(f"require_role: unknown minimum role {minimum!r}")
    minimum_rank = ROLE_RANK[minimum]

    async def _dep(principal: Principal = Depends(require_admin)) -> Principal:
        rank = ROLE_RANK.get(principal.role)  # unknown/garbage role -> None -> denied, never a default
        if rank is None or rank < minimum_rank:
            raise HTTPException(status_code=403, detail="insufficient role")
        return principal

    return _dep
