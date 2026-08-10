"""Project-scoped RBAC (Enterprise #4, issue #5) — a SECOND, INDEPENDENT role system alongside
archon/rbac.py's existing global roles, not a filter layered on top of it.

Two independent role systems, and exactly one place they touch:

- GLOBAL role (`users.role`, archon/rbac.py's `ROLE_RANK`, unchanged by this module) now means
  strictly INSTANCE-level authority: creating/deleting projects, managing users/settings, config
  import/export, GitOps. Untouched here — this module never reads ROLE_RANK.
- PROJECT role (`project_members.role`, this module's `PROJECT_ROLE_RANK`) — viewer < poweruser
  < admin, held independently per (user_id, project_id). A user can be admin in project A,
  viewer in project B, and have no membership at all (= no access) in project C, entirely
  independent of their global role.
- The one place the two touch: a user whose GLOBAL role is "admin" is an implicit "admin" in
  EVERY project, with NO membership row required (`require_project_role`'s short-circuit below).
  This is a superset relationship — it's what lets one instance admin actually administer the
  whole instance without being manually added to every project — not a parallel path a project
  admin can ignore. Every other combination requires a real, current membership row, looked up
  fresh on every request (same DB-is-authoritative pattern archon/admin_auth.py's auth_mode/
  session_version checks already use).

Fail-closed is reused verbatim from archon/rbac.py's own reasoning (same bug class as historical
finding F26): PROJECT_ROLE_RANK.get(role) returning None for a garbage/unrecognized role string
denies access, never falls through to a permissive default. No membership row at all (and not a
global admin) is exactly the same "None" outcome via .get() returning None on a missing key.
"""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request

from archon.admin_auth import Principal, require_admin

# Same three-tier shape as archon/rbac.py's ROLE_RANK, deliberately re-declared rather than
# imported/reused — this is a SEPARATE rank space (see module docstring): a "poweruser" here has
# no relationship to global "operator" other than playing the analogous middle-tier role.
# "poweruser" is this system's name for the tier "operator" plays globally (03-multi-tenancy.md's
# revision note, confirmed shape).
PROJECT_ROLE_RANK: dict[str, int] = {"viewer": 10, "poweruser": 20, "admin": 30}

VALID_PROJECT_ROLES = frozenset(PROJECT_ROLE_RANK)


def is_valid_project_role(role: str) -> bool:
    return role in PROJECT_ROLE_RANK


class ProjectNotFoundError(Exception):
    pass


async def resolve_project_role(
    *, principal: Principal, project_id: int, project_member_repo,
) -> Optional[str]:
    """Returns the caller's EFFECTIVE project role for `project_id`, or None if they have no
    access at all (no membership row and not a global admin).

    This is the single function both `require_project_role` and any route that needs to know
    "what can this user do here" (rather than just "can they do at least X") should call — the
    global-admin-superset short-circuit lives HERE, once, so it can never be forgotten at an
    individual call site the way re-deriving it inline at every route would risk.
    """
    if principal.role == "admin":
        # Global-admin superset (design decision 4): unconditional "admin" in every project, no
        # membership row required, no DB lookup needed. This must come before the membership
        # lookup, not as a fallback after a miss — a global admin ADDITIONALLY holding a lesser
        # explicit membership row (e.g. was demoted to project-viewer in A by another admin
        # before their own global role was raised) must not be capped by that stale row; the
        # global role is the floor's ceiling-breaker, always.
        return "admin"
    if principal.user_id is None:
        # Break-glass (admin_token) and legacy-admin principals both resolve role="admin" in
        # archon/admin_auth.py, so they're already handled by the branch above. A user_id-less
        # principal with a NON-admin role should not be reachable in practice (every real path
        # that produces user_id=None also produces role="admin" today) — but fail closed rather
        # than assume, since there is no membership row a None user_id could look up anyway.
        return None

    membership = await project_member_repo.get_membership(
        user_id=principal.user_id, project_id=project_id
    )
    if membership is None:
        return None
    if not is_valid_project_role(membership.role):
        # Fail-closed guard, same discipline as archon/rbac.py's require_role: an unrecognized
        # role string (hand-edited DB, a future migration this binary doesn't know about) must
        # resolve to NO ACCESS, never fall through to some default rank.
        return None
    return membership.role


async def _project_id_from_path_param(request: Request, param_name: str) -> int:
    raw = request.path_params.get(param_name)
    if raw is None:
        raise HTTPException(status_code=500, detail=f"route missing path param {param_name!r}")
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="project not found")


async def _project_id_from_server_slug(request: Request, slug_param: str) -> int:
    """Most project-owned routes key off a server SLUG in the path (`/servers/{slug}`,
    `/servers/{slug}/policy`, ...) rather than a project id directly — the project is a property
    of the resource, not of the URL. Resolves the slug to its server's project_id, 404ing (not
    403ing — matching every existing handler's own not-found convention) if the slug doesn't
    exist, so an unauthorized caller learns nothing about whether a slug exists that they
    couldn't already learn from the route's own 404 handling."""
    from db.repo import ServerNotFoundError

    slug = request.path_params.get(slug_param)
    if slug is None:
        raise HTTPException(status_code=500, detail=f"route missing path param {slug_param!r}")
    server_repo = request.app.state.server_repo
    try:
        server = await server_repo.get(slug)
    except ServerNotFoundError:
        raise HTTPException(status_code=404, detail="server not found")
    if server.project_id is None:
        # Unreachable through the app post-migration (every server gets a project_id at create
        # time), but a hand-edited DB could produce this — fail closed rather than crash.
        raise HTTPException(status_code=403, detail="server has no project assigned")
    return server.project_id


async def _project_id_from_key_id(request: Request, key_id_param: str) -> int:
    """Same shape as `_project_id_from_server_slug`, for routes keyed on `{key_id}` (PATCH/DELETE
    /keys/{key_id}, PATCH /keys/{key_id}/quota) — the project is a property of the key row."""
    raw_key_id = request.path_params.get(key_id_param)
    if raw_key_id is None:
        raise HTTPException(status_code=500, detail=f"route missing path param {key_id_param!r}")
    try:
        key_id = int(raw_key_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="key not found")
    api_keys = request.app.state.api_keys
    key = await api_keys.get(key_id)
    if key is None:
        raise HTTPException(status_code=404, detail="key not found")
    if key.project_id is None:
        raise HTTPException(status_code=403, detail="key has no project assigned")
    return key.project_id


async def _proposal_from_path_param(request: Request, param_name: str):
    """Loads the ProposalRecord named by the route's path param, 404ing if it doesn't exist —
    same not-found convention as the other resolvers. Returns the full record (not just an id)
    because `require_proposal_project_role` needs BOTH `proposal.project_id` (may legitimately
    be None — see below) and the record itself, and re-fetching it a second time in the route
    handler would be wasted work on every request."""
    from db.repo import ProposalNotFoundError

    raw = request.path_params.get(param_name)
    if raw is None:
        raise HTTPException(status_code=500, detail=f"route missing path param {param_name!r}")
    try:
        proposal_id = int(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="proposal not found")
    proposal_repo = request.app.state.proposal_repo
    try:
        return await proposal_repo.get(proposal_id)
    except ProposalNotFoundError:
        raise HTTPException(status_code=404, detail="proposal not found")


def require_proposal_project_role(minimum: str, *, proposal_id_param: str = "proposal_id"):
    """Project-scoped gate for the /proposals* routes (remediation, review 2026-08-10 — see
    0012_proposals_project_scope.sql's header for the finding this fixes).

    Deliberately NOT built on top of `require_project_role` above: every other resolver in this
    module always produces a real project_id or 404s — the project is a property of a resource
    that unconditionally belongs to exactly one project. A proposal is different. A
    'server_policy' proposal's project_id is real (the target server's project); a
    'config_import' proposal's project_id is NULL by design (config import can span every
    project in one file — see archon/approvals.py's propose_config_import). That NULL case is
    not a missing-data problem to paper over; it must force GLOBAL admin, explicitly, never
    silently fall through to "no project = no access" (which `resolve_project_role` would
    otherwise do for a bare project_id of None, since it has no membership row to look up) and
    never fall through to some permissive default either. Hence a dedicated dependency instead
    of another `project_id_param`/`server_slug_param`/`key_id_param` variant on the shared one.
    """
    if minimum not in PROJECT_ROLE_RANK:
        raise ValueError(f"require_proposal_project_role: unknown minimum project role {minimum!r}")
    minimum_rank = PROJECT_ROLE_RANK[minimum]

    async def _dep(
        request: Request,
        principal: Principal = Depends(require_admin),
    ) -> Principal:
        proposal = await _proposal_from_path_param(request, proposal_id_param)
        if proposal.project_id is None:
            # config_import proposal (or a server_policy proposal whose target server has since
            # been deleted — see the migration's backfill comment): instance-wide, global-admin
            # only. Explicit branch, not a fallthrough — resolve_project_role has no notion of
            # "no project" other than "no access", which would be the WRONG failure mode here
            # (a global admin must still be able to act on this proposal).
            if principal.role != "admin":
                raise HTTPException(status_code=403, detail="insufficient role")
            request.state.project_id = None
            return principal

        project_member_repo = request.app.state.project_member_repo
        role = await resolve_project_role(
            principal=principal, project_id=proposal.project_id,
            project_member_repo=project_member_repo,
        )
        rank = PROJECT_ROLE_RANK.get(role) if role is not None else None
        if rank is None or rank < minimum_rank:
            raise HTTPException(status_code=403, detail="insufficient project role")
        request.state.project_id = proposal.project_id
        return principal

    return _dep


def require_project_role(
    minimum: str, *, project_id_param: Optional[str] = "project_id",
    server_slug_param: Optional[str] = None, key_id_param: Optional[str] = None,
):
    """Dependency factory mirroring archon/rbac.py's `require_role` shape exactly: same
    fail-closed guarantee, same 403-not-404-for-authz convention (the caller IS authenticated —
    require_admin already ran — they simply lack permission at this project; a MISSING resource
    still 404s via the resolver helpers above, matching what the unprotected route would have
    done anyway).

    Exactly one of `project_id_param` (default), `server_slug_param`, or `key_id_param` should be
    meaningful for a given route — pass the one that names the actual path parameter this route
    has, e.g. `require_project_role("admin", project_id_param=None, server_slug_param="slug")`.
    All three funnel into the SAME `resolve_project_role()` — the global-admin-superset
    short-circuit and the fail-closed unknown-role handling are identical regardless of which
    resolver produced the project_id.
    """
    if minimum not in PROJECT_ROLE_RANK:
        raise ValueError(f"require_project_role: unknown minimum project role {minimum!r}")
    minimum_rank = PROJECT_ROLE_RANK[minimum]
    chosen = [p for p in (project_id_param, server_slug_param, key_id_param) if p is not None]
    if len(chosen) != 1:
        raise ValueError(
            "require_project_role: pass exactly one of project_id_param/server_slug_param/"
            f"key_id_param, got {chosen!r}"
        )

    async def _dep(
        request: Request,
        principal: Principal = Depends(require_admin),
    ) -> Principal:
        if server_slug_param is not None:
            project_id = await _project_id_from_server_slug(request, server_slug_param)
        elif key_id_param is not None:
            project_id = await _project_id_from_key_id(request, key_id_param)
        else:
            project_id = await _project_id_from_path_param(request, project_id_param)

        project_member_repo = request.app.state.project_member_repo
        role = await resolve_project_role(
            principal=principal, project_id=project_id, project_member_repo=project_member_repo,
        )
        rank = PROJECT_ROLE_RANK.get(role) if role is not None else None
        if rank is None or rank < minimum_rank:
            raise HTTPException(status_code=403, detail="insufficient project role")
        # Stash the resolved project_id on request.state so the route handler doesn't have to
        # re-derive it (re-fetching the server by slug a second time, etc.) — every project-
        # gated route needs it anyway to scope its repo calls.
        request.state.project_id = project_id
        return principal

    return _dep
