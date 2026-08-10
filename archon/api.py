from __future__ import annotations

import asyncio
import csv
import io
import json
import secrets
import uuid
from typing import Optional, Union

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from archon.admin_auth import Principal, require_admin
from archon.admin_audit import (
    filter_server_fields,
    filter_settings_keys,
    record,
    record_config_import,
    record_policy_change,
    record_secret_reference_change,
)
from archon.approvals import (
    SETTING_ENABLED as APPROVALS_SETTING_ENABLED,
    SETTING_TTL_DAYS as APPROVALS_SETTING_TTL_DAYS,
    ApprovalService,
    ProposalConflictError,
    ProposalError,
    ProposalResolvedError,
    ProposalStaleError,
)
from archon.auth.apikeys import ApiKeyService
from archon.config_io import export_config, plan_import
from archon.passwords import hash_password
from archon.rbac import ROLE_RANK, is_valid_role, require_role
from archon.project_rbac import (
    PROJECT_ROLE_RANK,
    is_valid_project_role,
    require_project_role,
    resolve_project_role,
)
from archon.secrets import SecretProvider, is_reference, provider_tier_name, store_upstream_auth_header
from archon.secrets.local import LocalSecretProvider
from archon.schemas import (
    AdminEventResponse,
    AuditEventResponse,
    ConfigImportAction,
    ConfigImportRequest,
    ConfigImportResponse,
    CurrentUserResponse,
    DriftActionResponse,
    DriftStatusResponse,
    KeyCreatedResponse,
    KeyCreateRequest,
    KeyQuotaUpdateRequest,
    KeyResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    ProposalApproveRequest,
    ProposalDetailResponse,
    ProposalPendingResponse,
    ProposalRejectRequest,
    ProposalResponse,
    ProjectCreateRequest,
    ProjectMemberResponse,
    ProjectMemberUpsertRequest,
    ProjectResponse,
    ServerCreateRequest,
    ServerHealthSummary,
    ServerResponse,
    ServerToolResponse,
    ServerToolsResponse,
    ServerUpdateRequest,
    SettingsResponse,
    SettingsUpdateRequest,
    StatsResponse,
    ToolTestRequest,
    ToolTestResponse,
    TracingStatusResponse,
    UsageBucketResponse,
    UsageResponse,
    UserCreateRequest,
    UserEnabledUpdateRequest,
    UserResponse,
    UserRoleUpdateRequest,
    WebhookTestResponse,
)
from argus.audit import AuditLogger
from argus.generation import ClientGeneration
from argus.pipeline import Pipeline
from argus.quotas import period_start
from argus.rate_limiter import RateLimiterRegistry, server_key
from argus.toolslist import ToolsCache
from argus.tracing import TracingManager
from db.database import utcnow
from db.repo import (
    _UNSET,
    AdminEventRepo,
    AuditRepo,
    ProjectMemberRepo,
    ProjectNotFoundError,
    ProjectRepo,
    ProjectSlugConflictError,
    ProposalNotFoundError,
    ProposalRepo,
    ServerNotFoundError,
    ServerRepo,
    SettingsRepo,
    UsageRepo,
    UserNotFoundError,
    UserRepo,
    UsernameConflictError,
    SlugConflictError,
)
from stoa.health import PROBE_TIMEOUT_SECONDS, HealthPoller
from stoa.webhooks import VALID_EVENTS, WebhookDispatcher

# Settings keys + defaults, applied when a key is absent from the settings table.
_SETTINGS_DEFAULTS = {
    "auth_mode": "keyed",
    "aggregate_enabled": "true",
    "default_ttl_ms": "300000",
    "audit_retention_days": "30",
    "webhook_enabled": "false",
    "webhook_events": "blocked,unhealthy",
    "gitops_enabled": "false",
    "gitops_poll_seconds": "300",
    "gitops_allow_private": "false",
    # Enterprise #9: approval workflows — OFF by default. Disabled = byte-identical to today;
    # the proposals table stays empty and every write path below behaves exactly as it did
    # before this feature existed.
    "approvals_enabled": "false",
    "approvals_ttl_days": "7",
}


def _server_to_response(server, project_slugs_by_id: Optional[dict[int, str]] = None) -> ServerResponse:
    project_slugs_by_id = project_slugs_by_id or {}
    return ServerResponse(
        slug=server.slug, name=server.name, upstream_url=server.upstream_url,
        enabled=server.enabled, in_aggregate=server.in_aggregate,
        upstream_protocol=server.upstream_protocol, health_status=server.health_status,
        last_seen_at=server.last_seen_at, created_at=server.created_at, updated_at=server.updated_at,
        has_upstream_auth_header=server.upstream_auth_header is not None,
        # Enterprise #5: this is the ONLY place server.upstream_auth_header's VALUE is ever
        # inspected on this control-plane read path — and only to classify its shape (does it
        # look like a reference?), never to resolve or return it. is_reference() is a pure
        # string-prefix check with no I/O, no provider call, so this stays true to the "list/get
        # never resolves" split the plan calls out as the thing that keeps secrets out of the UI.
        upstream_auth_header_is_reference=is_reference(server.upstream_auth_header),
        health_reason=server.health_reason,
        project_id=server.project_id,
        project_slug=project_slugs_by_id.get(server.project_id) if server.project_id else None,
    )


def _key_to_response(key, project_slugs_by_id: Optional[dict[int, str]] = None) -> KeyResponse:
    project_slugs_by_id = project_slugs_by_id or {}
    return KeyResponse(
        id=key.id, name=key.name, key_prefix=key.key_prefix, enabled=key.enabled,
        server_scopes=key.server_scopes, created_at=key.created_at, last_used_at=key.last_used_at,
        quota_calls=key.quota_calls, quota_period=key.quota_period,
        project_id=key.project_id,
        project_slug=project_slugs_by_id.get(key.project_id) if key.project_id else None,
    )


async def _get_settings_with_defaults(settings_repo: SettingsRepo) -> dict[str, str]:
    stored = await settings_repo.get_all()
    return {**_SETTINGS_DEFAULTS, **stored}


async def _resolve_project_id(project_repo: ProjectRepo, project_slug: str) -> int:
    """Enterprise #4: shared by every route that accepts a project_slug in its request body
    (server/key create) — 404s on an unknown slug rather than letting a typo silently create a
    NULL-project row (see 0011_projects.sql's header comment on why that must fail closed)."""
    try:
        project = await project_repo.get(project_slug)
    except ProjectNotFoundError:
        raise HTTPException(status_code=404, detail=f"project '{project_slug}' not found")
    return project.id


async def _project_slug_map(project_repo: ProjectRepo) -> dict[int, str]:
    """id -> slug for every project, used to populate ServerResponse/KeyResponse.project_slug
    without an N+1 lookup per row."""
    return {p.id: p.slug for p in await project_repo.list()}


def build_control_plane_router(
    server_repo: ServerRepo,
    api_keys: ApiKeyService,
    tools_cache: Optional[ToolsCache] = None,
    settings_repo: Optional[SettingsRepo] = None,
    audit_repo: Optional[AuditRepo] = None,
    audit_logger: Optional[AuditLogger] = None,
    health_poller: Optional[HealthPoller] = None,
    rate_limiter: Optional[RateLimiterRegistry] = None,
    pipeline: Optional[Pipeline] = None,
    webhook_dispatcher: Optional[WebhookDispatcher] = None,
    admin_event_repo: Optional[AdminEventRepo] = None,
    config_source: Optional["ConfigSource"] = None,
    user_repo: Optional[UserRepo] = None,
    secret_provider: Optional[SecretProvider] = None,
    tracing: Optional[TracingManager] = None,
    usage_repo: Optional["UsageRepo"] = None,
    project_repo: Optional[ProjectRepo] = None,
    project_member_repo: Optional[ProjectMemberRepo] = None,
    proposal_repo: Optional[ProposalRepo] = None,
) -> APIRouter:
    # enterprise #2 (RBAC): the router used to carry ONE blanket
    # dependencies=[Depends(require_admin)] gate — authenticated meant authorized for
    # everything. That's gone; every route below is individually annotated with
    # `Depends(require_role(...))` at its own minimum role. This is deliberate and explicit
    # rather than a decorator registry or in-handler checks (02-rbac.md design decision 2) —
    # `grep "require_role" archon/api.py` enumerates every protected route and its floor, and a
    # new route added without an annotation is UNPROTECTED (401 only, from require_admin having
    # never run) rather than silently permissive, which is the fail-safe direction for a mistake
    # to fail in even though the parametrised test suite is what's meant to catch it for real.
    router = APIRouter(prefix="/api/v1")
    # Enterprise #5: defaults to LocalSecretProvider (pass-through) so a router built without an
    # explicit provider — as every pre-feature test and call site does — stores/reads literals
    # exactly as before. argus/app.py wires the real, settings-selected provider.
    # Named distinctly from the stdlib `secrets` module (imported at top of file, used by
    # update_settings below for secrets.token_hex) — this function's own scope would otherwise
    # shadow it for the rest of the closure, breaking any call to the stdlib module made
    # anywhere inside build_control_plane_router after this point.
    secret_backend = secret_provider or LocalSecretProvider()

    # Enterprise #9: approval workflows. Built whenever a ProposalRepo is wired (the real app
    # always wires one; tests that don't care about approvals leave it None and get byte-
    # identical behaviour, matching how project_repo/usage_repo were made optional). The
    # feature's own off/on switch is the DB-backed approvals_enabled setting, read live by
    # ApprovalService.enabled() on every write — not construction here.
    approvals = None
    if proposal_repo is not None and settings_repo is not None:
        approvals = ApprovalService(
            proposal_repo=proposal_repo,
            server_repo=server_repo,
            settings_repo=settings_repo,
            admin_event_repo=admin_event_repo,
            project_repo=project_repo,
            tools_cache=tools_cache,
            webhook_dispatcher=webhook_dispatcher,
        )

    # F21 fix (review 2026-08-04): /api/v1/health used to live HERE, behind require_admin —
    # but both the Dockerfile HEALTHCHECK and the k8s liveness/readiness probes target it
    # unauthenticated. Once first-run setup completes, they started getting 401s: the k8s pod
    # entered a restart loop (livenessProbe failureThreshold=3 * periodSeconds=30 ≈ pod killed
    # ~90s after setup) and the compose container reported permanently unhealthy. Moved to
    # archon/setup.py's router, which is deliberately never behind require_admin — see that
    # module for the actual route.

    # Enterprise #4 (multi-tenancy, issue #5): servers are a PROJECT-owned resource — every route
    # below that touches one switches from require_role (global) to require_project_role
    # (project-scoped). GET /servers with no project filter is the one exception among the
    # "list" routes: it stays require_role("viewer") + returns EVERY server regardless of
    # project, because a project_id isn't derivable from the route itself (there's no
    # {project_id}/{slug} in the URL) — the frontend passes a `project_id` QUERY param to scope
    # it client-side-requested, and a caller who omits it gets the instance-wide list, same
    # shape as GET /users (also instance-wide, also viewer+). This does NOT leak project-scoped
    # authority: /servers is `viewer`-gated globally same as before, and a global viewer could
    # already see every server pre-this-feature (RBAC's ROLE_RANK never had a per-server
    # dimension until now) — enumerating project_slug alongside each row is strictly less new
    # information than the slug/upstream_url/policy every viewer already saw. Project-scoped
    # WRITE routes below are what actually enforce the new boundary.
    @router.get("/servers", response_model=list[ServerResponse], dependencies=[Depends(require_role("viewer"))])
    async def list_servers(project_id: Optional[int] = None):
        servers = await server_repo.list(project_id=project_id)
        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return [_server_to_response(s, project_slugs) for s in servers]

    @router.post("/servers", response_model=ServerResponse, status_code=201)
    async def create_server(
        body: ServerCreateRequest, request: Request,
        principal: Principal = Depends(require_admin),
    ):
        # Enterprise #4: the project is named in the REQUEST BODY (project_slug), not the URL
        # path, so this can't use require_project_role's path-param resolvers as a route
        # dependency the way slug-keyed routes below do — the body has to be parsed first. Same
        # fail-closed resolve_project_role() call those dependencies use internally, just
        # invoked directly here after resolving project_slug -> project_id. Creating a server
        # requires project-admin in the TARGET project (or global admin, via the superset).
        project_id = await _resolve_project_id(project_repo, body.project_slug)
        role = await resolve_project_role(
            principal=principal, project_id=project_id, project_member_repo=project_member_repo,
        )
        if PROJECT_ROLE_RANK.get(role) is None or PROJECT_ROLE_RANK[role] < PROJECT_ROLE_RANK["admin"]:
            raise HTTPException(status_code=403, detail="insufficient project role")

        # Enterprise #5: what actually lands in the DB may differ from what the operator typed —
        # a literal typed while the `encrypted` tier is selected is encrypted here BEFORE it
        # ever reaches server_repo.create; a vault:// reference or a literal under `local`/
        # `openbao` is stored exactly as typed. See store_upstream_auth_header's docstring.
        stored_auth_header = await store_upstream_auth_header(secret_backend, body.upstream_auth_header)
        try:
            server = await server_repo.create(
                slug=body.slug, name=body.name, upstream_url=body.upstream_url,
                enabled=body.enabled, in_aggregate=body.in_aggregate,
                upstream_auth_header=stored_auth_header,
                project_id=project_id,
            )
        except SlugConflictError:
            raise HTTPException(status_code=409, detail=f"server slug '{body.slug}' already exists")

        if admin_event_repo is not None:
            await record(
                admin_event_repo,
                action="server.create",
                summary=f"created server '{body.slug}'",
                actor=principal.actor,
                target_type="server",
                target_id=body.slug,
                after=filter_server_fields({
                    "slug": body.slug,
                    "name": body.name,
                    "upstream_url": body.upstream_url,
                    "enabled": body.enabled,
                    "in_aggregate": body.in_aggregate,
                }),
                client_ip=request.client.host if request.client else None,
            )
            # Enterprise #5: a distinct event from server.create above — see
            # record_secret_reference_change's docstring on why the credential's change is
            # tracked separately from the rest of the server fields (never the value, in either
            # event).
            await record_secret_reference_change(
                admin_event_repo, server_slug=body.slug,
                before_value=None, after_value=stored_auth_header,
                actor=principal.actor, client_ip=request.client.host if request.client else None,
            )

        if health_poller is not None:
            # Probe immediately rather than leaving the server at "unknown" for up to a full
            # poll interval (60s default) — a first-time user's very first action shouldn't
            # feel broken while they wait. A failed probe still returns 201 for the server
            # itself; health_status just reflects "unhealthy" instead of "unknown".
            try:
                await health_poller.poll_one(server.slug)
            except Exception:
                pass  # best-effort; the background poller will retry on its own schedule
            server = await server_repo.get(server.slug)

        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return _server_to_response(server, project_slugs)

    @router.post(
        "/servers/{slug}/probe", response_model=ServerResponse,
        dependencies=[Depends(require_project_role("poweruser", project_id_param=None, server_slug_param="slug"))],
    )
    async def probe_server_now(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        if health_poller is not None:
            await health_poller.poll_one(slug)
            if tools_cache is not None:
                # A manual re-probe is also the natural moment to refresh the tool catalog —
                # e.g. after the operator adds a new tool to their own MCP server.
                #
                # §26 fix (review 2026-08-04): get_raw_tools has no timeout of its own — it
                # rides the shared http client's default (settings.upstream_timeout_seconds,
                # 120s), sized for a real tool call, not a quick "did the probe work" check.
                # poll_one() above is already bounded to PROBE_TIMEOUT_SECONDS (10s), but this
                # follow-up tools/list call was not, so this endpoint — meant to feel like an
                # instant re-probe click in the UI — could hang the HTTP request for up to
                # ~130s total against a slow/hung upstream. Bound it to the same probe budget;
                # a timed-out tools refresh just means the operator sees the OLD cached tool
                # list a little longer, which is a fine degradation for what's meant to be a
                # quick health check, not a hard failure.
                try:
                    await asyncio.wait_for(
                        tools_cache.get_raw_tools(
                            server.id, server.upstream_url, force_refresh=True,
                            upstream_auth_header=server.upstream_auth_header,
                        ),
                        timeout=PROBE_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    pass
        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return _server_to_response(await server_repo.get(slug), project_slugs)

    @router.get(
        "/servers/{slug}", response_model=ServerResponse,
        dependencies=[Depends(require_project_role("viewer", project_id_param=None, server_slug_param="slug"))],
    )
    async def get_server(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return _server_to_response(server, project_slugs)

    @router.put("/servers/{slug}", response_model=ServerResponse)
    async def update_server(
        slug: str, body: ServerUpdateRequest, request: Request,
        principal: Principal = Depends(
            require_project_role("admin", project_id_param=None, server_slug_param="slug")
        ),
    ):
        # F23: upstream_auth_header needs three states (unset/set-to-value/cleared-to-null),
        # which a plain `Optional[str] = None` field can't distinguish on its own — checking
        # model_fields_set tells us whether the key was present in the request body at all.
        auth_header_update = (
            body.upstream_auth_header if "upstream_auth_header" in body.model_fields_set else _UNSET
        )
        # Enterprise #5: same store-before-persist treatment as create_server — only when the
        # field was actually part of this request (a bare _UNSET must never be passed through
        # store_upstream_auth_header, which only understands Optional[str]).
        if auth_header_update is not _UNSET:
            auth_header_update = await store_upstream_auth_header(secret_backend, auth_header_update)
        try:
            # Fetch before state for audit diff
            before_server = await server_repo.get(slug)
            before_dict = filter_server_fields({
                "slug": before_server.slug,
                "name": before_server.name,
                "upstream_url": before_server.upstream_url,
                "enabled": before_server.enabled,
                "in_aggregate": before_server.in_aggregate,
            })

            server = await server_repo.update(
                slug, name=body.name, upstream_url=body.upstream_url,
                enabled=body.enabled, in_aggregate=body.in_aggregate,
                upstream_auth_header=auth_header_update,
            )
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")

        if admin_event_repo is not None:
            after_dict = filter_server_fields({
                "slug": server.slug,
                "name": server.name,
                "upstream_url": server.upstream_url,
                "enabled": server.enabled,
                "in_aggregate": server.in_aggregate,
            })
            changes = []
            for key in before_dict:
                if before_dict[key] != after_dict.get(key):
                    changes.append(f"{key}: {before_dict[key]} -> {after_dict.get(key)}")
            summary = f"updated server '{slug}'" + (f" ({'; '.join(changes)})" if changes else "")

            await record(
                admin_event_repo,
                action="server.update",
                summary=summary,
                actor=principal.actor,
                target_type="server",
                target_id=slug,
                before=before_dict,
                after=after_dict,
                client_ip=request.client.host if request.client else None,
            )
            # Enterprise #5: fires only when upstream_auth_header was actually part of this
            # request (auth_header_update is _UNSET otherwise, which never reaches server_repo.
            # update as a change and must not be reported as one here either — before_server's
            # value equals server's in that case, so record_secret_reference_change's own
            # no-op-if-unchanged check makes this safe even without the extra condition, but the
            # condition documents the intent explicitly).
            if "upstream_auth_header" in body.model_fields_set:
                await record_secret_reference_change(
                    admin_event_repo, server_slug=slug,
                    before_value=before_server.upstream_auth_header,
                    after_value=server.upstream_auth_header,
                    actor=principal.actor, client_ip=request.client.host if request.client else None,
                )

        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return _server_to_response(server, project_slugs)

    @router.delete("/servers/{slug}", status_code=204)
    async def delete_server(
        slug: str, request: Request,
        principal: Principal = Depends(
            require_project_role("admin", project_id_param=None, server_slug_param="slug")
        ),
    ):
        try:
            # Fetch before state for audit
            server = await server_repo.get(slug)
            before_dict = filter_server_fields({
                "slug": server.slug,
                "name": server.name,
                "upstream_url": server.upstream_url,
                "enabled": server.enabled,
                "in_aggregate": server.in_aggregate,
            })

            await server_repo.delete(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")

        if admin_event_repo is not None:
            await record(
                admin_event_repo,
                action="server.delete",
                summary=f"deleted server '{slug}'",
                actor=principal.actor,
                target_type="server",
                target_id=slug,
                before=before_dict,
                client_ip=request.client.host if request.client else None,
            )

        if rate_limiter is not None:
            # F8: the rate-limit bucket is keyed on the slug STRING, not the server's DB id —
            # if this slug is deleted and later recreated with a different rate_limit, the old
            # bucket (and its old consumed-token state) must not still be registered under it.
            rate_limiter.unregister(server_key(slug))

    @router.get(
        "/servers/{slug}/tools", response_model=ServerToolsResponse,
        dependencies=[Depends(require_project_role("viewer", project_id_param=None, server_slug_param="slug"))],
    )
    async def get_server_tools(slug: str, force_refresh: bool = False):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")

        policy = await server_repo.get_policy(server.id)

        if tools_cache is None:
            return ServerToolsResponse(fetched_at=None, tools=[])

        tools = await tools_cache.get_raw_tools(
            server.id, server.upstream_url, force_refresh=force_refresh,
            upstream_auth_header=server.upstream_auth_header,
        )
        result = []
        for tool in tools:
            name = tool.get("name", "")
            if policy.mode == "allowlist":
                status = "allowed" if name in policy.allowed else "denied"
            elif policy.mode == "denylist":
                status = "denied" if name in policy.denied else "allowed"
            else:
                status = "allowed"  # passthrough
            result.append(ServerToolResponse(
                name=name,
                description=tool.get("description"),
                status=status,
                has_param_rules=name in policy.param_rules,
                # Feature #1 (tool tester): the raw upstream tool definition already carries its
                # JSON Schema under this key (MCP spec) — it was just never passed through before.
                input_schema=tool.get("inputSchema"),
            ))
        fetched_at = await tools_cache.fetched_at(server.id)
        return ServerToolsResponse(fetched_at=fetched_at, tools=result)

    if pipeline is not None:
        @router.post(
            "/servers/{slug}/test-call", response_model=ToolTestResponse,
            dependencies=[Depends(
                require_project_role("poweruser", project_id_param=None, server_slug_param="slug")
            )],
        )
        async def test_call(slug: str, request: Request, body: ToolTestRequest):
            # Feature #1 (in-UI tool tester): dispatches through the REAL pipeline — real rate
            # limiting, real policy evaluation, real audit logging — rather than a second
            # evaluator that could drift from the one actually enforcing. `skip_api_key_auth`
            # bypasses only the data plane's bearer-token check (the caller is already
            # authenticated with at least project-poweruser via require_project_role above); `force_generation`
            # forces the bridged path so this always goes through the same evaluate() call a
            # real 2026-generation client's tools/call would. `origin="test"` tags the resulting
            # audit row so it never counts toward /stats or the default Audit page view.
            try:
                await server_repo.get(slug)
            except ServerNotFoundError:
                raise HTTPException(status_code=404, detail="server not found")

            rpc_body = json.dumps({
                # Unique id per call — see argus/upstream.py's _handshake for the reasoning.
                "jsonrpc": "2.0", "id": f"acropolis-test-call-{uuid.uuid4()}", "method": "tools/call",
                "params": {"name": body.tool, "arguments": body.arguments},
            }).encode("utf-8")

            captured: list[dict] = []
            audit_queue = audit_logger.subscribe() if audit_logger is not None else None
            try:
                response = await pipeline.handle(
                    request, slug, "", body_override=rpc_body,
                    force_generation=ClientGeneration.GEN_2026,
                    skip_api_key_auth=True, origin="test",
                )
                # The audit event for THIS call was broadcast synchronously inside handle(),
                # before it returned — drain whatever's already queued rather than waiting,
                # since nothing else will arrive after this call returns.
                if audit_queue is not None:
                    while not audit_queue.empty():
                        captured.append(audit_queue.get_nowait())
            finally:
                if audit_queue is not None:
                    audit_logger.unsubscribe(audit_queue)

            event = captured[-1] if captured else {}
            try:
                upstream_response = json.loads(response.body) if response.body else None
            except json.JSONDecodeError:
                upstream_response = None

            return ToolTestResponse(
                decision=event.get("decision", "ERROR"),
                rule=event.get("rule"),
                matched=event.get("matched"),
                reason=event.get("reason"),
                status_code=event.get("status_code") or response.status_code,
                latency_ms=event.get("latency_ms"),
                upstream_response=upstream_response,
            )

    @router.get(
        "/servers/{slug}/policy", response_model=PolicyResponse,
        dependencies=[Depends(require_project_role("viewer", project_id_param=None, server_slug_param="slug"))],
    )
    async def get_policy(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        policy = await server_repo.get_policy(server.id)
        return PolicyResponse(**policy.model_dump())

    @router.put("/servers/{slug}/policy", response_model=Union[PolicyResponse, ProposalPendingResponse])
    async def set_policy(
        slug: str, body: PolicyUpdateRequest, request: Request,
        principal: Principal = Depends(
            require_project_role("poweruser", project_id_param=None, server_slug_param="slug")
        ),
    ):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")

        # Enterprise #9: when approval workflows are enabled, a policy write is QUEUED, not
        # applied — PUT returns 202 + the proposal id and nothing about the server changes
        # (policy unchanged on re-read, tools cache untouched, no policy.update event). The
        # four-eyes gate applies to EVERYONE, including admins ("four-eyes that admins can
        # bypass is theater" — plan design decision 4); the approver gate is
        # require_role("admin") on POST /proposals/{id}/approve.
        if approvals is not None and await approvals.enabled():
            proposal = await approvals.propose_policy_change(
                server_slug=slug,
                requested=body.model_dump(),
                proposer=principal,
                client_ip=request.client.host if request.client else None,
            )
            return JSONResponse(
                status_code=202,
                content={
                    "proposal_id": proposal.id,
                    "state": proposal.state,
                    "message": "change queued for approval",
                },
            )

        # Fetch before state for audit diff
        before_policy = await server_repo.get_policy(server.id)

        await server_repo.set_policy(server.id, body)
        if tools_cache is not None:
            # A stale filtered tools/list would otherwise show a tool that was just denied,
            # or hide one that was just allowed, until the TTL naturally expires.
            await tools_cache.invalidate(server.id)

        # Fetch after state for audit diff
        after_policy = await server_repo.get_policy(server.id)

        if admin_event_repo is not None:
            await record_policy_change(
                admin_event_repo,
                server_slug=slug,
                current=before_policy,
                incoming=after_policy,
                actor=principal.actor,
                client_ip=request.client.host if request.client else None,
            )

        return PolicyResponse(**after_policy.model_dump())

    # Enterprise #4: keys are project-owned (design decision 7 — project-bound transitively).
    # GET /keys with no project filter stays global-admin-only exactly as before (a full,
    # cross-project key listing is instance-wide sensitive information, unlike GET /servers'
    # already-visible-to-viewers shape above) — a project admin sees their OWN project's keys via
    # the `project_id` query param on this SAME route, gated by resolve_project_role inline below
    # since a bare `require_role("admin")` would wrongly exclude a project-admin-but-global-viewer
    # from ever listing their own project's keys, and require_project_role's path-param
    # resolvers don't fit a query-param-scoped list route.
    @router.get("/keys", response_model=list[KeyResponse])
    async def list_keys(
        project_id: Optional[int] = None,
        principal: Principal = Depends(require_admin),
    ):
        if project_id is None:
            if principal.role != "admin":
                raise HTTPException(status_code=403, detail="insufficient role")
            keys = await api_keys.list()
        else:
            role = await resolve_project_role(
                principal=principal, project_id=project_id, project_member_repo=project_member_repo,
            )
            if PROJECT_ROLE_RANK.get(role) is None or PROJECT_ROLE_RANK[role] < PROJECT_ROLE_RANK["admin"]:
                raise HTTPException(status_code=403, detail="insufficient project role")
            keys = await api_keys.list(project_id=project_id)
        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return [_key_to_response(k, project_slugs) for k in keys]

    @router.post("/keys", response_model=KeyCreatedResponse, status_code=201)
    async def create_key(
        body: KeyCreateRequest, request: Request,
        principal: Principal = Depends(require_admin),
    ):
        # 02-rbac.md design decision 3: key minting is a privileged action, not merely because
        # keys feel sensitive — a caller who could mint a key could use it against the DATA
        # plane and act entirely outside their control-plane role, which would make the
        # poweruser/admin boundary trivially bypassable. Enterprise #4: now project-admin (of
        # the TARGET project) rather than unconditionally global-admin — see
        # tests/integration/test_rbac.py's "operator cannot mint a key" case for the global-role
        # analogue this mirrors at the project level.
        project_id = await _resolve_project_id(project_repo, body.project_slug)
        role = await resolve_project_role(
            principal=principal, project_id=project_id, project_member_repo=project_member_repo,
        )
        if PROJECT_ROLE_RANK.get(role) is None or PROJECT_ROLE_RANK[role] < PROJECT_ROLE_RANK["admin"]:
            raise HTTPException(status_code=403, detail="insufficient project role")

        generated = await api_keys.create(
            name=body.name, server_scopes=body.server_scopes,
            quota_calls=body.quota_calls, quota_period=body.quota_period,
            project_id=project_id,
        )

        if admin_event_repo is not None:
            after = {
                "name": body.name, "key_prefix": generated.record.key_prefix,
                "server_scopes": body.server_scopes,
            }
            # Enterprise #11: only recorded when actually set, so a plain key-create's
            # admin-event summary stays exactly as it read before this feature existed — see
            # tests/integration/test_admin_events.py's key.create shape assertions.
            if body.quota_calls is not None:
                after["quota_calls"] = body.quota_calls
                after["quota_period"] = body.quota_period
            await record(
                admin_event_repo,
                action="key.create",
                summary=f"created API key '{body.name}'",
                actor=principal.actor,
                target_type="key",
                target_id=str(generated.record.id),
                after=after,
                client_ip=request.client.host if request.client else None,
            )

        return KeyCreatedResponse(
            id=generated.record.id, name=generated.record.name,
            key_prefix=generated.record.key_prefix, plaintext=generated.plaintext,
        )

    @router.patch("/keys/{key_id}", response_model=KeyResponse)
    async def patch_key(
        key_id: int, enabled: bool, request: Request,
        principal: Principal = Depends(
            require_project_role("admin", project_id_param=None, key_id_param="key_id")
        ),
    ):
        # Fetch before state for audit
        key_before = await api_keys.get(key_id)

        if enabled:
            await api_keys.enable(key_id)
        else:
            await api_keys.disable(key_id)

        key_after = await api_keys.get(key_id)
        if key_after is None:
            raise HTTPException(status_code=404, detail="key not found")

        if admin_event_repo is not None and key_before is not None:
            action = "key.enable" if enabled else "key.disable"
            await record(
                admin_event_repo,
                action=action,
                summary=f"{'enabled' if enabled else 'disabled'} API key '{key_after.name}'",
                actor=principal.actor,
                target_type="key",
                target_id=str(key_id),
                before={"enabled": key_before.enabled},
                after={"enabled": enabled},
                client_ip=request.client.host if request.client else None,
            )

        # Fix (review 2026-08-10): every other _key_to_response call site passes the
        # project_slugs map (see list_keys/create_key above) so KeyResponse.project_slug is
        # populated; this route omitted it, so a PATCHed key with a real project would come
        # back with project_slug: null until the next full GET/list refetched it.
        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return _key_to_response(key_after, project_slugs)

    @router.patch(
        "/keys/{key_id}/quota", response_model=KeyResponse,
        dependencies=[Depends(
            require_project_role("admin", project_id_param=None, key_id_param="key_id")
        )],
    )
    async def patch_key_quota(
        key_id: int, body: KeyQuotaUpdateRequest, request: Request,
        principal: Principal = Depends(require_admin),
    ):
        """Enterprise #11: sets or clears a key's quota. A separate route from PATCH /keys/{id}
        (see KeyQuotaUpdateRequest's docstring) — project-admin-only, same as every other
        key-mutating route (02-rbac.md design decision 3: a key is a data-plane credential, so
        changing what it can do is as sensitive as minting one; enterprise #4 moves the floor
        from global-admin to project-admin, same as key minting above)."""
        key_before = await api_keys.get(key_id)
        if key_before is None:
            raise HTTPException(status_code=404, detail="key not found")

        await api_keys.set_quota(key_id, body.quota_calls, body.quota_period)
        key_after = await api_keys.get(key_id)

        if admin_event_repo is not None and key_after is not None:
            await record(
                admin_event_repo,
                action="key.quota_update",
                summary=(
                    f"set quota on API key '{key_after.name}': {body.quota_calls}/{body.quota_period}"
                    if body.quota_calls is not None
                    else f"cleared quota on API key '{key_after.name}'"
                ),
                actor=principal.actor,
                target_type="key",
                target_id=str(key_id),
                before={"quota_calls": key_before.quota_calls, "quota_period": key_before.quota_period},
                after={"quota_calls": body.quota_calls, "quota_period": body.quota_period},
                client_ip=request.client.host if request.client else None,
            )

        project_slugs = await _project_slug_map(project_repo) if project_repo is not None else {}
        return _key_to_response(key_after, project_slugs)

    @router.delete("/keys/{key_id}", status_code=204)
    async def delete_key(
        key_id: int, request: Request,
        principal: Principal = Depends(
            require_project_role("admin", project_id_param=None, key_id_param="key_id")
        ),
    ):
        # Fetch before state for audit
        key_before = await api_keys.get(key_id)

        await api_keys.delete(key_id)

        if admin_event_repo is not None and key_before is not None:
            await record(
                admin_event_repo,
                action="key.delete",
                summary=f"deleted API key '{key_before.name}'",
                actor=principal.actor,
                target_type="key",
                target_id=str(key_id),
                before={"name": key_before.name, "key_prefix": key_before.key_prefix},
                client_ip=request.client.host if request.client else None,
            )

    if settings_repo is not None:
        @router.get("/settings", response_model=SettingsResponse, dependencies=[Depends(require_role("viewer"))])
        async def get_settings():
            values = await _get_settings_with_defaults(settings_repo)
            return SettingsResponse(
                auth_mode=values["auth_mode"],
                aggregate_enabled=values["aggregate_enabled"] == "true",
                default_ttl_ms=int(values["default_ttl_ms"]),
                audit_retention_days=int(values["audit_retention_days"]),
                setup_complete=await settings_repo.get("admin_password_hash") is not None,
                webhook_url=values.get("webhook_url"),
                webhook_enabled=values["webhook_enabled"] == "true",
                webhook_events=values["webhook_events"].split(","),
                webhook_allow_private=values.get("webhook_allow_private") == "true",
                has_webhook_secret=bool(values.get("webhook_secret")),
                secret_provider=provider_tier_name(secret_backend),
                approvals_enabled=values["approvals_enabled"] == "true",
                approvals_ttl_days=int(values["approvals_ttl_days"]),
            )

        @router.put("/settings", response_model=SettingsResponse)
        async def update_settings(
            body: SettingsUpdateRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            # Fetch before state for audit diff
            before_settings = await _get_settings_with_defaults(settings_repo)
            before_filtered = filter_settings_keys(before_settings)

            updates: dict[str, str] = {}
            if body.auth_mode is not None:
                if body.auth_mode not in ("open", "keyed"):
                    raise HTTPException(status_code=400, detail="auth_mode must be 'open' or 'keyed'")
                updates["auth_mode"] = body.auth_mode
            if body.aggregate_enabled is not None:
                updates["aggregate_enabled"] = "true" if body.aggregate_enabled else "false"
            if body.default_ttl_ms is not None:
                updates["default_ttl_ms"] = str(body.default_ttl_ms)
            if body.audit_retention_days is not None:
                updates["audit_retention_days"] = str(body.audit_retention_days)
            if body.webhook_allow_private is not None:
                updates["webhook_allow_private"] = "true" if body.webhook_allow_private else "false"
            if body.webhook_url is not None:
                # "" clears it — SettingsUpdateRequest's field validator already ran
                # _validate_webhook_url on a truthy value, so anything non-empty here is safe.
                updates["webhook_url"] = body.webhook_url
                if body.webhook_url and await settings_repo.get("webhook_secret") is None:
                    # Generate the HMAC signing secret lazily, on first real URL, rather than at
                    # app startup — no reason to mint a secret nobody will ever use on an
                    # instance that never configures a webhook.
                    updates["webhook_secret"] = secrets.token_hex(32)
            if body.webhook_enabled is not None:
                updates["webhook_enabled"] = "true" if body.webhook_enabled else "false"
            if body.webhook_events is not None:
                bad = [e for e in body.webhook_events if e not in VALID_EVENTS]
                if bad:
                    raise HTTPException(
                        status_code=400,
                        detail=f"webhook_events contains unsupported value(s): {bad}",
                    )
                updates["webhook_events"] = ",".join(body.webhook_events)
            # Enterprise #9: approvals on/off + TTL. TTL must be a positive integer (same
            # fail-fast validation the retention window gets); <= 0 at expiry time means "keep
            # forever" — the >0 check here just stops a mistyped 0/-1 from being silently
            # accepted as a "keep forever" someone didn't mean to set.
            if body.approvals_enabled is not None:
                updates[APPROVALS_SETTING_ENABLED] = "true" if body.approvals_enabled else "false"
            if body.approvals_ttl_days is not None:
                if body.approvals_ttl_days <= 0:
                    raise HTTPException(
                        status_code=400,
                        detail="approvals_ttl_days must be a positive integer (0 means keep "
                               "proposals forever, set it explicitly via the settings table)",
                    )
                updates[APPROVALS_SETTING_TTL_DAYS] = str(body.approvals_ttl_days)
            await settings_repo.set_many(updates)

            # Fetch after state for audit diff
            after_settings = await _get_settings_with_defaults(settings_repo)
            after_filtered = filter_settings_keys(after_settings)

            if admin_event_repo is not None:
                changes = []
                for key in before_filtered:
                    if before_filtered[key] != after_filtered.get(key):
                        changes.append(f"{key}: {before_filtered[key]} -> {after_filtered.get(key)}")
                summary = "updated settings" + (f" ({'; '.join(changes)})" if changes else "")

                await record(
                    admin_event_repo,
                    action="settings.update",
                    summary=summary,
                    actor=principal.actor,
                    target_type="settings",
                    before=before_filtered,
                    after=after_filtered,
                    client_ip=request.client.host if request.client else None,
                )

            return await get_settings()

        @router.get("/config/export", dependencies=[Depends(require_role("viewer"))])
        async def export_configuration(
            include_credentials: bool = False,
            principal: Principal = Depends(require_admin),
        ):
            # Judgment call beyond what 02-rbac.md's table spells out: plain "config export" is
            # viewer-level there, but include_credentials=true returns PLAINTEXT upstream auth
            # headers and the webhook signing secret (see config_io.py) — letting a viewer
            # request that would hand them exactly the credentials the operator/admin boundary
            # exists to protect. Base export stays viewer; the credentials variant is admin-only.
            if include_credentials and (
                ROLE_RANK.get(principal.role) is None or ROLE_RANK[principal.role] < ROLE_RANK["admin"]
            ):
                raise HTTPException(status_code=403, detail="include_credentials requires admin role")
            result = await export_config(
                server_repo, settings_repo, include_credentials=include_credentials,
                project_repo=project_repo,
            )
            filename = f"acropolis-config-{utcnow().replace(':', '').split('.')[0]}.yaml"
            headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
            if result.warnings:
                # Surfaced as a header as well as inside the file, so a CLI/curl user piping
                # straight to disk still has a way to see it without opening the file.
                headers["X-Acropolis-Export-Warnings"] = " | ".join(result.warnings)
            return Response(
                content=result.to_yaml(), media_type="application/x-yaml", headers=headers
            )

        @router.post("/config/import", response_model=Union[ConfigImportResponse, ProposalPendingResponse])
        async def import_configuration(
            body: ConfigImportRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            # 02-rbac.md design decision 1: config import is admin-only even though it edits
            # policies (which operators may do directly) — one import rewrites the entire
            # instance in one shot, a different blast radius from a single server's policy.
            # Enterprise #4: stays global-admin-only, UNCHANGED gate — a project admin does not
            # get config-import authority merely by being a project admin (03-multi-tenancy.md
            # design decision 8). Only the YAML shape changes (project_slug per server).
            # Enterprise #9: config import is a policy-shaped mutation by blast radius (the
            # same reasoning that made it admin-only) — with approvals on, an apply=true import
            # is QUEUED as a proposal and returns 202 instead of applying; the proposal's
            # approve path recomputes the plan against current state (dry-run stays as-is: a
            # preview changes nothing).
            if body.apply and approvals is not None and await approvals.enabled():
                proposal = await approvals.propose_config_import(
                    yaml_text=body.yaml, proposer=principal,
                    client_ip=request.client.host if request.client else None,
                )
                return JSONResponse(
                    status_code=202,
                    content={
                        "proposal_id": proposal.id,
                        "state": proposal.state,
                        "message": "change queued for approval",
                    },
                )

            plan = await plan_import(
                server_repo, settings_repo, body.yaml, apply=body.apply, project_repo=project_repo,
            )

            # Record config import as ONE event, not one per touched server — otherwise a
            # routine import drowns the log it's supposed to make legible.
            if admin_event_repo is not None and body.apply and plan.ok:
                action_descriptions = [a.describe(applied=True) for a in plan.actions]
                await record_config_import(
                    admin_event_repo,
                    actions=action_descriptions,
                    actor=principal.actor,
                    client_ip=request.client.host if request.client else None,
                )

            return ConfigImportResponse(
                # `applied` reflects what ACTUALLY happened, not what was asked for: a file with
                # errors is rejected wholesale, so apply=true + errors still means nothing wrote.
                applied=body.apply and plan.ok,
                ok=plan.ok,
                actions=[
                    ConfigImportAction(
                        kind=a.kind, target=a.target, detail=a.detail,
                        description=a.describe(applied=body.apply and plan.ok),
                    )
                    for a in plan.actions
                ],
                warnings=plan.warnings,
                errors=plan.errors,
            )

    if approvals is not None:
        # Enterprise #9: the approval-workflow surface. Everything here is global-admin-gated
        # (require_role("admin"), same gate as config import): proposals carry the full policy
        # intent / import YAML, which can include plaintext upstream credentials when an
        # operator imports a file exported with include_credentials=true — a viewer or
        # poweruser must never be able to list those. The four-eyes *proposer* gate stays where
        # it always was (the write routes above queue proposals from anyone who could have made
        # the write directly); the *approver* gate is here.

        def _proposal_to_response(proposal) -> ProposalResponse:
            return ProposalResponse(
                id=proposal.id,
                target_type=proposal.target_type,
                target_id=proposal.target_id,
                proposer=proposal.proposer,
                state=proposal.state,
                created_at=proposal.created_at,
                resolved_at=proposal.resolved_at,
                resolver=proposal.resolver,
                resolution_reason=proposal.resolution_reason,
            )

        @router.get(
            "/proposals", response_model=list[ProposalResponse],
            dependencies=[Depends(require_role("admin"))],
        )
        async def list_proposals(state: Optional[str] = None):
            if state is not None and state not in ("pending", "approved", "rejected", "expired"):
                raise HTTPException(
                    status_code=400,
                    detail=f"invalid state {state!r}; must be one of: pending, approved, "
                           "rejected, expired",
                )
            return [_proposal_to_response(p) for p in await proposal_repo.list(state=state)]

        @router.get(
            "/proposals/{proposal_id}", response_model=ProposalDetailResponse,
            dependencies=[Depends(require_role("admin"))],
        )
        async def get_proposal(proposal_id: int):
            try:
                proposal = await proposal_repo.get(proposal_id)
            except ProposalNotFoundError:
                raise HTTPException(status_code=404, detail="proposal not found")
            preview, stale = await approvals.preview(proposal)
            base = _proposal_to_response(proposal).model_dump()
            return ProposalDetailResponse(**base, preview=preview, stale=stale)

        @router.post(
            "/proposals/{proposal_id}/approve", response_model=ProposalResponse,
        )
        async def approve_proposal(
            proposal_id: int, body: ProposalApproveRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            try:
                resolved = await approvals.approve(
                    proposal_id=proposal_id, principal=principal,
                    reason=body.reason,
                    client_ip=request.client.host if request.client else None,
                )
            except ProposalNotFoundError:
                raise HTTPException(status_code=404, detail="proposal not found")
            except ProposalStaleError as e:
                # 409 Conflict: the target changed since the proposal was created — the change
                # must be re-proposed/re-reviewed, never blindly applied (the TOCTOU guard).
                raise HTTPException(status_code=409, detail=str(e))
            except ProposalResolvedError as e:
                raise HTTPException(status_code=409, detail=str(e))
            except ProposalConflictError as e:
                # 403 with a DISTINCT message from a plain role failure, per the plan's
                # verification item 2 ("self-approval rejected (403, distinct message)").
                raise HTTPException(status_code=403, detail=str(e))
            except ProposalError as e:
                raise HTTPException(status_code=400, detail=str(e))
            return _proposal_to_response(resolved)

        @router.post(
            "/proposals/{proposal_id}/reject", response_model=ProposalResponse,
        )
        async def reject_proposal(
            proposal_id: int, body: ProposalRejectRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            try:
                resolved = await approvals.reject(
                    proposal_id=proposal_id, principal=principal,
                    reason=body.reason,
                    client_ip=request.client.host if request.client else None,
                )
            except ProposalNotFoundError:
                raise HTTPException(status_code=404, detail="proposal not found")
            except ProposalResolvedError as e:
                raise HTTPException(status_code=409, detail=str(e))
            except ProposalError as e:
                raise HTTPException(status_code=400, detail=str(e))
            return _proposal_to_response(resolved)

    if webhook_dispatcher is not None:
        @router.post(
            "/webhooks/test", response_model=WebhookTestResponse,
            dependencies=[Depends(require_role("admin"))],
        )
        async def test_webhook():
            ok, status_code, error = await webhook_dispatcher.send_test()
            return WebhookTestResponse(ok=ok, status_code=status_code, error=error)

    if audit_repo is not None:
        # Enterprise #4: /stats stays GLOBAL-viewer-gated and instance-wide by default — a
        # judgment call, documented here since the plan doesn't spell this specific route out.
        # Rationale: it's a dashboard SUMMARY (counts only, no individual server/key identity
        # beyond what a global viewer already saw pre-feature via GET /servers), and every prior
        # enterprise item's byte-identical-on-upgrade guarantee means an existing dashboard
        # integration calling this with no project_id must keep returning the SAME instance-wide
        # numbers it always has. `project_id` is an OPTIONAL filter for the frontend's
        # project-scoped dashboard view — a caller who passes it still only needs global-viewer
        # (not project-viewer), matching this route's existing instance-wide gate; a stricter
        # project-role-gated variant was considered and rejected as inconsistent with GET
        # /servers' own "global viewer sees everything" call directly above.
        @router.get("/stats", response_model=StatsResponse, dependencies=[Depends(require_role("viewer"))])
        async def get_stats(project_id: Optional[int] = None):
            from datetime import datetime, timedelta, timezone

            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            servers = await server_repo.list(project_id=project_id)
            server_slug_in = [s.slug for s in servers] if project_id is not None else None

            requests_24h = await audit_repo.count_since(since, server_slug_in=server_slug_in)
            blocked_24h = await audit_repo.count_since(since, decision="BLOCKED", server_slug_in=server_slug_in)
            allowed_24h = await audit_repo.count_since(since, decision="ALLOWED", server_slug_in=server_slug_in)
            # Excludes origin='test' for the same reason count_since does — the dashboard
            # shouldn't surface an operator's own Try-it calls as if they were real traffic.
            recent_blocked = await audit_repo.query(
                decision="BLOCKED", limit=10, origin=None, server_slug_in=server_slug_in,
            )

            healthy = sum(1 for s in servers if s.health_status == "healthy")
            unhealthy = sum(1 for s in servers if s.health_status == "unhealthy")

            return StatsResponse(
                requests_24h=requests_24h, blocked_24h=blocked_24h, allowed_24h=allowed_24h,
                servers_total=len(servers), servers_healthy=healthy, servers_unhealthy=unhealthy,
                server_health=[
                    ServerHealthSummary(
                        slug=s.slug, health_status=s.health_status, upstream_protocol=s.upstream_protocol,
                    )
                    for s in servers
                ],
                recent_blocked=recent_blocked,
            )

        # Enterprise #4: same instance-wide-by-default, optional project_id filter shape as
        # /stats above. Post-Postgres-cutover, audit_events and servers/projects live in the
        # SAME database (see db/database.py) — this is NOT a cross-database limitation anymore.
        # It's still a slug-set filter rather than a JOIN because audit_events.server_slug is a
        # bare TEXT column with no FK to servers.id (0001_init.sql — audit rows must survive a
        # server being renamed or deleted, so there's nothing to join against), so project
        # scoping resolves the project's server slugs first and passes them as server_slug_in
        # (see AuditRepo.query's own docstring).
        @router.get("/audit", response_model=list[AuditEventResponse], dependencies=[Depends(require_role("viewer"))])
        async def query_audit(
            server_slug: Optional[str] = None, decision: Optional[str] = None,
            tool: Optional[str] = None, before_id: Optional[int] = None, limit: int = 100,
            api_key_id: Optional[int] = None, after: Optional[str] = None,
            before: Optional[str] = None, search: Optional[str] = None,
            include_test: bool = False, project_id: Optional[int] = None,
        ):
            # Feature #1 (tool tester): Try-it calls are tagged origin='test' and excluded from
            # the default history view, same as they're excluded from /stats — an operator
            # testing their own policy shouldn't see it appear as if it were real traffic unless
            # they explicitly ask to (include_test=true).
            server_slug_in = None
            if project_id is not None:
                server_slug_in = [s.slug for s in await server_repo.list(project_id=project_id)]
            events = await audit_repo.query(
                server_slug=server_slug, decision=decision, tool=tool,
                before_id=before_id, limit=min(limit, 500),
                api_key_id=api_key_id, after=after, before=before, search=search,
                origin=_UNSET if include_test else None, server_slug_in=server_slug_in,
            )
            return [AuditEventResponse(**{**e, "bridged": bool(e["bridged"])}) for e in events]

        @router.get("/audit/export.csv", dependencies=[Depends(require_role("viewer"))])
        async def export_audit_csv(
            server_slug: Optional[str] = None, decision: Optional[str] = None,
            tool: Optional[str] = None, api_key_id: Optional[int] = None,
            after: Optional[str] = None, before: Optional[str] = None,
            search: Optional[str] = None, include_test: bool = False,
            project_id: Optional[int] = None,
        ):
            server_slug_in = None
            if project_id is not None:
                server_slug_in = [s.slug for s in await server_repo.list(project_id=project_id)]
            columns = [
                "id", "ts", "server_slug", "api_key_id", "client_ip", "endpoint", "rpc_method",
                "tool", "decision", "rule", "matched", "reason", "args_summary", "bridged",
                "status_code", "latency_ms", "origin",
            ]

            def csv_safe(value: object) -> str:
                # Formula-injection guard: `reason`/`args_summary`/`matched` can contain
                # attacker-influenced tool arguments. A cell opening with =, +, -, or @ is
                # executed as a formula by Excel/Sheets on open — prefix with a quote to defuse it.
                text = "" if value is None else str(value)
                if text and text[0] in ("=", "+", "-", "@"):
                    return f"'{text}"
                return text

            async def rows():
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(columns)
                yield buf.getvalue()

                before_id: Optional[int] = None
                while True:
                    buf = io.StringIO()
                    writer = csv.writer(buf)
                    events = await audit_repo.query(
                        server_slug=server_slug, decision=decision, tool=tool,
                        before_id=before_id, limit=500, api_key_id=api_key_id,
                        after=after, before=before, search=search,
                        origin=_UNSET if include_test else None, server_slug_in=server_slug_in,
                    )
                    if not events:
                        break
                    for e in events:
                        writer.writerow([csv_safe(e[c]) for c in columns])
                    yield buf.getvalue()
                    before_id = events[-1]["id"]
                    if len(events) < 500:
                        break

            filename = f"acropolis-audit-{utcnow().replace(':', '').split('.')[0]}.csv"
            return StreamingResponse(
                rows(), media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        if audit_logger is not None:
            # Enterprise #4: NOT project-scoped — a deliberate, documented call. This is a live
            # SSE tail of the in-process AuditLogger broadcast queue (see AuditLogger.subscribe),
            # not a DB query; filtering it per-project would mean holding a snapshot of the
            # project's server slugs for the lifetime of the connection and filtering each event
            # against it, which is a reasonable future enhancement but adds real complexity for a
            # live-tail feature that's already global-viewer-gated (same visibility a global
            # viewer already has via polling /audit with no project_id). Left instance-wide here;
            # documented rather than silently scoped or silently left ambiguous.
            @router.get("/audit/tail", dependencies=[Depends(require_role("viewer"))])
            async def audit_tail(request: Request):
                async def event_stream():
                    q = audit_logger.subscribe()
                    try:
                        while True:
                            if await request.is_disconnected():
                                break
                            try:
                                event = await asyncio.wait_for(q.get(), timeout=15.0)
                                yield f"data: {json.dumps(event)}\n\n"
                            except asyncio.TimeoutError:
                                yield ": keepalive\n\n"
                    finally:
                        audit_logger.unsubscribe(q)

                return StreamingResponse(event_stream(), media_type="text/event-stream")

    if usage_repo is not None:
        @router.get("/usage", response_model=UsageResponse)
        async def get_usage(
            api_key_id: Optional[int] = None, server_slug: Optional[str] = None,
            tool: Optional[str] = None, period: str = "day", project_id: Optional[int] = None,
            # The gate is this parameter, not a separate `dependencies=[...]` entry (redundant
            # with this — see api.py's other routes that need `principal` in the handler body,
            # e.g. list_proposals/list_keys, which use the same single-declaration shape).
            principal: Principal = Depends(require_role("viewer")),
        ):
            """Enterprise #11. viewer+ (read-only, consistent with how /audit is already scoped
            — a viewer can already see per-key traffic there, including numeric api_key_id and
            tool on every row; this route's CALL-COUNT data is the same order of visibility.

            SECURITY (self-review finding, fixed here — see docs/quotas.md's "who can see what"
            section for the full writeup): `key_prefix` is a piece of key metadata `/audit`
            does NOT expose to a viewer (that response carries only the bare numeric
            api_key_id — see AuditEventResponse) and GET /keys, which DOES expose it, is
            admin-only. A first pass at this route populated key_prefix for every caller,
            which would have handed a viewer something they could not get from either existing
            surface — a real, new capability, not a re-exposure of something already visible.
            Fixed by gating key_prefix on admin role specifically; a viewer/operator still gets
            the numeric api_key_id and the call count (exactly what /audit already shows them),
            just not the human-identifiable prefix.

            `period` selects how far back to sum: "day" (since UTC midnight today), "month"
            (since the 1st of the current UTC month), or "all" (every stored bucket — hourly
            rollups are never pruned, see 0010_usage_rollups.sql, so "all" is bounded only by
            how long this Acropolis instance has been running). This is a QUERY window,
            independent of any key's configured quota_period — a key with no quota at all can
            still be queried here.

            `project_id` (enterprise #4, optional) filters to one project's rollups directly on
            usage_rollups.project_id — unlike /audit's server_slug (a bare TEXT column with no
            FK), usage_rollups carries its OWN project_id column (populated at write time and
            backfilled by 0010_projects.sql), so no slug-set indirection is needed here. Same
            instance-wide-by-default shape as /stats and /audit above.
            """
            if period not in ("day", "month", "all"):
                raise HTTPException(status_code=400, detail="period must be 'day', 'month', or 'all'")

            since_iso: Optional[str] = None
            if period in ("day", "month"):
                since_iso = period_start(period).isoformat()

            server_id: Optional[int] = None
            if server_slug is not None:
                try:
                    server_id = (await server_repo.get(server_slug)).id
                except ServerNotFoundError:
                    return UsageResponse(period=period, since=since_iso, buckets=[])

            raw = await usage_repo.query(
                api_key_id=api_key_id, server_id=server_id, tool=tool, since_iso=since_iso,
                project_id=project_id,
            )

            # Sum the raw hourly buckets down to one row per (key, server, tool) — see
            # UsageRepo.query's docstring on why summing here beats N bespoke GROUP BY queries.
            # Sentinel translation (0 -> None for api_key_id/server_id, '' -> None for tool)
            # happens here too, so the API never leaks the storage-layer sentinel outward.
            totals: dict[tuple[Optional[int], Optional[int], Optional[str]], int] = {}
            for row in raw:
                key = (
                    row["api_key_id"] or None,
                    row["server_id"] or None,
                    row["tool"] or None,
                )
                totals[key] = totals.get(key, 0) + row["calls"]

            # key_prefix/server_slug are looked up for display — never the key hash/plaintext,
            # matching the webhook payload's same discipline (see stoa/webhooks.py's
            # fire_quota_threshold docstring).
            #
            # Self-review fix: this used to call api_keys.get(k_id) / server_repo.get_by_id(s_id)
            # ONCE PER DISTINCT key/server in the result set — an N+1 query pattern (N sequential
            # DB round-trips for N distinct keys, again for N distinct servers). Both api_keys
            # and server_repo already expose a single list() call each (the same one GET /keys
            # and GET /servers use) — two bulk reads regardless of how many distinct keys/servers
            # appear in `totals`, rather than scaling with the size of the result set.
            #
            # Security fix (see this route's docstring): key_prefix is admin-only. server_slug
            # stays available to every role — servers are already fully visible to a viewer via
            # GET /servers, so there is no analogous leak on that side.
            key_prefixes = (
                {k.id: k.key_prefix for k in await api_keys.list()}
                if principal.role == "admin" else {}
            )
            server_slugs = {s.id: s.slug for s in await server_repo.list()}

            buckets = [
                UsageBucketResponse(
                    api_key_id=k_id, key_prefix=key_prefixes.get(k_id) if k_id is not None else None,
                    server_id=s_id, server_slug=server_slugs.get(s_id) if s_id is not None else None,
                    tool=tool_name, calls=calls,
                )
                for (k_id, s_id, tool_name), calls in sorted(totals.items(), key=lambda kv: -kv[1])
            ]
            return UsageResponse(period=period, since=since_iso, buckets=buckets)

    if admin_event_repo is not None:
        @router.get("/admin-events", response_model=list[AdminEventResponse], dependencies=[Depends(require_role("viewer"))])
        async def query_admin_events(
            action: Optional[str] = None,
            target_type: Optional[str] = None,
            since: Optional[str] = None,
            limit: int = 100,
        ):
            events = await admin_event_repo.query(
                action=action, target_type=target_type, since=since, limit=limit,
            )
            return [
                AdminEventResponse(
                    id=e.id,
                    ts=e.ts,
                    actor=e.actor,
                    action=e.action,
                    target_type=e.target_type,
                    target_id=e.target_id,
                    before=e.before,
                    after=e.after,
                    client_ip=e.client_ip,
                    summary=e.summary,
                )
                for e in events
            ]

    # Current-principal endpoint — always registered, works under every auth path (admin_token
    # break-glass, legacy pre-migration session, or a real user), so the frontend has one place
    # to ask "who am I" regardless of migration/auth state. viewer-level: knowing your own
    # identity isn't a privileged operation.
    @router.get("/me", response_model=CurrentUserResponse, dependencies=[Depends(require_role("viewer"))])
    async def get_current_user(principal: Principal = Depends(require_admin)):
        return CurrentUserResponse(
            user_id=principal.user_id, username=principal.username,
            role=principal.role, auth_source=principal.auth_source,
        )

    # Enterprise #4 (multi-tenancy, issue #5): project CRUD is INSTANCE-WIDE and GLOBAL-ADMIN-
    # ONLY (creating/deleting a project is instance-level authority per design decision 2/3 of
    # 03-multi-tenancy.md) — these stay on require_role, never require_project_role. Membership
    # management (who holds what PROJECT role) is the one place a project-admin (not necessarily
    # a global admin) gets write access, gated by require_project_role("admin", ...) below.
    if project_repo is not None and project_member_repo is not None:
        @router.get("/projects", response_model=list[ProjectResponse], dependencies=[Depends(require_role("viewer"))])
        async def list_projects(principal: Principal = Depends(require_admin)):
            # viewer+ globally can SEE every project (same "list is cheap, low-sensitivity"
            # reasoning as GET /servers/GET /users) — this is what populates the frontend's
            # project switcher for every signed-in user, not just those with explicit
            # memberships (a global admin with zero membership rows still needs to see every
            # project to exercise the superset). A non-admin's per-project AUTHORITY is still
            # fully gated by require_project_role on the actual project-scoped routes; this list
            # route only discloses project id/slug/name, which is not sensitive on its own.
            return [
                ProjectResponse(id=p.id, slug=p.slug, name=p.name, created_at=p.created_at)
                for p in await project_repo.list()
            ]

        @router.post("/projects", response_model=ProjectResponse, status_code=201)
        async def create_project(
            body: ProjectCreateRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            try:
                project = await project_repo.create(slug=body.slug, name=body.name)
            except ProjectSlugConflictError:
                raise HTTPException(status_code=409, detail=f"project slug '{body.slug}' already exists")

            if admin_event_repo is not None:
                await record(
                    admin_event_repo,
                    action="project.create",
                    summary=f"created project '{body.slug}'",
                    actor=principal.actor,
                    target_type="project",
                    target_id=body.slug,
                    after={"slug": body.slug, "name": body.name},
                    client_ip=request.client.host if request.client else None,
                )
            return ProjectResponse(
                id=project.id, slug=project.slug, name=project.name, created_at=project.created_at
            )

        @router.delete("/projects/{project_slug}", status_code=204)
        async def delete_project(
            project_slug: str, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            try:
                project = await project_repo.get(project_slug)
            except ProjectNotFoundError:
                raise HTTPException(status_code=404, detail="project not found")

            # Refuse rather than orphan/cascade: servers.project_id and api_keys.project_id have
            # NO ON DELETE clause (see 0011_projects.sql), so deleting a project that still owns
            # real infrastructure would leave those rows pointing at a project_id that no longer
            # exists — every project-scoping filter would then silently exclude them from every
            # list, an "infrastructure vanished" bug far worse than a blocked delete. The 'default'
            # project itself is not special-cased beyond this same check: it can be deleted once
            # it holds nothing, exactly like any other project.
            remaining_servers = await server_repo.list(project_id=project.id)
            remaining_keys = await api_keys.list(project_id=project.id)
            if remaining_servers or remaining_keys:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"project '{project_slug}' still has {len(remaining_servers)} server(s) and "
                        f"{len(remaining_keys)} key(s) — move or delete them first"
                    ),
                )

            await project_repo.delete(project_slug)
            if admin_event_repo is not None:
                await record(
                    admin_event_repo,
                    action="project.delete",
                    summary=f"deleted project '{project_slug}'",
                    actor=principal.actor,
                    target_type="project",
                    target_id=project_slug,
                    before={"slug": project.slug, "name": project.name},
                    client_ip=request.client.host if request.client else None,
                )

        @router.get(
            "/projects/{project_id}/members", response_model=list[ProjectMemberResponse],
            dependencies=[Depends(require_project_role("viewer", project_id_param="project_id"))],
        )
        async def list_project_members(project_id: int):
            try:
                await project_repo.get_by_id(project_id)
            except ProjectNotFoundError:
                raise HTTPException(status_code=404, detail="project not found")
            members = await project_member_repo.list_for_project(project_id)
            if not members or user_repo is None:
                return [
                    ProjectMemberResponse(user_id=m.user_id, username=f"user#{m.user_id}", role=m.role)
                    for m in members
                ]
            # Bulk-resolve usernames — same N+1 avoidance discipline as GET /usage's
            # key_prefixes/server_slugs lookups above (one list() call, not one get_by_id per
            # member).
            usernames = {u.id: u.username for u in await user_repo.list()}
            return [
                ProjectMemberResponse(
                    user_id=m.user_id, username=usernames.get(m.user_id, f"user#{m.user_id}"), role=m.role,
                )
                for m in members
            ]

        @router.put(
            "/projects/{project_id}/members", response_model=ProjectMemberResponse,
            dependencies=[Depends(require_project_role("admin", project_id_param="project_id"))],
        )
        async def upsert_project_member(
            project_id: int, body: ProjectMemberUpsertRequest, request: Request,
            principal: Principal = Depends(require_admin),
        ):
            """Add a member or change an existing member's role — project-admin-or-global-admin,
            per design decision 3 (membership management is where a project admin, not just a
            global admin, gets real write authority)."""
            try:
                project = await project_repo.get_by_id(project_id)
            except ProjectNotFoundError:
                raise HTTPException(status_code=404, detail="project not found")
            if user_repo is not None:
                try:
                    target_user = await user_repo.get_by_id(body.user_id)
                except UserNotFoundError:
                    raise HTTPException(status_code=404, detail="user not found")
            else:
                target_user = None

            existing = await project_member_repo.get_membership(user_id=body.user_id, project_id=project_id)
            member = await project_member_repo.upsert(
                user_id=body.user_id, project_id=project_id, role=body.role,
            )

            if admin_event_repo is not None:
                action = "project.member_role_change" if existing is not None else "project.member_add"
                username = target_user.username if target_user is not None else f"user#{body.user_id}"
                summary = (
                    f"{'changed' if existing else 'added'} member '{username}' in project "
                    f"'{project.slug}'" + (f": {existing.role} -> {body.role}" if existing else f" as {body.role}")
                )
                await record(
                    admin_event_repo,
                    action=action,
                    summary=summary,
                    actor=principal.actor,
                    target_type="project_member",
                    target_id=f"{project.slug}:{body.user_id}",
                    before={"role": existing.role} if existing is not None else None,
                    after={"role": body.role},
                    client_ip=request.client.host if request.client else None,
                )

            username = target_user.username if target_user is not None else f"user#{body.user_id}"
            return ProjectMemberResponse(user_id=member.user_id, username=username, role=member.role)

        @router.delete(
            "/projects/{project_id}/members/{user_id}", status_code=204,
            dependencies=[Depends(require_project_role("admin", project_id_param="project_id"))],
        )
        async def remove_project_member(
            project_id: int, user_id: int, request: Request,
            principal: Principal = Depends(require_admin),
        ):
            try:
                project = await project_repo.get_by_id(project_id)
            except ProjectNotFoundError:
                raise HTTPException(status_code=404, detail="project not found")

            existing = await project_member_repo.get_membership(user_id=user_id, project_id=project_id)
            if existing is None:
                raise HTTPException(status_code=404, detail="membership not found")

            await project_member_repo.remove(user_id=user_id, project_id=project_id)

            if admin_event_repo is not None:
                username = f"user#{user_id}"
                if user_repo is not None:
                    try:
                        username = (await user_repo.get_by_id(user_id)).username
                    except UserNotFoundError:
                        pass
                await record(
                    admin_event_repo,
                    action="project.member_remove",
                    summary=f"removed member '{username}' from project '{project.slug}'",
                    actor=principal.actor,
                    target_type="project_member",
                    target_id=f"{project.slug}:{user_id}",
                    before={"role": existing.role},
                    client_ip=request.client.host if request.client else None,
                )

    # User management — enterprise #1/#2. All admin-only: creating a user, changing a role, or
    # disabling an account are exactly the "irreversible or security-lowering" actions
    # 02-rbac.md draws the operator/admin boundary around.
    if user_repo is not None:
        def _user_to_response(u) -> UserResponse:
            return UserResponse(
                id=u.id, username=u.username, email=u.email, role=u.role,
                auth_source=u.auth_source, enabled=u.enabled,
                created_at=u.created_at, last_login_at=u.last_login_at,
            )

        @router.get("/users", response_model=list[UserResponse], dependencies=[Depends(require_role("admin"))])
        async def list_users():
            users = await user_repo.list()
            return [_user_to_response(u) for u in users]

        @router.post("/users", response_model=UserResponse, status_code=201)
        async def create_user(
            body: UserCreateRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            if not is_valid_role(body.role):
                raise HTTPException(
                    status_code=400,
                    detail=f"role must be one of {sorted(ROLE_RANK)}, got {body.role!r}",
                )
            if len(body.password) < 8:
                raise HTTPException(status_code=400, detail="password must be at least 8 characters")

            loop = asyncio.get_running_loop()
            password_hash = await loop.run_in_executor(None, hash_password, body.password)
            try:
                user = await user_repo.create(
                    username=body.username, role=body.role, password_hash=password_hash,
                    email=body.email, auth_source="local",
                )
            except UsernameConflictError:
                raise HTTPException(status_code=409, detail=f"username '{body.username}' already exists")

            if admin_event_repo is not None:
                await record(
                    admin_event_repo,
                    action="user.create",
                    summary=f"created user '{body.username}' with role '{body.role}'",
                    actor=principal.actor,
                    target_type="user",
                    target_id=str(user.id),
                    after={"username": user.username, "role": user.role, "auth_source": user.auth_source},
                    client_ip=request.client.host if request.client else None,
                )
            return _user_to_response(user)

        @router.patch("/users/{user_id}/role", response_model=UserResponse)
        async def update_user_role(
            user_id: int, body: UserRoleUpdateRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            if not is_valid_role(body.role):
                raise HTTPException(
                    status_code=400,
                    detail=f"role must be one of {sorted(ROLE_RANK)}, got {body.role!r}",
                )
            try:
                before = await user_repo.get_by_id(user_id)
            except UserNotFoundError:
                raise HTTPException(status_code=404, detail="user not found")

            user = await user_repo.update_role(user_id, body.role)
            # A role change is exactly what per-user session revocation exists for: the OLD
            # role must not keep working via an already-issued cookie until it expires on its
            # own up to 7 days later — same reasoning as F18's password-change bump, scoped to
            # this one user instead of everyone.
            await user_repo.bump_session_version(user_id)

            if admin_event_repo is not None and before.role != user.role:
                # Role changes must write a control-plane audit event (02-rbac.md design
                # decision 2) — privilege changes are exactly what admin_events exists for.
                await record(
                    admin_event_repo,
                    action="user.role_change",
                    summary=f"changed role of '{user.username}': {before.role} -> {user.role}",
                    actor=principal.actor,
                    target_type="user",
                    target_id=str(user_id),
                    before={"role": before.role},
                    after={"role": user.role},
                    client_ip=request.client.host if request.client else None,
                )
            return _user_to_response(user)

        @router.patch("/users/{user_id}/enabled", response_model=UserResponse)
        async def update_user_enabled(
            user_id: int, body: UserEnabledUpdateRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            try:
                before = await user_repo.get_by_id(user_id)
            except UserNotFoundError:
                raise HTTPException(status_code=404, detail="user not found")

            if not body.enabled and principal.user_id == user_id:
                # A self-lockout guard: an admin disabling their OWN account while it's the
                # only session they're acting through would have to immediately re-authenticate
                # as someone else, which may not exist yet on a small instance. Not a security
                # boundary (they could still do it via a second admin account, or the
                # admin_token break-glass) — just a footgun guard.
                raise HTTPException(status_code=400, detail="cannot disable your own account")

            user = await user_repo.set_enabled(user_id, body.enabled)
            if not body.enabled:
                # Disabling must stop an EXISTING session on its very next request, not just
                # block future logins — bump the per-user version so any outstanding cookie for
                # this user is rejected immediately (require_admin re-checks `enabled` too, as
                # defense in depth, but the version bump is what makes it immediate rather than
                # racing the 7-day cookie expiry).
                await user_repo.bump_session_version(user_id)

            if admin_event_repo is not None and before.enabled != user.enabled:
                await record(
                    admin_event_repo,
                    action="user.enabled_change",
                    summary=f"{'enabled' if user.enabled else 'disabled'} user '{user.username}'",
                    actor=principal.actor,
                    target_type="user",
                    target_id=str(user_id),
                    before={"enabled": before.enabled},
                    after={"enabled": user.enabled},
                    client_ip=request.client.host if request.client else None,
                )
            return _user_to_response(user)

    # GitOps endpoints — only registered when a ConfigSource is wired in
    if config_source is not None:
        @router.get("/config/drift", response_model=DriftStatusResponse, dependencies=[Depends(require_role("viewer"))])
        async def get_drift():
            """Get current drift state between live config and git-tracked file."""
            state = config_source.state
            result = DriftStatusResponse(
                status=state.status,
                last_check=state.last_check,
                last_error=state.last_error,
            )
            if state.plan is not None:
                result.actions = [
                    DriftActionResponse(
                        kind=a.kind,
                        target=a.target,
                        detail=a.detail,
                        description=a.describe(applied=False),
                    )
                    for a in state.plan.actions
                ]
                result.warnings = state.plan.warnings
                result.errors = state.plan.errors
            return result

        @router.post("/config/reconcile", dependencies=[Depends(require_role("admin"))])
        async def reconcile_config(request: Request):
            """Apply the pending drift plan. Writes one admin event recording the change.

            02-rbac.md's interaction note with 06-policy-as-code: reconcile is admin-only since
            it's config import by another name — same one-shot-rewrites-the-instance blast
            radius as POST /config/import, just sourced from git instead of an uploaded file."""
            try:
                plan = await config_source.reconcile()
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except httpx.HTTPError as e:
                # The gateway couldn't reach the config source during the reconcile re-fetch.
                raise HTTPException(status_code=502, detail=f"config source fetch failed: {e}")

            # Record reconcile in admin events
            if admin_event_repo is not None:
                await record(
                    admin_event_repo,
                    action="config.reconcile",
                    summary=f"reconciled from git ({len(plan.actions)} change(s))",
                    actor="gitops",
                    target_type="config",
                    after={
                        "changes": [a.describe(applied=True) for a in plan.actions],
                    },
                    client_ip=request.client.host if request.client else None,
                )

            return {
                "applied": plan.ok,
                "actions": [a.describe(applied=True) for a in plan.actions],
                "errors": plan.errors,
            }

    # Enterprise #9 (OTel tracing): read-only status for the Settings page. Deliberately not
    # gated behind `if tracing is not None` the way the GitOps block above is gated on
    # config_source — app.py always wires a TracingManager (build_tracing_manager() never
    # returns None), so this endpoint always exists; it just always reports
    # enabled=False/active=False on a deployment that never set ACROPOLIS_OTEL_ENABLED. A test
    # or other caller that constructs this router without passing `tracing` at all gets the same
    # "disabled" answer via this fallback, matching every other optional-dependency default in
    # this router (secret_provider, pipeline, etc.).
    _tracing_status = tracing or TracingManager(enabled=False)  # inert: never .init()'d, .active stays False

    @router.get("/tracing/status", response_model=TracingStatusResponse, dependencies=[Depends(require_role("viewer"))])
    async def get_tracing_status():
        """Whether OpenTelemetry tracing is enabled/active. No span content, no configured
        exporter endpoint (that's sourced from standard OTEL_EXPORTER_OTLP_* environment
        variables, not from anything this API surfaces) — see docs/observability.md."""
        return TracingStatusResponse(
            enabled=_tracing_status.enabled,
            active=_tracing_status.active,
            sample_ratio=_tracing_status.sample_ratio,
        )

    return router
