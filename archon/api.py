from __future__ import annotations

import asyncio
import csv
import io
import json
import secrets
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from archon.admin_auth import Principal, require_admin
from archon.admin_audit import (
    filter_server_fields,
    filter_settings_keys,
    record,
    record_config_import,
    record_policy_change,
    record_secret_reference_change,
)
from archon.auth.apikeys import ApiKeyService
from archon.config_io import export_config, plan_import
from archon.passwords import hash_password
from archon.rbac import ROLE_RANK, is_valid_role, require_role
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
}


def _server_to_response(server) -> ServerResponse:
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
    )


def _key_to_response(key) -> KeyResponse:
    return KeyResponse(
        id=key.id, name=key.name, key_prefix=key.key_prefix, enabled=key.enabled,
        server_scopes=key.server_scopes, created_at=key.created_at, last_used_at=key.last_used_at,
        quota_calls=key.quota_calls, quota_period=key.quota_period,
    )


async def _get_settings_with_defaults(settings_repo: SettingsRepo) -> dict[str, str]:
    stored = await settings_repo.get_all()
    return {**_SETTINGS_DEFAULTS, **stored}


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

    # F21 fix (review 2026-08-04): /api/v1/health used to live HERE, behind require_admin —
    # but both the Dockerfile HEALTHCHECK and the k8s liveness/readiness probes target it
    # unauthenticated. Once first-run setup completes, they started getting 401s: the k8s pod
    # entered a restart loop (livenessProbe failureThreshold=3 * periodSeconds=30 ≈ pod killed
    # ~90s after setup) and the compose container reported permanently unhealthy. Moved to
    # archon/setup.py's router, which is deliberately never behind require_admin — see that
    # module for the actual route.

    @router.get("/servers", response_model=list[ServerResponse], dependencies=[Depends(require_role("viewer"))])
    async def list_servers():
        servers = await server_repo.list()
        return [_server_to_response(s) for s in servers]

    @router.post("/servers", response_model=ServerResponse, status_code=201)
    async def create_server(
        body: ServerCreateRequest, request: Request,
        principal: Principal = Depends(require_role("admin")),
    ):
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

        return _server_to_response(server)

    @router.post("/servers/{slug}/probe", response_model=ServerResponse, dependencies=[Depends(require_role("operator"))])
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
        return _server_to_response(await server_repo.get(slug))

    @router.get("/servers/{slug}", response_model=ServerResponse, dependencies=[Depends(require_role("viewer"))])
    async def get_server(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        return _server_to_response(server)

    @router.put("/servers/{slug}", response_model=ServerResponse)
    async def update_server(
        slug: str, body: ServerUpdateRequest, request: Request,
        principal: Principal = Depends(require_role("admin")),
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

        return _server_to_response(server)

    @router.delete("/servers/{slug}", status_code=204)
    async def delete_server(
        slug: str, request: Request,
        principal: Principal = Depends(require_role("admin")),
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

    @router.get("/servers/{slug}/tools", response_model=ServerToolsResponse, dependencies=[Depends(require_role("viewer"))])
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
            dependencies=[Depends(require_role("operator"))],
        )
        async def test_call(slug: str, request: Request, body: ToolTestRequest):
            # Feature #1 (in-UI tool tester): dispatches through the REAL pipeline — real rate
            # limiting, real policy evaluation, real audit logging — rather than a second
            # evaluator that could drift from the one actually enforcing. `skip_api_key_auth`
            # bypasses only the data plane's bearer-token check (the caller is already
            # authenticated with at least operator role via require_role above); `force_generation`
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

    @router.get("/servers/{slug}/policy", response_model=PolicyResponse, dependencies=[Depends(require_role("viewer"))])
    async def get_policy(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        policy = await server_repo.get_policy(server.id)
        return PolicyResponse(**policy.model_dump())

    @router.put("/servers/{slug}/policy", response_model=PolicyResponse)
    async def set_policy(
        slug: str, body: PolicyUpdateRequest, request: Request,
        principal: Principal = Depends(require_role("operator")),
    ):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")

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

    @router.get("/keys", response_model=list[KeyResponse], dependencies=[Depends(require_role("admin"))])
    async def list_keys():
        keys = await api_keys.list()
        return [_key_to_response(k) for k in keys]

    @router.post("/keys", response_model=KeyCreatedResponse, status_code=201)
    async def create_key(
        body: KeyCreateRequest, request: Request,
        principal: Principal = Depends(require_role("admin")),
    ):
        # 02-rbac.md design decision 3: key minting is admin-only, not merely because keys feel
        # sensitive — an operator who could mint a key could use it against the DATA plane and
        # act entirely outside their control-plane role, which would make the operator/admin
        # boundary trivially bypassable. require_role("admin") above is what actually enforces
        # this; see tests/integration/test_rbac.py's "operator cannot mint a key" case.
        generated = await api_keys.create(
            name=body.name, server_scopes=body.server_scopes,
            quota_calls=body.quota_calls, quota_period=body.quota_period,
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
        principal: Principal = Depends(require_role("admin")),
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

        return _key_to_response(key_after)

    @router.patch("/keys/{key_id}/quota", response_model=KeyResponse, dependencies=[Depends(require_role("admin"))])
    async def patch_key_quota(
        key_id: int, body: KeyQuotaUpdateRequest, request: Request,
        principal: Principal = Depends(require_role("admin")),
    ):
        """Enterprise #11: sets or clears a key's quota. A separate route from PATCH /keys/{id}
        (see KeyQuotaUpdateRequest's docstring) — admin-only, same as every other key-mutating
        route (02-rbac.md design decision 3: a key is a data-plane credential, so changing what
        it can do is as sensitive as minting one)."""
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

        return _key_to_response(key_after)

    @router.delete("/keys/{key_id}", status_code=204)
    async def delete_key(
        key_id: int, request: Request,
        principal: Principal = Depends(require_role("admin")),
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
                server_repo, settings_repo, include_credentials=include_credentials
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

        @router.post("/config/import", response_model=ConfigImportResponse)
        async def import_configuration(
            body: ConfigImportRequest, request: Request,
            principal: Principal = Depends(require_role("admin")),
        ):
            # 02-rbac.md design decision 1: config import is admin-only even though it edits
            # policies (which operators may do directly) — one import rewrites the entire
            # instance in one shot, a different blast radius from a single server's policy.
            plan = await plan_import(server_repo, settings_repo, body.yaml, apply=body.apply)

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

    if webhook_dispatcher is not None:
        @router.post(
            "/webhooks/test", response_model=WebhookTestResponse,
            dependencies=[Depends(require_role("admin"))],
        )
        async def test_webhook():
            ok, status_code, error = await webhook_dispatcher.send_test()
            return WebhookTestResponse(ok=ok, status_code=status_code, error=error)

    if audit_repo is not None:
        @router.get("/stats", response_model=StatsResponse, dependencies=[Depends(require_role("viewer"))])
        async def get_stats():
            from datetime import datetime, timedelta, timezone

            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            requests_24h = await audit_repo.count_since(since)
            blocked_24h = await audit_repo.count_since(since, decision="BLOCKED")
            allowed_24h = await audit_repo.count_since(since, decision="ALLOWED")
            # Excludes origin='test' for the same reason count_since does — the dashboard
            # shouldn't surface an operator's own Try-it calls as if they were real traffic.
            recent_blocked = await audit_repo.query(decision="BLOCKED", limit=10, origin=None)

            servers = await server_repo.list()
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

        @router.get("/audit", response_model=list[AuditEventResponse], dependencies=[Depends(require_role("viewer"))])
        async def query_audit(
            server_slug: Optional[str] = None, decision: Optional[str] = None,
            tool: Optional[str] = None, before_id: Optional[int] = None, limit: int = 100,
            api_key_id: Optional[int] = None, after: Optional[str] = None,
            before: Optional[str] = None, search: Optional[str] = None,
            include_test: bool = False,
        ):
            # Feature #1 (tool tester): Try-it calls are tagged origin='test' and excluded from
            # the default history view, same as they're excluded from /stats — an operator
            # testing their own policy shouldn't see it appear as if it were real traffic unless
            # they explicitly ask to (include_test=true).
            events = await audit_repo.query(
                server_slug=server_slug, decision=decision, tool=tool,
                before_id=before_id, limit=min(limit, 500),
                api_key_id=api_key_id, after=after, before=before, search=search,
                origin=_UNSET if include_test else None,
            )
            return [AuditEventResponse(**{**e, "bridged": bool(e["bridged"])}) for e in events]

        @router.get("/audit/export.csv", dependencies=[Depends(require_role("viewer"))])
        async def export_audit_csv(
            server_slug: Optional[str] = None, decision: Optional[str] = None,
            tool: Optional[str] = None, api_key_id: Optional[int] = None,
            after: Optional[str] = None, before: Optional[str] = None,
            search: Optional[str] = None, include_test: bool = False,
        ):
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
                        origin=_UNSET if include_test else None,
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
        @router.get("/usage", response_model=UsageResponse, dependencies=[Depends(require_role("viewer"))])
        async def get_usage(
            api_key_id: Optional[int] = None, server_slug: Optional[str] = None,
            tool: Optional[str] = None, period: str = "day",
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
