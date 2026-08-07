from __future__ import annotations

import asyncio
import csv
import io
import json
import secrets
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from archon.admin_auth import require_admin
from archon.admin_audit import (
    filter_server_fields,
    filter_settings_keys,
    record,
    record_config_import,
    record_policy_change,
)
from archon.auth.apikeys import ApiKeyService
from archon.config_io import export_config, plan_import
from archon.schemas import (
    AdminEventResponse,
    AuditEventResponse,
    ConfigImportAction,
    ConfigImportRequest,
    ConfigImportResponse,
    KeyCreatedResponse,
    KeyCreateRequest,
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
    WebhookTestResponse,
)
from argus.audit import AuditLogger
from argus.generation import ClientGeneration
from argus.pipeline import Pipeline
from argus.rate_limiter import RateLimiterRegistry, server_key
from argus.toolslist import ToolsCache
from db.database import utcnow
from db.repo import _UNSET, AdminEventRepo, AuditRepo, ServerNotFoundError, ServerRepo, SettingsRepo, SlugConflictError
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
    )


def _key_to_response(key) -> KeyResponse:
    return KeyResponse(
        id=key.id, name=key.name, key_prefix=key.key_prefix, enabled=key.enabled,
        server_scopes=key.server_scopes, created_at=key.created_at, last_used_at=key.last_used_at,
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
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])

    # F21 fix (review 2026-08-04): /api/v1/health used to live HERE, behind require_admin —
    # but both the Dockerfile HEALTHCHECK and the k8s liveness/readiness probes target it
    # unauthenticated. Once first-run setup completes, they started getting 401s: the k8s pod
    # entered a restart loop (livenessProbe failureThreshold=3 * periodSeconds=30 ≈ pod killed
    # ~90s after setup) and the compose container reported permanently unhealthy. Moved to
    # archon/setup.py's router, which is deliberately never behind require_admin — see that
    # module for the actual route.

    @router.get("/servers", response_model=list[ServerResponse])
    async def list_servers():
        servers = await server_repo.list()
        return [_server_to_response(s) for s in servers]

    @router.post("/servers", response_model=ServerResponse, status_code=201)
    async def create_server(body: ServerCreateRequest, request: Request):
        try:
            server = await server_repo.create(
                slug=body.slug, name=body.name, upstream_url=body.upstream_url,
                enabled=body.enabled, in_aggregate=body.in_aggregate,
                upstream_auth_header=body.upstream_auth_header,
            )
        except SlugConflictError:
            raise HTTPException(status_code=409, detail=f"server slug '{body.slug}' already exists")

        if admin_event_repo is not None:
            await record(
                admin_event_repo,
                action="server.create",
                summary=f"created server '{body.slug}'",
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
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

    @router.post("/servers/{slug}/probe", response_model=ServerResponse)
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

    @router.get("/servers/{slug}", response_model=ServerResponse)
    async def get_server(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        return _server_to_response(server)

    @router.put("/servers/{slug}", response_model=ServerResponse)
    async def update_server(slug: str, body: ServerUpdateRequest, request: Request):
        # F23: upstream_auth_header needs three states (unset/set-to-value/cleared-to-null),
        # which a plain `Optional[str] = None` field can't distinguish on its own — checking
        # model_fields_set tells us whether the key was present in the request body at all.
        auth_header_update = (
            body.upstream_auth_header if "upstream_auth_header" in body.model_fields_set else _UNSET
        )
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
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
                target_type="server",
                target_id=slug,
                before=before_dict,
                after=after_dict,
                client_ip=request.client.host if request.client else None,
            )

        return _server_to_response(server)

    @router.delete("/servers/{slug}", status_code=204)
    async def delete_server(slug: str, request: Request):
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
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
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

    @router.get("/servers/{slug}/tools", response_model=ServerToolsResponse)
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
        @router.post("/servers/{slug}/test-call", response_model=ToolTestResponse)
        async def test_call(slug: str, request: Request, body: ToolTestRequest):
            # Feature #1 (in-UI tool tester): dispatches through the REAL pipeline — real rate
            # limiting, real policy evaluation, real audit logging — rather than a second
            # evaluator that could drift from the one actually enforcing. `skip_api_key_auth`
            # bypasses only the data plane's bearer-token check (the operator is already
            # authenticated as admin via require_admin on this whole router); `force_generation`
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

    @router.get("/servers/{slug}/policy", response_model=PolicyResponse)
    async def get_policy(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        policy = await server_repo.get_policy(server.id)
        return PolicyResponse(**policy.model_dump())

    @router.put("/servers/{slug}/policy", response_model=PolicyResponse)
    async def set_policy(slug: str, body: PolicyUpdateRequest, request: Request):
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
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
                client_ip=request.client.host if request.client else None,
            )

        return PolicyResponse(**after_policy.model_dump())

    @router.get("/keys", response_model=list[KeyResponse])
    async def list_keys():
        keys = await api_keys.list()
        return [_key_to_response(k) for k in keys]

    @router.post("/keys", response_model=KeyCreatedResponse, status_code=201)
    async def create_key(body: KeyCreateRequest, request: Request):
        generated = await api_keys.create(name=body.name, server_scopes=body.server_scopes)

        if admin_event_repo is not None:
            await record(
                admin_event_repo,
                action="key.create",
                summary=f"created API key '{body.name}'",
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
                target_type="key",
                target_id=str(generated.record.id),
                after={"name": body.name, "key_prefix": generated.record.key_prefix, "server_scopes": body.server_scopes},
                client_ip=request.client.host if request.client else None,
            )

        return KeyCreatedResponse(
            id=generated.record.id, name=generated.record.name,
            key_prefix=generated.record.key_prefix, plaintext=generated.plaintext,
        )

    @router.patch("/keys/{key_id}", response_model=KeyResponse)
    async def patch_key(key_id: int, enabled: bool, request: Request):
        # Fetch before state for audit
        key_before = await api_keys.get(key_id)

        if enabled:
            await api_keys.enable(key_id)
        else:
            await api_keys.disable(key_id)

        key_after = await api_keys.get(key_id)
        if key_after is None:
            raise HTTPException(status_code=404, detail="key not found")

        # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
        if admin_event_repo is not None and key_before is not None:
            action = "key.enable" if enabled else "key.disable"
            await record(
                admin_event_repo,
                action=action,
                summary=f"{'enabled' if enabled else 'disabled'} API key '{key_after.name}'",
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
                target_type="key",
                target_id=str(key_id),
                before={"enabled": key_before.enabled},
                after={"enabled": enabled},
                client_ip=request.client.host if request.client else None,
            )

        return _key_to_response(key_after)

    @router.delete("/keys/{key_id}", status_code=204)
    async def delete_key(key_id: int, request: Request):
        # Fetch before state for audit
        key_before = await api_keys.get(key_id)

        await api_keys.delete(key_id)

        # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
        if admin_event_repo is not None and key_before is not None:
            await record(
                admin_event_repo,
                action="key.delete",
                summary=f"deleted API key '{key_before.name}'",
                # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
                target_type="key",
                target_id=str(key_id),
                before={"name": key_before.name, "key_prefix": key_before.key_prefix},
                client_ip=request.client.host if request.client else None,
            )

    if settings_repo is not None:
        @router.get("/settings", response_model=SettingsResponse)
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
            )

        @router.put("/settings", response_model=SettingsResponse)
        async def update_settings(body: SettingsUpdateRequest, request: Request):
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
                    # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
                    target_type="settings",
                    before=before_filtered,
                    after=after_filtered,
                    client_ip=request.client.host if request.client else None,
                )

            return await get_settings()

        @router.get("/config/export")
        async def export_configuration(include_credentials: bool = False):
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
        async def import_configuration(body: ConfigImportRequest, request: Request):
            plan = await plan_import(server_repo, settings_repo, body.yaml, apply=body.apply)

            # Record config import as ONE event, not one per touched server — otherwise a
            # routine import drowns the log it's supposed to make legible.
            if admin_event_repo is not None and body.apply and plan.ok:
                action_descriptions = [a.describe(applied=True) for a in plan.actions]
                await record_config_import(
                    admin_event_repo,
                    actions=action_descriptions,
                    # TODO(enterprise #2): actor should be the real user ID, not hardcoded "admin-session"
                actor="admin-session",
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
        @router.post("/webhooks/test", response_model=WebhookTestResponse)
        async def test_webhook():
            ok, status_code, error = await webhook_dispatcher.send_test()
            return WebhookTestResponse(ok=ok, status_code=status_code, error=error)

    if audit_repo is not None:
        @router.get("/stats", response_model=StatsResponse)
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

        @router.get("/audit", response_model=list[AuditEventResponse])
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

        @router.get("/audit/export.csv")
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
            @router.get("/audit/tail")
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

    if admin_event_repo is not None:
        @router.get("/admin-events", response_model=list[AdminEventResponse])
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

    # GitOps endpoints — only registered when a ConfigSource is wired in
    if config_source is not None:
        @router.get("/config/drift")
        async def get_drift():
            """Get current drift state between live config and git-tracked file."""
            state = config_source.state
            result = {
                "status": state.status,
                "last_check": state.last_check,
                "last_error": state.last_error,
                "commit_sha": state.commit_sha,
            }
            if state.plan is not None:
                result["actions"] = [
                    {
                        "kind": a.kind,
                        "target": a.target,
                        "detail": a.detail,
                        "description": a.describe(applied=False),
                    }
                    for a in state.plan.actions
                ]
                result["warnings"] = state.plan.warnings
                result["errors"] = state.plan.errors
            return result

        @router.post("/config/reconcile")
        async def reconcile_config(request: Request):
            """Apply the pending drift plan. Writes one admin event with commit SHA."""
            try:
                plan = await config_source.reconcile()
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

            # Record reconcile in admin events with commit SHA
            if admin_event_repo is not None:
                await record(
                    admin_event_repo,
                    action="config.reconcile",
                    summary=f"reconciled from git ({len(plan.actions)} change(s))",
                    actor="gitops",
                    target_type="config",
                    after={
                        "commit_sha": config_source.state.commit_sha,
                        "changes": [a.describe(applied=True) for a in plan.actions],
                    },
                    client_ip=request.client.host if request.client else None,
                )

            return {
                "applied": plan.ok,
                "actions": [a.describe(applied=True) for a in plan.actions],
                "errors": plan.errors,
            }

    return router
