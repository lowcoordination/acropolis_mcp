from __future__ import annotations

import asyncio
import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from archon.admin_auth import require_admin
from archon.auth.apikeys import ApiKeyService
from archon.schemas import (
    AuditEventResponse,
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
)
from argus.audit import AuditLogger
from argus.rate_limiter import RateLimiterRegistry, server_key
from argus.toolslist import ToolsCache
from db.database import utcnow
from db.repo import AuditRepo, ServerNotFoundError, ServerRepo, SettingsRepo, SlugConflictError
from stoa.health import PROBE_TIMEOUT_SECONDS, HealthPoller

# Settings keys + defaults, applied when a key is absent from the settings table.
_SETTINGS_DEFAULTS = {
    "auth_mode": "keyed",
    "aggregate_enabled": "true",
    "default_ttl_ms": "300000",
    "audit_retention_days": "30",
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
    async def create_server(body: ServerCreateRequest):
        try:
            server = await server_repo.create(
                slug=body.slug, name=body.name, upstream_url=body.upstream_url,
                enabled=body.enabled, in_aggregate=body.in_aggregate,
                upstream_auth_header=body.upstream_auth_header,
            )
        except SlugConflictError:
            raise HTTPException(status_code=409, detail=f"server slug '{body.slug}' already exists")

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
    async def update_server(slug: str, body: ServerUpdateRequest):
        # F23: upstream_auth_header needs three states (unset/set-to-value/cleared-to-null),
        # which a plain `Optional[str] = None` field can't distinguish on its own — checking
        # model_fields_set tells us whether the key was present in the request body at all.
        from db.repo import _UNSET

        auth_header_update = (
            body.upstream_auth_header if "upstream_auth_header" in body.model_fields_set else _UNSET
        )
        try:
            server = await server_repo.update(
                slug, name=body.name, upstream_url=body.upstream_url,
                enabled=body.enabled, in_aggregate=body.in_aggregate,
                upstream_auth_header=auth_header_update,
            )
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        return _server_to_response(server)

    @router.delete("/servers/{slug}", status_code=204)
    async def delete_server(slug: str):
        try:
            await server_repo.delete(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
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
            ))
        fetched_at = await tools_cache.fetched_at(server.id)
        return ServerToolsResponse(fetched_at=fetched_at, tools=result)

    @router.get("/servers/{slug}/policy", response_model=PolicyResponse)
    async def get_policy(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        policy = await server_repo.get_policy(server.id)
        return PolicyResponse(**policy.model_dump())

    @router.put("/servers/{slug}/policy", response_model=PolicyResponse)
    async def set_policy(slug: str, body: PolicyUpdateRequest):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        await server_repo.set_policy(server.id, body)
        if tools_cache is not None:
            # A stale filtered tools/list would otherwise show a tool that was just denied,
            # or hide one that was just allowed, until the TTL naturally expires.
            await tools_cache.invalidate(server.id)
        policy = await server_repo.get_policy(server.id)
        return PolicyResponse(**policy.model_dump())

    @router.get("/keys", response_model=list[KeyResponse])
    async def list_keys():
        keys = await api_keys.list()
        return [_key_to_response(k) for k in keys]

    @router.post("/keys", response_model=KeyCreatedResponse, status_code=201)
    async def create_key(body: KeyCreateRequest):
        generated = await api_keys.create(name=body.name, server_scopes=body.server_scopes)
        return KeyCreatedResponse(
            id=generated.record.id, name=generated.record.name,
            key_prefix=generated.record.key_prefix, plaintext=generated.plaintext,
        )

    @router.patch("/keys/{key_id}", response_model=KeyResponse)
    async def patch_key(key_id: int, enabled: bool):
        if enabled:
            await api_keys.enable(key_id)
        else:
            await api_keys.disable(key_id)
        keys = await api_keys.list()
        match = next((k for k in keys if k.id == key_id), None)
        if match is None:
            raise HTTPException(status_code=404, detail="key not found")
        return _key_to_response(match)

    @router.delete("/keys/{key_id}", status_code=204)
    async def delete_key(key_id: int):
        await api_keys.delete(key_id)

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
            )

        @router.put("/settings", response_model=SettingsResponse)
        async def update_settings(body: SettingsUpdateRequest):
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
            await settings_repo.set_many(updates)
            return await get_settings()

    if audit_repo is not None:
        @router.get("/stats", response_model=StatsResponse)
        async def get_stats():
            from datetime import datetime, timedelta, timezone

            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            requests_24h = await audit_repo.count_since(since)
            blocked_24h = await audit_repo.count_since(since, decision="BLOCKED")
            allowed_24h = await audit_repo.count_since(since, decision="ALLOWED")
            recent_blocked = await audit_repo.query(decision="BLOCKED", limit=10)

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
        ):
            events = await audit_repo.query(
                server_slug=server_slug, decision=decision, tool=tool,
                before_id=before_id, limit=min(limit, 500),
                api_key_id=api_key_id, after=after, before=before, search=search,
            )
            return [AuditEventResponse(**{**e, "bridged": bool(e["bridged"])}) for e in events]

        @router.get("/audit/export.csv")
        async def export_audit_csv(
            server_slug: Optional[str] = None, decision: Optional[str] = None,
            tool: Optional[str] = None, api_key_id: Optional[int] = None,
            after: Optional[str] = None, before: Optional[str] = None,
            search: Optional[str] = None,
        ):
            columns = [
                "id", "ts", "server_slug", "api_key_id", "client_ip", "endpoint", "rpc_method",
                "tool", "decision", "rule", "matched", "reason", "args_summary", "bridged",
                "status_code", "latency_ms",
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

    return router
