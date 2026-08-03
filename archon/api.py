from __future__ import annotations

import asyncio
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
    ServerUpdateRequest,
    SettingsResponse,
    SettingsUpdateRequest,
    StatsResponse,
)
from argus.audit import AuditLogger
from argus.toolslist import ToolsCache
from db.database import utcnow
from db.repo import AuditRepo, ServerNotFoundError, ServerRepo, SettingsRepo, SlugConflictError

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
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])

    @router.get("/health")
    async def health():
        return {"status": "ok"}

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
            )
        except SlugConflictError:
            raise HTTPException(status_code=409, detail=f"server slug '{body.slug}' already exists")
        return _server_to_response(server)

    @router.get("/servers/{slug}", response_model=ServerResponse)
    async def get_server(slug: str):
        try:
            server = await server_repo.get(slug)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        return _server_to_response(server)

    @router.put("/servers/{slug}", response_model=ServerResponse)
    async def update_server(slug: str, body: ServerUpdateRequest):
        try:
            server = await server_repo.update(
                slug, name=body.name, upstream_url=body.upstream_url,
                enabled=body.enabled, in_aggregate=body.in_aggregate,
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
        ):
            events = await audit_repo.query(
                server_slug=server_slug, decision=decision, tool=tool,
                before_id=before_id, limit=min(limit, 500),
            )
            return [AuditEventResponse(**{**e, "bridged": bool(e["bridged"])}) for e in events]

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
