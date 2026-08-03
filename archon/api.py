from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from archon.admin_auth import require_admin
from archon.auth.apikeys import ApiKeyService
from archon.schemas import (
    KeyCreatedResponse,
    KeyCreateRequest,
    KeyResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    ServerCreateRequest,
    ServerResponse,
    ServerUpdateRequest,
)
from argus.toolslist import ToolsCache
from db.repo import ApiKeyRepo, ServerNotFoundError, ServerRepo, SlugConflictError


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


def build_control_plane_router(
    server_repo: ServerRepo, api_keys: ApiKeyService, tools_cache: Optional[ToolsCache] = None,
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

    return router
