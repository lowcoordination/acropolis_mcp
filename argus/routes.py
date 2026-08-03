from __future__ import annotations

from fastapi import APIRouter, Request, Response

from argus.pipeline import Pipeline


def build_data_plane_router(pipeline: Pipeline) -> APIRouter:
    router = APIRouter()

    @router.api_route(
        "/mcp/{slug}/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )
    async def per_server_with_path(request: Request, slug: str, path: str) -> Response:
        return await pipeline.handle(request, slug, path)

    @router.api_route(
        "/mcp/{slug}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )
    async def per_server_root(request: Request, slug: str) -> Response:
        return await pipeline.handle(request, slug, "")

    return router
