from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from archon.api import build_control_plane_router
from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
from archon.setup import build_setup_router
from argus.aggregate_pipeline import AggregatePipeline
from argus.audit import AuditLogger
from argus.bridge import ProtocolBridge
from argus.pipeline import Pipeline
from argus.rate_limiter import RateLimiterRegistry
from argus.routes import build_data_plane_router
from argus.toolslist import ToolsCache
from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.repo import ApiKeyRepo, AuditRepo, ServerRepo, SettingsRepo
from stoa.health import HealthPoller


def create_app(settings: Settings, db: Database) -> FastAPI:
    server_repo = ServerRepo(db)
    api_key_repo = ApiKeyRepo(db)
    audit_repo = AuditRepo(db)
    settings_repo = SettingsRepo(db)

    api_keys = ApiKeyService(api_key_repo)
    rate_limiter = RateLimiterRegistry()
    audit = AuditLogger(audit_repo)
    http_client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)

    handshake_cache = UpstreamHandshakeCache(http_client)
    bridge = ProtocolBridge(http_client, handshake_cache)
    tools_cache = ToolsCache(db, bridge)
    health_poller = HealthPoller(
        server_repo, http_client, handshake_cache,
        interval_seconds=settings.health_poll_interval_seconds,
    )

    pipeline = Pipeline(
        settings=settings,
        server_repo=server_repo,
        api_keys=api_keys,
        rate_limiter=rate_limiter,
        audit=audit,
        http_client=http_client,
        bridge=bridge,
        tools_cache=tools_cache,
        settings_repo=settings_repo,
    )
    aggregate_pipeline = AggregatePipeline(
        settings=settings, server_repo=server_repo, api_keys=api_keys,
        audit=audit, per_server_pipeline=pipeline,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        audit.start()
        if settings.health_poll_enabled:
            health_poller.start()
        try:
            yield
        finally:
            await health_poller.stop()
            await audit.stop()
            await http_client.aclose()

    app = FastAPI(title="Argus", docs_url=None, redoc_url=None, lifespan=lifespan)

    app.state.settings = settings
    app.state.db = db
    app.state.settings_repo = settings_repo
    app.state.server_repo = server_repo
    app.state.api_keys = api_keys
    app.state.rate_limiter = rate_limiter
    app.state.audit = audit
    app.state.http_client = http_client
    app.state.bridge = bridge
    app.state.tools_cache = tools_cache
    app.state.health_poller = health_poller

    app.include_router(build_setup_router(settings_repo))
    app.include_router(build_control_plane_router(
        server_repo, api_keys, tools_cache, settings_repo, audit_repo, audit, health_poller,
    ))
    app.include_router(build_data_plane_router(pipeline, aggregate_pipeline))

    _mount_web_ui(app)

    return app


def _mount_web_ui(app: FastAPI) -> None:
    """Serves the built React SPA (web/dist, produced by the Dockerfile's node build stage).
    Registered LAST so it never shadows /api/* or /mcp/* — FastAPI/Starlette match routes in
    registration order, and this uses a catch-all path.

    In local dev (no dist/ present, e.g. running `python -m argus` directly against the repo
    without having built web/), this mount is a no-op — use `npm run dev` in web/ instead,
    which proxies /api and /mcp to this backend (see web/vite.config.ts)."""
    dist_dir = Path(__file__).parent.parent / "web" / "dist"
    if not dist_dir.is_dir():
        return

    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="web-assets")

    index_path = dist_dir / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str) -> Response:
        # A React Router client-side route (e.g. /servers/shell) has no matching file on
        # disk — serve index.html for anything that isn't a real static asset, and let the
        # client-side router take it from there.
        candidate = dist_dir / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(index_path)
