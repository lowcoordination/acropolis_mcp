from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from archon.api import build_control_plane_router
from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
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
    app.state.server_repo = server_repo
    app.state.api_keys = api_keys
    app.state.rate_limiter = rate_limiter
    app.state.audit = audit
    app.state.http_client = http_client
    app.state.bridge = bridge
    app.state.tools_cache = tools_cache
    app.state.health_poller = health_poller

    app.include_router(build_control_plane_router(
        server_repo, api_keys, tools_cache, settings_repo, audit_repo, audit,
    ))
    app.include_router(build_data_plane_router(pipeline, aggregate_pipeline))

    return app
