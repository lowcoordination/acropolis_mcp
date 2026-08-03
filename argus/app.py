from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from archon.api import build_control_plane_router
from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
from argus.audit import AuditLogger
from argus.pipeline import Pipeline
from argus.rate_limiter import RateLimiterRegistry
from argus.routes import build_data_plane_router
from db.database import Database
from db.repo import ApiKeyRepo, AuditRepo, ServerRepo


def create_app(settings: Settings, db: Database) -> FastAPI:
    server_repo = ServerRepo(db)
    api_key_repo = ApiKeyRepo(db)
    audit_repo = AuditRepo(db)

    api_keys = ApiKeyService(api_key_repo)
    rate_limiter = RateLimiterRegistry()
    audit = AuditLogger(audit_repo)
    http_client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)

    pipeline = Pipeline(
        settings=settings,
        server_repo=server_repo,
        api_keys=api_keys,
        rate_limiter=rate_limiter,
        audit=audit,
        http_client=http_client,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        audit.start()
        try:
            yield
        finally:
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

    app.include_router(build_control_plane_router(server_repo, api_keys))
    app.include_router(build_data_plane_router(pipeline))

    return app
