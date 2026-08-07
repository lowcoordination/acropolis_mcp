from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from archon.api import build_control_plane_router
from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
from archon.setup import build_setup_router
from argus.aggregate_pipeline import AggregatePipeline
from argus.audit import AuditLogger
from argus.bridge import ProtocolBridge
from argus.metrics import build_metrics_router
from argus.pipeline import Pipeline
from argus.rate_limiter import RateLimiterRegistry
from argus.routes import build_data_plane_router
from argus.toolslist import ToolsCache
from argus.upstream import UpstreamHandshakeCache
from db.database import Database
from db.repo import AdminEventRepo, ApiKeyRepo, AuditRepo, ServerRepo, SettingsRepo
from stoa.health import HealthPoller
from stoa.retention import AuditRetentionJob
from stoa.webhooks import WebhookDispatcher


# F20 fix (review 2026-08-04): no Content-Security-Policy, X-Frame-Options, or
# X-Content-Type-Options anywhere, no middleware registered. No CSP means no defence-in-depth
# if an XSS is ever introduced into the React SPA; no frame protection means the admin
# dashboard is clickjackable (embed it in an invisible iframe over a fake UI, trick the admin
# into clicking through actions on the real page underneath). Applied gateway-wide, including
# /mcp/* — those responses are JSON, not HTML, but the headers are harmless there and this way
# nothing has to remember to apply them selectively. HSTS is deliberately NOT set here: TLS, if
# any, is terminated by a reverse proxy in front of Acropolis (see
# docs/tls-and-reverse-proxy.md), and HSTS is a proxy-layer concern — setting it here would
# advertise HTTPS-only even when an operator is legitimately running plain HTTP on a trusted
# LAN, which is this product's documented default. Documented in that same doc instead.
async def _security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


_logger = logging.getLogger("argus.app")


# F3 fix (review 2026-08-04, second half): a global safety net so an exception from ANYWHERE
# in the app — not just the specific _forward() site the review named — never escapes as a
# bare Starlette 500 with a stack trace leaked to the client. The specific fix at the call site
# (RoutingError(502, ...) in argus/pipeline.py's _forward) is what makes THAT failure mode
# return a proper JSON-RPC error and get audited; this handler is the backstop for anything
# else that wasn't specifically anticipated. Logged at ERROR with the traceback server-side
# (exc_info=True) so it's still debuggable — only the CLIENT-facing body is generic.
async def _unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    _logger.error("unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    if request.url.path.startswith("/mcp"):
        from argus.jsonrpc import rpc_error

        return Response(
            content=rpc_error(None, "internal error"), status_code=500,
            media_type="application/json",
        )
    return JSONResponse(status_code=500, content={"detail": "internal error"})


def create_app(settings: Settings, db: Database) -> FastAPI:
    server_repo = ServerRepo(db)
    api_key_repo = ApiKeyRepo(db)
    audit_repo = AuditRepo(db)
    settings_repo = SettingsRepo(db)

    api_keys = ApiKeyService(api_key_repo)
    rate_limiter = RateLimiterRegistry()
    audit = AuditLogger(audit_repo)
    # F13 fix (review 2026-08-04): httpx.AsyncClient(timeout=N) applies N to ALL FOUR of
    # connect/read/write/pool — including pool acquisition wait, which has nothing to do with
    # how long a real upstream tool call should be allowed to take. With the default
    # Limits(max_connections=100), one upstream that accepts TCP connections but never
    # responds could exhaust all 100 in-flight request slots, and every request to every OTHER
    # server would then block acquiring a pool slot for up to the full 120s upstream_timeout —
    # a single hung MCP server taking down the whole gateway. connect/pool get short, fixed
    # budgets (a real handshake or a free connection slot should appear in single-digit
    # seconds); read/write keep the operator-configured budget, since a legitimately slow tool
    # call still needs to be allowed to run long. max_connections raised well above the
    # previous default so a burst across many registered servers doesn't itself become the
    # bottleneck.
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=5.0, pool=5.0,
            read=settings.upstream_timeout_seconds, write=settings.upstream_timeout_seconds,
        ),
        limits=httpx.Limits(max_connections=500, max_keepalive_connections=100),
    )

    handshake_cache = UpstreamHandshakeCache(http_client)
    bridge = ProtocolBridge(http_client, handshake_cache)
    tools_cache = ToolsCache(db, bridge)
    webhook_dispatcher = WebhookDispatcher(audit, settings_repo)
    health_poller = HealthPoller(
        server_repo, http_client, handshake_cache,
        interval_seconds=settings.health_poll_interval_seconds,
        webhook_dispatcher=webhook_dispatcher,
    )
    retention_job = AuditRetentionJob(
        audit_repo, settings_repo,
        check_interval_seconds=settings.audit_retention_check_interval_seconds,
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
        audit=audit, per_server_pipeline=pipeline, settings_repo=settings_repo,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        audit.start()
        webhook_dispatcher.start()
        if settings.health_poll_enabled:
            health_poller.start()
        if settings.audit_retention_enabled:
            retention_job.start()
        try:
            yield
        finally:
            await retention_job.stop()
            await health_poller.stop()
            # Stop the dispatcher before audit — it unsubscribe()s from the SAME AuditLogger it
            # subscribed to in start(), and that logger must still be alive to accept the call.
            await webhook_dispatcher.stop()
            await audit.stop()
            await http_client.aclose()

    app = FastAPI(title="Acropolis", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.middleware("http")(_security_headers_middleware)
    app.add_exception_handler(Exception, _unhandled_exception_handler)

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
    app.state.retention_job = retention_job
    app.state.webhook_dispatcher = webhook_dispatcher

    app.include_router(build_setup_router(settings_repo, rate_limiter))
    app.include_router(build_control_plane_router(
        server_repo, api_keys, tools_cache, settings_repo, audit_repo, audit, health_poller,
        rate_limiter, pipeline, webhook_dispatcher, AdminEventRepo(db),
    ))
    app.include_router(build_data_plane_router(pipeline, aggregate_pipeline))
    app.include_router(build_metrics_router(server_repo, audit_repo))

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
    resolved_dist = dist_dir.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str) -> Response:
        # A React Router client-side route (e.g. /servers/shell) has no matching file on
        # disk — serve index.html for anything that isn't a real static asset, and let the
        # client-side router take it from there.
        #
        # SECURITY: full_path is raw, attacker-controlled input. Two traversal vectors must be
        # closed before touching the filesystem: (1) pathlib's __truediv__ silently discards the
        # left operand when the right side is absolute — Path("/app/dist") / "/etc/passwd"
        # becomes "/etc/passwd" — which a request line starting "//" produces; (2) uvicorn does
        # not normalise ".." before routing, so "/../" reaches this handler intact. Stripping a
        # leading "/" defuses (1); resolving and checking containment via is_relative_to defuses
        # both, including any percent-decoded or symlink-based escape.
        #
        # §26 fix (review 2026-08-04): this catch-all is registered LAST specifically so it
        # never shadows a REGISTERED /api/* or /mcp/* route — but a MISS on those prefixes (a
        # typo'd path, an old client hitting a removed endpoint, a probe) still fell through to
        # here and got served the SPA's index.html with a 200, rather than a 404. An API client
        # has no use for HTML and every reason to want an honest 404 to detect a broken
        # integration; only real browser navigation should ever see index.html.
        if full_path.startswith("api/") or full_path == "api":
            return Response(status_code=404, content="Not Found")

        candidate = (dist_dir / full_path.lstrip("/")).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(resolved_dist):
            return FileResponse(candidate)
        return FileResponse(index_path)
