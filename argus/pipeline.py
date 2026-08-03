from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
from argus.audit import AuditLogger
from argus.headers import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    METHODS_REQUIRING_NAME,
    extract_name_from_params,
    header_matches_body,
    strip_hop_by_hop,
)
from argus.jsonrpc import HEADER_MISMATCH_ERROR, rpc_error, sanitize_rpc_id
from argus.policy import evaluate
from argus.rate_limiter import RateLimiterRegistry, api_key_key, server_key, tool_key
from db.models import ServerRecord
from db.repo import ServerRepo

logger = logging.getLogger("argus.pipeline")


class RoutingError(Exception):
    """Raised for conditions that should short-circuit the pipeline with an HTTP response."""

    def __init__(self, status_code: int, body: str, media_type: str = "application/json"):
        self.status_code = status_code
        self.body = body
        self.media_type = media_type
        super().__init__(body)


class Pipeline:
    """
    M1 scope: per-server passthrough proxy. No aggregate endpoint, no protocol bridging yet —
    both client and upstream are assumed to speak the same (2025-06-18-style) generation.
    That scope boundary is deliberate (see plan milestone M1 vs M2).
    """

    def __init__(
        self,
        settings: Settings,
        server_repo: ServerRepo,
        api_keys: ApiKeyService,
        rate_limiter: RateLimiterRegistry,
        audit: AuditLogger,
        http_client: httpx.AsyncClient,
    ):
        self._settings = settings
        self._servers = server_repo
        self._api_keys = api_keys
        self._rate_limiter = rate_limiter
        self._audit = audit
        self._client = http_client

    async def handle(self, request: Request, slug: str, path: str) -> Response:
        start = time.monotonic()
        server: Optional[ServerRecord] = None
        try:
            server = await self._resolve_server(slug)
            api_key_id = await self._authenticate(request, slug)
            body_bytes = await self._read_body_guarded(request)
            response = await self._process(request, server, path, body_bytes, api_key_id)
            return response
        except RoutingError as e:
            await self._audit.log(
                server_slug=slug,
                tool=None,
                decision="ERROR",
                endpoint="per-server",
                status_code=e.status_code,
                latency_ms=int((time.monotonic() - start) * 1000),
                reason=e.body[:200],
            )
            return Response(status_code=e.status_code, content=e.body, media_type=e.media_type)

    async def _resolve_server(self, slug: str) -> ServerRecord:
        from db.repo import ServerNotFoundError

        try:
            server = await self._servers.get(slug)
        except ServerNotFoundError:
            raise RoutingError(404, rpc_error(None, f"unknown server '{slug}'"))
        if not server.enabled:
            raise RoutingError(404, rpc_error(None, f"server '{slug}' is disabled"))
        return server

    async def _authenticate(self, request: Request, slug: str) -> Optional[int]:
        if self._settings.auth_mode == "open":
            return None

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise RoutingError(401, rpc_error(None, "missing bearer token"))
        plaintext = auth_header[len("Bearer "):]
        record = await self._api_keys.verify(plaintext)
        if record is None:
            raise RoutingError(401, rpc_error(None, "invalid or disabled api key"))
        if not self._api_keys.key_permits_server(record, slug):
            raise RoutingError(403, rpc_error(None, f"key not scoped for server '{slug}'"))
        return record.id

    async def _read_body_guarded(self, request: Request) -> bytes:
        content_length = request.headers.get("content-length")
        max_bytes = self._settings.max_body_bytes
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    raise RoutingError(413, rpc_error(None, "payload too large"))
            except ValueError:
                raise RoutingError(400, rpc_error(None, "invalid content-length header"))

        body_bytes = await request.body()
        if len(body_bytes) > max_bytes:
            raise RoutingError(413, rpc_error(None, "payload too large"))
        return body_bytes

    async def _process(
        self,
        request: Request,
        server: ServerRecord,
        path: str,
        body_bytes: bytes,
        api_key_id: Optional[int],
    ) -> Response:
        start = time.monotonic()
        rpc_id: Any = None
        rpc_method: str = ""
        tool_name: Optional[str] = None

        if request.method == "POST" and body_bytes:
            try:
                body_json = json.loads(body_bytes)
            except json.JSONDecodeError:
                body_json = None

            if body_json is not None:
                rpc_id = body_json.get("id")
                rpc_method = body_json.get("method", "")
                params = body_json.get("params", {}) or {}
                body_name = extract_name_from_params(rpc_method, params)

                mismatch_response = self._check_header_consistency(request, rpc_method, body_name)
                if mismatch_response is not None:
                    await self._audit.log(
                        server_slug=server.slug, tool=body_name, decision="ERROR",
                        endpoint="per-server", rpc_method=rpc_method,
                        api_key_id=api_key_id, reason="Mcp-Method/Mcp-Name header mismatch",
                        status_code=400, latency_ms=int((time.monotonic() - start) * 1000),
                    )
                    return mismatch_response

                if rpc_method == "tools/call":
                    tool_name = body_json.get("params", {}).get("name")
                    arguments = body_json.get("params", {}).get("arguments") or {}

                    if not tool_name or not isinstance(tool_name, str):
                        await self._audit.log(
                            server_slug=server.slug, tool="<missing>", decision="BLOCKED",
                            endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                            reason="tools/call missing required 'name' field", status_code=400,
                            latency_ms=int((time.monotonic() - start) * 1000),
                        )
                        return Response(
                            content=rpc_error(rpc_id, "tools/call missing required 'name' field"),
                            status_code=400, media_type="application/json",
                        )

                    blocked_response = await self._check_rate_limits(
                        server, tool_name, api_key_id, rpc_id, start
                    )
                    if blocked_response is not None:
                        return blocked_response

                    policy = await self._servers.get_policy(server.id)
                    decision = evaluate(tool_name, arguments, server.name, policy)
                    await self._audit.log(
                        server_slug=server.slug, tool=tool_name,
                        decision="BLOCKED" if decision.blocked else "ALLOWED",
                        endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                        rule=decision.rule, matched=decision.matched,
                        args_summary=decision.args_summary, reason=decision.reason,
                        latency_ms=int((time.monotonic() - start) * 1000),
                    )

                    if decision.blocked:
                        return Response(
                            content=rpc_error(
                                rpc_id, f"Blocked by argus: {decision.reason}",
                                data={"tool": tool_name, "rule": decision.rule, "matched": decision.matched},
                            ),
                            status_code=403, media_type="application/json",
                        )
                else:
                    await self._audit.log(
                        server_slug=server.slug, tool=body_name, decision="PASSTHROUGH",
                        endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                        latency_ms=int((time.monotonic() - start) * 1000),
                    )

        return await self._forward(request, server, path, body_bytes)

    def _check_header_consistency(
        self, request: Request, rpc_method: str, body_name: Optional[str]
    ) -> Optional[Response]:
        mcp_method_header = request.headers.get(MCP_METHOD_HEADER)
        mcp_name_header = request.headers.get(MCP_NAME_HEADER)
        if not header_matches_body(mcp_method_header, mcp_name_header, rpc_method, body_name):
            return Response(
                content=rpc_error(
                    None, "Mcp-Method/Mcp-Name header does not match request body",
                    code=HEADER_MISMATCH_ERROR,
                ),
                status_code=400, media_type="application/json",
            )
        return None

    async def _check_rate_limits(
        self, server: ServerRecord, tool_name: str, api_key_id: Optional[int], rpc_id: Any, start: float
    ) -> Optional[Response]:
        # Lazily (re)register the server-level bucket from its current policy. Cheap: register()
        # only replaces the dict entry, and unregistered keys are treated as unlimited, so a
        # server with no rate_limit configured never gets a bucket at all.
        # NOTE (tracked gap, not M1 scope): tool_policies.rate_limit exists in the DB schema but
        # ServerPolicy doesn't surface per-tool limits yet, so only the server-level limit is
        # enforced here — matches what the real guard-config.yml fleet actually used.
        policy = await self._servers.get_policy(server.id)
        srv_key = server_key(server.slug)
        if policy.rate_limit and not self._rate_limiter.is_registered(srv_key):
            self._rate_limiter.register(srv_key, policy.rate_limit)

        keys = [srv_key] if policy.rate_limit else []
        keys.append(tool_key(server.slug, tool_name))
        if api_key_id is not None:
            keys.append(api_key_key(api_key_id))
        if not await self._rate_limiter.check_all(keys):
            await self._audit.log(
                server_slug=server.slug, tool=tool_name, decision="BLOCKED",
                endpoint="per-server", rpc_method="tools/call", api_key_id=api_key_id,
                rule="rate_limit", reason="Rate limit exceeded",
                latency_ms=int((time.monotonic() - start) * 1000),
            )
            return Response(
                content=rpc_error(rpc_id, "Rate limit exceeded", data={"tool": tool_name}),
                status_code=429, media_type="application/json",
            )
        return None

    async def _forward(
        self, request: Request, server: ServerRecord, path: str, body_bytes: bytes
    ) -> Response:
        upstream_url = httpx.URL(
            f"{server.upstream_url}/{path}".rstrip("/") if path else server.upstream_url,
            query=request.url.query.encode("utf-8"),
        )
        forward_headers = strip_hop_by_hop(request.headers.raw)

        upstream_req = self._client.build_request(
            method=request.method, url=upstream_url, content=body_bytes, headers=forward_headers,
        )
        r = await self._client.send(upstream_req, stream=True)

        return StreamingResponse(
            r.aiter_raw(), status_code=r.status_code, headers=dict(r.headers),
            background=BackgroundTask(r.aclose),
        )
