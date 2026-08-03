from __future__ import annotations

import json
import logging
import time
from typing import Any

from fastapi import Request, Response

from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
from argus.aggregate import namespace_tool_definition, split_namespaced_tool_name
from argus.audit import AuditLogger
from argus.discover import synthesize_gateway_discover
from argus.generation import ClientGeneration
from argus.jsonrpc import rpc_error, sanitize_rpc_id
from argus.pipeline import Pipeline, RoutingError
from db.repo import ServerNotFoundError, ServerRepo

logger = logging.getLogger("argus.aggregate_pipeline")


class AggregatePipeline:
    """
    Handles the aggregate POST /mcp endpoint (no per-server slug in the path). v1 aggregates
    tools only — see plan's aggregate scope note. tools/list merges every enabled, in_aggregate
    server's filtered+cached tool list with {slug}__{tool} namespacing; tools/call strips the
    prefix and re-dispatches through the per-server Pipeline (so all the same auth/rate-limit/
    policy/audit machinery applies — the aggregate is a routing layer in front of it, not a
    parallel enforcement path).
    """

    def __init__(self, settings: Settings, server_repo: ServerRepo, api_keys: ApiKeyService,
                 audit: AuditLogger, per_server_pipeline: Pipeline):
        self._settings = settings
        self._servers = server_repo
        self._api_keys = api_keys
        self._audit = audit
        self._per_server = per_server_pipeline

    async def handle(self, request: Request) -> Response:
        start = time.monotonic()

        # tools/call re-dispatches through Pipeline.handle(), which does its own (per-server-
        # scoped) auth check — but tools/list and server/discover are answered directly here
        # and would otherwise skip authentication entirely regardless of auth_mode. Check
        # up front, before even parsing the body, so every method on this endpoint is gated.
        try:
            await self._per_server.authenticate_no_scope(request)
        except RoutingError as e:
            await self._audit.log(
                server_slug=None, tool=None, decision="ERROR", endpoint="aggregate",
                status_code=e.status_code, reason=e.body[:200],
                latency_ms=int((time.monotonic() - start) * 1000),
            )
            return Response(status_code=e.status_code, content=e.body, media_type=e.media_type)

        body_bytes = await request.body()

        try:
            body_json = json.loads(body_bytes) if body_bytes else None
        except json.JSONDecodeError:
            body_json = None

        if body_json is None:
            return Response(
                content=rpc_error(None, "aggregate endpoint requires a JSON-RPC body"),
                status_code=400, media_type="application/json",
            )

        rpc_id = body_json.get("id")
        rpc_method = body_json.get("method", "")
        params = body_json.get("params", {}) or {}

        if rpc_method == "tools/list":
            return await self._handle_tools_list(rpc_id)
        if rpc_method == "tools/call":
            return await self._handle_tools_call(request, body_json, rpc_id, params)
        if rpc_method == "server/discover":
            return await self._handle_discover(rpc_id)

        await self._audit.log(
            server_slug=None, tool=None, decision="ERROR", endpoint="aggregate",
            rpc_method=rpc_method, reason=f"unsupported method on aggregate endpoint: {rpc_method}",
            status_code=501, latency_ms=int((time.monotonic() - start) * 1000),
        )
        return Response(
            content=rpc_error(rpc_id, f"'{rpc_method}' is not supported on the aggregate endpoint"),
            status_code=501, media_type="application/json",
        )

    async def _handle_discover(self, rpc_id: Any) -> Response:
        servers = await self._servers.list()
        result = synthesize_gateway_discover(servers)
        return Response(
            content=json.dumps({"jsonrpc": "2.0", "id": sanitize_rpc_id(rpc_id), "result": result}),
            status_code=200, media_type="application/json",
        )

    async def _handle_tools_list(self, rpc_id: Any) -> Response:
        servers = await self._servers.list()
        merged: list[dict] = []
        for server in servers:
            if not server.enabled or not server.in_aggregate:
                continue
            policy = await self._servers.get_policy(server.id)
            tools = await self._per_server.tools_cache.get_filtered_tools(
                server.id, server.upstream_url, policy
            )
            for tool in tools:
                namespaced = namespace_tool_definition(server.slug, tool)
                if namespaced is not None:
                    merged.append(namespaced)
                else:
                    logger.warning(
                        "tool '%s' on server '%s' excluded from aggregate (name too long or invalid chars)",
                        tool.get("name"), server.slug,
                    )

        return Response(
            content=json.dumps({"jsonrpc": "2.0", "id": sanitize_rpc_id(rpc_id), "result": {"tools": merged}}),
            status_code=200, media_type="application/json",
        )

    async def _handle_tools_call(
        self, request: Request, body_json: dict, rpc_id: Any, params: dict
    ) -> Response:
        namespaced_name = params.get("name")
        if not namespaced_name or not isinstance(namespaced_name, str):
            return Response(
                content=rpc_error(rpc_id, "tools/call missing required 'name' field"),
                status_code=400, media_type="application/json",
            )

        split = split_namespaced_tool_name(namespaced_name)
        if split is None:
            return Response(
                content=rpc_error(
                    rpc_id, f"'{namespaced_name}' is not a validly-namespaced aggregate tool "
                    f"name (expected '{{server_slug}}__{{tool_name}}')",
                ),
                status_code=400, media_type="application/json",
            )
        slug, tool_name = split

        try:
            server = await self._servers.get(slug)
        except ServerNotFoundError:
            return Response(
                content=rpc_error(rpc_id, f"unknown server '{slug}' in aggregate tool name"),
                status_code=404, media_type="application/json",
            )
        if not server.enabled or not server.in_aggregate:
            return Response(
                content=rpc_error(rpc_id, f"server '{slug}' is not available on the aggregate endpoint"),
                status_code=404, media_type="application/json",
            )

        # Rebuild the request body with the de-namespaced tool name and re-dispatch through
        # the normal per-server pipeline, so auth/rate-limit/policy/audit all apply identically
        # to a direct /mcp/{slug} call — the aggregate is a routing layer, not a parallel path.
        # Passed as body_override rather than mutating Starlette's internal body cache.
        rewritten_body = dict(body_json)
        rewritten_body["params"] = {**params, "name": tool_name}

        return await self._per_server.handle(
            request, slug, "", body_override=json.dumps(rewritten_body).encode(),
            force_generation=ClientGeneration.GEN_2026,
        )
