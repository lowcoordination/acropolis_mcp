from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional

from fastapi import Request, Response

from archon.auth.apikeys import ApiKeyService
from archon.settings import Settings
from argus.aggregate import namespace_tool_definition, split_namespaced_tool_name
from argus.audit import AuditLogger
from argus.discover import synthesize_gateway_discover
from argus.generation import ClientGeneration
from argus.jsonrpc import rpc_error, sanitize_rpc_id
from argus.pipeline import Pipeline, RoutingError, _client_ip
from db.repo import ServerNotFoundError, ServerRepo, SettingsRepo

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
                 audit: AuditLogger, per_server_pipeline: Pipeline,
                 settings_repo: Optional[SettingsRepo] = None):
        self._settings = settings
        self._servers = server_repo
        self._api_keys = api_keys
        self._audit = audit
        self._per_server = per_server_pipeline
        self._settings_repo = settings_repo

    async def _aggregate_enabled(self) -> bool:
        # F15 fix (review 2026-08-04): aggregate_enabled was stored, defaulted, returned by
        # GET /settings, written by PUT /settings, and rendered as a UI toggle — and NOTHING
        # read it. argus/app.py always registered this pipeline and argus/routes.py always
        # registered POST /mcp unconditionally. An operator who toggled the aggregate endpoint
        # off got a 200 from the API and a persisted setting while the endpoint stayed fully
        # live — a control that silently no-ops is worse than an absent one, since it actively
        # tells the operator the merged cross-server tool surface is closed when it isn't.
        # Same DB-is-live pattern as Pipeline._current_auth_mode: read per request so a change
        # via the Settings page takes effect immediately, matching what its save button implies.
        if self._settings_repo is not None:
            stored = await self._settings_repo.get("aggregate_enabled")
            if stored is not None:
                return stored == "true"
        return True  # matches archon/api.py's _SETTINGS_DEFAULTS default

    async def handle(self, request: Request) -> Response:
        start = time.monotonic()
        client_ip = _client_ip(request)

        if not await self._aggregate_enabled():
            await self._audit.log(
                server_slug=None, tool=None, decision="ERROR", endpoint="aggregate",
                status_code=404, reason="aggregate endpoint is disabled in settings",
                latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
            )
            return Response(
                content=rpc_error(None, "aggregate endpoint is disabled"),
                status_code=404, media_type="application/json",
            )

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
                latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
            )
            return Response(status_code=e.status_code, content=e.body, media_type=e.media_type)

        # §26 fix (review 2026-08-04): this used to be a bare `await request.body()` with no
        # size limit at all — unlike the per-server path (Pipeline._read_body_guarded), which
        # enforces settings.max_body_bytes. An authenticated-but-malicious (or just careless)
        # caller could send an arbitrarily large body to this endpoint and force it fully into
        # memory before the JSON-RPC parse even runs. Reuse the per-server pipeline's own guard
        # rather than duplicating the content-length + actual-size check here.
        try:
            body_bytes = await self._per_server._read_body_guarded(request)
        except RoutingError as e:
            await self._audit.log(
                server_slug=None, tool=None, decision="ERROR", endpoint="aggregate",
                status_code=e.status_code, reason=e.body[:200],
                latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
            )
            return Response(status_code=e.status_code, content=e.body, media_type=e.media_type)

        try:
            body_json = json.loads(body_bytes) if body_bytes else None
        except json.JSONDecodeError:
            body_json = None

        # F11 fix (review 2026-08-04): a JSON-RPC batch (top-level array — spec-legal) parses
        # successfully but isn't a dict, so body_json.get(...) below would raise
        # AttributeError -> unhandled 500. Confirmed:
        # `[{"jsonrpc":"2.0","id":1,"method":"ping"}]` crashed pre-fix. Same fix as
        # argus/pipeline.py's _process — treat non-dict JSON the same as unparseable JSON.
        if not isinstance(body_json, dict):
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
            return await self._handle_tools_list(rpc_id, start, client_ip)
        if rpc_method == "tools/call":
            return await self._handle_tools_call(request, body_json, rpc_id, params)
        if rpc_method == "server/discover":
            return await self._handle_discover(rpc_id)

        await self._audit.log(
            server_slug=None, tool=None, decision="ERROR", endpoint="aggregate",
            rpc_method=rpc_method, reason=f"unsupported method on aggregate endpoint: {rpc_method}",
            status_code=501, latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
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

    # F14 fix (review 2026-08-04): each server's tool fetch (upstream handshake + tools/list
    # round-trip on a cache miss) gets its own deadline well below the full
    # upstream_timeout_seconds budget, so one slow/unreachable server can only ever cost this
    # much wall time — never the full per-call timeout, and never serially stacked with every
    # other server's cost (see the asyncio.gather fan-out below).
    _PER_SERVER_DEADLINE_SECONDS = 10.0

    async def _fetch_one_server(self, server, policy) -> list[dict]:
        try:
            tools = await asyncio.wait_for(
                self._per_server.tools_cache.get_filtered_tools(
                    server.id, server.upstream_url, policy,
                    upstream_auth_header=server.upstream_auth_header,
                ),
                timeout=self._PER_SERVER_DEADLINE_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "server '%s' timed out after %.0fs fetching tools for the aggregate endpoint "
                "— excluded from this response, not blocking the others",
                server.slug, self._PER_SERVER_DEADLINE_SECONDS,
            )
            return []

        namespaced_tools = []
        for tool in tools:
            namespaced = namespace_tool_definition(server.slug, tool)
            if namespaced is not None:
                namespaced_tools.append(namespaced)
            else:
                logger.warning(
                    "tool '%s' on server '%s' excluded from aggregate (name too long or invalid chars)",
                    tool.get("name"), server.slug,
                )
        return namespaced_tools

    async def _handle_tools_list(self, rpc_id: Any, start: float, client_ip=None) -> Response:
        # F14 fix: this used to be a plain `for server in servers: await get_policy(...); await
        # get_filtered_tools(...)` loop — every server's cost (a full upstream handshake plus a
        # tools/list round-trip on a cache miss) was SUMMED, sequentially. With 8 registered
        # servers, cold cache, and two slow/unreachable ones at the old 120s upstream timeout,
        # one client tools/list call could block ~4 minutes — and agents typically call
        # tools/list first, so this was the very first thing a user experienced. Also: the
        # aggregate path never audited at all, unlike the per-server path.
        servers = [s for s in (await self._servers.list()) if s.enabled and s.in_aggregate]
        policies = await self._servers.get_policies_for([s.id for s in servers])

        results = await asyncio.gather(
            *(self._fetch_one_server(server, policies[server.id]) for server in servers)
        )
        merged: list[dict] = [tool for server_tools in results for tool in server_tools]

        await self._audit.log(
            server_slug=None, tool=None, decision="PASSTHROUGH", endpoint="aggregate",
            rpc_method="tools/list", latency_ms=int((time.monotonic() - start) * 1000),
            client_ip=client_ip,
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
