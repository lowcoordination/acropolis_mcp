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
from argus.bridge import BridgeError, ProtocolBridge
from argus.discover import synthesize_server_discover
from argus.generation import ClientGeneration, detect_client_generation
from argus.headers import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    METHODS_REQUIRING_NAME,
    extract_name_from_params,
    filter_response_headers,
    header_matches_body,
    strip_hop_by_hop,
)
from argus.jsonrpc import HEADER_MISMATCH_ERROR, rpc_error, sanitize_rpc_id
from argus.policy import evaluate
from argus.rate_limiter import RateLimiterRegistry, server_key, tool_key
from argus.toolslist import ToolsCache
from db.models import ServerPolicy, ServerRecord
from db.repo import ServerRepo, SettingsRepo

logger = logging.getLogger("argus.pipeline")


def _client_ip(request: Request) -> Optional[str]:
    """F22 fix (review 2026-08-04): client_ip is a parameter on AuditLogger.log() and a column
    in audit_events — grep confirmed no call site anywhere ever passed it, so every audit
    record had client_ip = NULL. For a gateway whose selling point is auditability, not being
    able to attribute a blocked/allowed call to a source materially undercuts the feature for
    incident response. request.client.host is available at every call site that has a Request
    object; this small helper is threaded through instead of duplicating the None-check."""
    return request.client.host if request.client else None


class RoutingError(Exception):
    """Raised for conditions that should short-circuit the pipeline with an HTTP response."""

    def __init__(self, status_code: int, body: str, media_type: str = "application/json"):
        self.status_code = status_code
        self.body = body
        self.media_type = media_type
        super().__init__(body)


class Pipeline:
    """
    M2: per-server proxy that additionally bridges 2026-generation stateless clients to
    2025-generation upstreams (the whole real fleet, today). A 2025-generation client is still
    served by raw passthrough, unchanged from M1 — bridging only engages when Mcp-Method is
    present on the request (see argus.generation.detect_client_generation).
    """

    def __init__(
        self,
        settings: Settings,
        server_repo: ServerRepo,
        api_keys: ApiKeyService,
        rate_limiter: RateLimiterRegistry,
        audit: AuditLogger,
        http_client: httpx.AsyncClient,
        bridge: Optional[ProtocolBridge] = None,
        tools_cache: Optional[ToolsCache] = None,
        settings_repo: Optional[SettingsRepo] = None,
    ):
        self._settings = settings
        self._servers = server_repo
        self._api_keys = api_keys
        self._rate_limiter = rate_limiter
        self._audit = audit
        self._client = http_client
        self._bridge = bridge
        self._tools_cache = tools_cache
        self._settings_repo = settings_repo

    @property
    def tools_cache(self) -> Optional[ToolsCache]:
        return self._tools_cache

    async def handle(
        self, request: Request, slug: str, path: str, body_override: Optional[bytes] = None,
        force_generation: Optional[ClientGeneration] = None,
        skip_api_key_auth: bool = False, origin: Optional[str] = None,
    ) -> Response:
        """`body_override` lets a caller (the aggregate pipeline) substitute a rewritten body
        — e.g. a de-namespaced tool name — without touching Starlette's internal body cache.

        `force_generation` lets a caller bypass header-based generation detection. The aggregate
        endpoint is itself an inherently 2026-shaped concept (a single namespaced stateless
        call) regardless of whether the original inbound request happened to carry Mcp-Method —
        it must always be bridged, not accidentally fall back to 2025 raw passthrough (which
        forwards headers the real upstream may reject, e.g. a bare `Accept: application/json`
        that FastMCP 406s on because it expects `application/json, text/event-stream`).

        `skip_api_key_auth` + `origin` exist for feature #1 (the in-UI tool tester): an
        admin-session "Try it" call must run through REAL rate limiting, policy evaluation, and
        audit logging — a simulated evaluator could drift from the one actually enforcing — but
        it explicitly bypasses the data plane's *API-key* auth (the operator is already
        authenticated as admin) and tags its audit row `origin='test'` so it never pollutes
        /stats or looks like real client traffic. Only the control plane's test-call route may
        set these; nothing on the data plane ever does.
        """
        start = time.monotonic()
        server: Optional[ServerRecord] = None
        try:
            server = await self._resolve_server(slug)
            api_key_id = (
                None if skip_api_key_auth else await self._authenticate(request, slug)
            )
            body_bytes = (
                self._guard_body_size(body_override) if body_override is not None
                else await self._read_body_guarded(request)
            )
            response = await self._process(
                request, server, path, body_bytes, api_key_id,
                force_generation=force_generation, origin=origin,
            )
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
                client_ip=_client_ip(request),
                origin=origin,
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

    async def _current_auth_mode(self) -> str:
        """Data-plane auth mode, sourced live from the DB settings table (set by the first-run
        wizard / Settings page in Archon) rather than the static env-var Settings object — the
        env var is only the DEFAULT applied when the DB has no override yet. Reading this per
        request means a policy change in the UI takes effect immediately, matching what the
        Settings page's save button visibly implies it does."""
        if self._settings_repo is not None:
            stored = await self._settings_repo.get("auth_mode")
            if stored is not None:
                return stored
        return self._settings.auth_mode

    async def authenticate_no_scope(self, request: Request) -> Optional[int]:
        """Auth check with no per-server scope requirement — for entry points that aren't
        about one specific server (the aggregate endpoint's tools/list and server/discover,
        which span every registered server). Still fully respects auth_mode and requires a
        valid, enabled key when auth_mode is 'keyed'; just skips the scope check that
        _authenticate does for a single-server request."""
        if await self._current_auth_mode() == "open":
            return None
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise RoutingError(401, rpc_error(None, "missing bearer token"))
        plaintext = auth_header[len("Bearer "):]
        record = await self._api_keys.verify(plaintext)
        if record is None:
            raise RoutingError(401, rpc_error(None, "invalid or disabled api key"))
        return record.id

    async def _authenticate(self, request: Request, slug: str) -> Optional[int]:
        if await self._current_auth_mode() == "open":
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
        return self._guard_body_size(body_bytes)

    def _guard_body_size(self, body_bytes: bytes) -> bytes:
        if len(body_bytes) > self._settings.max_body_bytes:
            raise RoutingError(413, rpc_error(None, "payload too large"))
        return body_bytes

    async def _process(
        self,
        request: Request,
        server: ServerRecord,
        path: str,
        body_bytes: bytes,
        api_key_id: Optional[int],
        force_generation: Optional[ClientGeneration] = None,
        origin: Optional[str] = None,
    ) -> Response:
        start = time.monotonic()
        rpc_id: Any = None
        rpc_method: str = ""
        tool_name: Optional[str] = None
        client_ip = _client_ip(request)

        if request.method == "POST" and body_bytes:
            try:
                body_json = json.loads(body_bytes)
            except json.JSONDecodeError:
                body_json = None

            # F11 fix (review 2026-08-04): a JSON-RPC batch (a top-level array — spec-legal) or
            # a bare top-level JSON string/number both parse successfully but aren't a dict, so
            # body_json.get(...) below would raise AttributeError -> unhandled 500. Confirmed:
            # `[{"jsonrpc":"2.0","id":1,"method":"ping"}]` and a bare `"hello"` body both
            # crashed the pipeline pre-fix. Treat anything non-dict the same as unparseable —
            # falls through to the PASSTHROUGH/forward path below with rpc_method="" untouched,
            # same as today's un-parseable-JSON case, rather than inventing new handling.
            if not isinstance(body_json, dict):
                body_json = None

            if body_json is not None:
                rpc_id = body_json.get("id")
                rpc_method = body_json.get("method", "")
                params = body_json.get("params", {}) or {}
                body_name = extract_name_from_params(rpc_method, params)

                # Header/body consistency is only meaningful when headers were actually sent by
                # the real client — skip it for a forced (aggregate-originated) dispatch, since
                # the rewritten body's tool name legitimately won't match the ORIGINAL request's
                # (still-namespaced) Mcp-Name header, if one was even present.
                if force_generation is None:
                    mismatch_response = self._check_header_consistency(request, rpc_method, body_name)
                    if mismatch_response is not None:
                        await self._audit.log(
                            server_slug=server.slug, tool=body_name, decision="ERROR",
                            endpoint="per-server", rpc_method=rpc_method,
                            api_key_id=api_key_id, reason="Mcp-Method/Mcp-Name header mismatch",
                            status_code=400, latency_ms=int((time.monotonic() - start) * 1000),
                            client_ip=client_ip,
                        )
                        return mismatch_response

                generation = force_generation or detect_client_generation(request)

                if rpc_method == "server/discover":
                    return self._handle_discover(server, rpc_id)

                if rpc_method == "tools/list" and self._tools_cache is not None:
                    return await self._handle_tools_list(server, rpc_id, api_key_id, start, client_ip)

                if generation == ClientGeneration.GEN_2026 and self._bridge is not None:
                    return await self._handle_bridged(
                        server, rpc_method, rpc_id, params, body_json.get("_meta"),
                        api_key_id, start, client_ip, origin=origin,
                    )

                if rpc_method == "tools/call":
                    # F11 fix: this used to re-read body_json.get("params", {}) from scratch
                    # instead of reusing the `params` local computed above (line 216, which
                    # already has the `or {}` guard) — re-introducing the exact
                    # params-can-be-None crash two lines after it was fixed for the `params`
                    # local. Reuse `params` here so there's only one place this is guarded.
                    tool_name = params.get("name")
                    arguments = params.get("arguments") or {}

                    if not tool_name or not isinstance(tool_name, str):
                        await self._audit.log(
                            server_slug=server.slug, tool="<missing>", decision="BLOCKED",
                            endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                            reason="tools/call missing required 'name' field", status_code=400,
                            latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
                        )
                        return Response(
                            content=rpc_error(rpc_id, "tools/call missing required 'name' field"),
                            status_code=400, media_type="application/json",
                        )

                    policy = await self._servers.get_policy(server.id)
                    blocked_response = await self._check_rate_limits(
                        server, policy, tool_name, api_key_id, rpc_id, start, client_ip
                    )
                    if blocked_response is not None:
                        return blocked_response

                    decision = await evaluate(tool_name, arguments, server.name, policy)
                    await self._audit.log(
                        server_slug=server.slug, tool=tool_name,
                        decision="BLOCKED" if decision.blocked else "ALLOWED",
                        endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                        rule=decision.rule, matched=decision.matched,
                        args_summary=decision.args_summary, reason=decision.reason,
                        latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
                        dlp_detector=decision.dlp_detector, dlp_action=decision.dlp_action,
                        dlp_match_count=decision.dlp_match_count,
                    )

                    if decision.blocked:
                        return Response(
                            content=rpc_error(
                                rpc_id, f"Blocked by acropolis: {decision.reason}",
                                data={"tool": tool_name, "rule": decision.rule, "matched": decision.matched},
                            ),
                            status_code=403, media_type="application/json",
                        )

                    # DLP redact (enterprise #10): the redacted body MUST be what actually
                    # leaves the process — re-serialize the JSON-RPC envelope with the redacted
                    # arguments substituted in and forward THAT, never the original body_bytes.
                    # This is the third consumer of the body_override seam (after
                    # AggregatePipeline's de-namespacing rewrite and the tool tester), reusing
                    # it rather than inventing a parallel forwarding path.
                    if decision.dlp_redacted_arguments is not None:
                        rewritten = dict(body_json)
                        rewritten_params = dict(params)
                        rewritten_params["arguments"] = decision.dlp_redacted_arguments
                        rewritten["params"] = rewritten_params
                        body_bytes = json.dumps(rewritten).encode("utf-8")
                else:
                    await self._audit.log(
                        server_slug=server.slug, tool=body_name, decision="PASSTHROUGH",
                        endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                        latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
                    )

        return await self._forward(request, server, path, body_bytes)

    def _handle_discover(self, server: ServerRecord, rpc_id: Any) -> Response:
        result = synthesize_server_discover(server)
        return Response(
            content=json.dumps({"jsonrpc": "2.0", "id": sanitize_rpc_id(rpc_id), "result": result}),
            status_code=200, media_type="application/json",
        )

    async def _handle_tools_list(
        self, server: ServerRecord, rpc_id: Any, api_key_id: Optional[int], start: float,
        client_ip: Optional[str] = None,
    ) -> Response:
        policy = await self._servers.get_policy(server.id)
        tools = await self._tools_cache.get_filtered_tools(
            server.id, server.upstream_url, policy, upstream_auth_header=server.upstream_auth_header
        )
        await self._audit.log(
            server_slug=server.slug, tool=None, decision="PASSTHROUGH",
            endpoint="per-server", rpc_method="tools/list", api_key_id=api_key_id,
            latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
        )
        return Response(
            content=json.dumps({"jsonrpc": "2.0", "id": sanitize_rpc_id(rpc_id), "result": {"tools": tools}}),
            status_code=200, media_type="application/json",
        )

    async def _handle_bridged(
        self, server: ServerRecord, rpc_method: str, rpc_id: Any, params: dict,
        meta: Optional[dict], api_key_id: Optional[int], start: float,
        client_ip: Optional[str] = None, origin: Optional[str] = None,
    ) -> Response:
        if rpc_method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}

            if not tool_name or not isinstance(tool_name, str):
                await self._audit.log(
                    server_slug=server.slug, tool="<missing>", decision="BLOCKED",
                    endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                    reason="tools/call missing required 'name' field", status_code=400,
                    latency_ms=int((time.monotonic() - start) * 1000), bridged=True,
                    client_ip=client_ip, origin=origin,
                )
                return Response(
                    content=rpc_error(rpc_id, "tools/call missing required 'name' field"),
                    status_code=400, media_type="application/json",
                )

            policy = await self._servers.get_policy(server.id)
            blocked_response = await self._check_rate_limits(
                server, policy, tool_name, api_key_id, rpc_id, start, client_ip
            )
            if blocked_response is not None:
                return blocked_response

            decision = await evaluate(tool_name, arguments, server.name, policy)
            await self._audit.log(
                server_slug=server.slug, tool=tool_name,
                decision="BLOCKED" if decision.blocked else "ALLOWED",
                endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                rule=decision.rule, matched=decision.matched,
                args_summary=decision.args_summary, reason=decision.reason,
                latency_ms=int((time.monotonic() - start) * 1000), bridged=True,
                client_ip=client_ip, origin=origin,
                dlp_detector=decision.dlp_detector, dlp_action=decision.dlp_action,
                dlp_match_count=decision.dlp_match_count,
            )
            # DLP redact (enterprise #10): the bridged path forwards `params` directly to
            # ProtocolBridge.bridge_call rather than raw body bytes, so redaction here means
            # substituting the redacted arguments into `params` before that call — no
            # body_override needed on this path, but the ordering guarantee is identical: this
            # happens before bridge_call is ever invoked, so nothing unredacted leaves the
            # process.
            if decision.dlp_redacted_arguments is not None:
                params = dict(params)
                params["arguments"] = decision.dlp_redacted_arguments
            if decision.blocked:
                return Response(
                    content=rpc_error(
                        rpc_id, f"Blocked by acropolis: {decision.reason}",
                        data={"tool": tool_name, "rule": decision.rule, "matched": decision.matched},
                    ),
                    status_code=403, media_type="application/json",
                )
        else:
            await self._audit.log(
                server_slug=server.slug, tool=None, decision="PASSTHROUGH",
                endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                latency_ms=int((time.monotonic() - start) * 1000), bridged=True,
                client_ip=client_ip, origin=origin,
            )

        try:
            status, body = await self._bridge.bridge_call(
                server_id=server.id, upstream_url=server.upstream_url, rpc_method=rpc_method,
                rpc_id=rpc_id, params=params, meta=meta,
                upstream_auth_header=server.upstream_auth_header,
            )
        except BridgeError as e:
            await self._audit.log(
                server_slug=server.slug, tool=None, decision="ERROR",
                endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                reason=e.body[:200], status_code=e.status_code, bridged=True,
                latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
                origin=origin,
            )
            return Response(content=e.body, status_code=e.status_code, media_type="application/json")

        return Response(content=json.dumps(body), status_code=status, media_type="application/json")

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
        self, server: ServerRecord, policy: ServerPolicy, tool_name: str,
        api_key_id: Optional[int], rpc_id: Any, start: float,
        client_ip: Optional[str] = None,
    ) -> Optional[Response]:
        # F8 fix (review 2026-08-04): this used to be `if policy.rate_limit and not
        # is_registered(srv_key): register(...)` — a bucket was built ONCE per process and
        # never refreshed, so an operator raising a limit from 5/minute to 500/minute got a 200
        # from the API but the gateway kept enforcing 5/minute until restart. The fix can't be
        # "just always call register()" either — TokenBucket construction resets consumed
        # state, so registering fresh on every request would hand every caller an always-full
        # bucket and defeat rate limiting entirely. Instead: (re)register only when the SPEC
        # STRING has actually changed since it was last registered for this key, via
        # RateLimiterRegistry.ensure_current — a no-op on the hot path once the bucket matches
        # the live policy, but picks up an operator's change on the very next request.
        #
        # F9 fix (review 2026-08-04): tool_key(...) and the now-removed api_key_key(...) were
        # both constructed and passed to check_all() here, but nothing anywhere ever called
        # register() for either — check_all() treats an unregistered key as "unlimited", so
        # both lookups always passed regardless of load. A compromised or runaway API key had
        # NO rate limit whatsoever, despite the code reading as though one was enforced.
        #
        # Per-tool limits: the DB column (tool_policies.rate_limit) exists but ServerPolicy
        # doesn't surface it — documented as a tracked gap on tool_key()'s own docstring rather
        # than silently dropped, since it matches what the real guard-config.yml fleet actually
        # configured (server-level only).
        #
        # Per-API-key limits: there is currently no schema field to configure one (api_keys has
        # no rate_limit column) — adding one is a real feature (migration + API + UI), out of
        # scope for this fix. Removed the dead api_key_key construction rather than leave code
        # that LOOKED like it enforced a per-key limit while doing nothing; see F23-adjacent
        # design-gap note in the vault (03-reliability-and-ops.md) for where to land it.
        #
        # §26 fix (review 2026-08-04): `policy` used to be fetched HERE via a fresh
        # self._servers.get_policy(server.id) call, and the caller fetched it AGAIN
        # immediately afterward to evaluate the tool decision — two DB reads of the same,
        # request-scoped-immutable data per tools/call. Now the caller fetches once and passes
        # it in.
        srv_key = server_key(server.slug)
        if policy.rate_limit:
            self._rate_limiter.ensure_current(srv_key, policy.rate_limit)
        else:
            self._rate_limiter.unregister(srv_key)

        keys = [srv_key] if policy.rate_limit else []
        keys.append(tool_key(server.slug, tool_name))
        if not await self._rate_limiter.check_all(keys):
            await self._audit.log(
                server_slug=server.slug, tool=tool_name, decision="BLOCKED",
                endpoint="per-server", rpc_method="tools/call", api_key_id=api_key_id,
                rule="rate_limit", reason="Rate limit exceeded",
                latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
            )
            return Response(
                content=rpc_error(rpc_id, "Rate limit exceeded", data={"tool": tool_name}),
                status_code=429, media_type="application/json",
            )
        return None

    async def _forward(
        self, request: Request, server: ServerRecord, path: str, body_bytes: bytes
    ) -> Response:
        # SECURITY: httpx.URL normalises dot segments during parsing, so
        # f"{upstream}/mcp/../../admin" resolves OUTSIDE the configured upstream endpoint —
        # an arbitrary path on the upstream host, bypassing whatever prefix the operator
        # registered. path comes straight from the /mcp/{slug}/{path:path} route with no prior
        # validation, so it must be rejected here, before the URL is ever constructed.
        if path and (path.startswith("/") or "/../" in f"/{path}/" or path in ("..", ".")):
            raise RoutingError(400, rpc_error(None, "invalid upstream path"))

        upstream_url = httpx.URL(
            f"{server.upstream_url}/{path}".rstrip("/") if path else server.upstream_url,
            query=request.url.query.encode("utf-8"),
        )
        forward_headers = strip_hop_by_hop(request.headers.raw)

        # F23 fix (review 2026-08-04): if this server has a configured upstream credential,
        # inject it as the Authorization header sent to the upstream — this is the actual
        # mechanism the design gap was about. Appended AFTER strip_hop_by_hop, and as a plain
        # list append rather than a header-merge, so it always wins even though the client's
        # own Authorization was already stripped (F5) — there should never be two.
        if server.upstream_auth_header:
            forward_headers = [
                (k, v) for k, v in forward_headers if k.lower() != b"authorization"
            ]
            forward_headers.append((b"authorization", server.upstream_auth_header.encode()))

        upstream_req = self._client.build_request(
            method=request.method, url=upstream_url, content=body_bytes, headers=forward_headers,
        )
        # F3 fix (review 2026-08-04): self._client.send() had no exception handling — any httpx
        # transport error (refused connection, DNS failure, TLS error) escaped as an unhandled
        # exception, past Pipeline.handle's `except RoutingError` (the only thing that logs an
        # audit event), all the way to Starlette as a bare 500 with a stack trace and a
        # non-JSON-RPC body. This is the MOST LIKELY real-world event in a self-hosted
        # deployment — an MCP server container restarting — and it broke in the ugliest
        # possible way, with the gateway's own audit trail showing nothing happened. The
        # bridged path (argus/bridge.py:106) already handled this correctly; matched here.
        try:
            r = await self._client.send(upstream_req, stream=True)
        except httpx.HTTPError as e:
            raise RoutingError(502, rpc_error(None, f"upstream request failed: {e}"))

        return StreamingResponse(
            r.aiter_raw(), status_code=r.status_code,
            headers=filter_response_headers(r.headers), background=BackgroundTask(r.aclose),
        )
