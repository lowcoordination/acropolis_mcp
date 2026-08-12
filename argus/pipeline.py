from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from archon.auth.apikeys import ApiKeyService
from archon.secrets import SecretProvider, SecretResolutionError
from archon.secrets.local import LocalSecretProvider
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
from argus.policy import Decision, evaluate
from argus.quotas import period_start
from argus.rate_limiter import RateLimiterRegistry, server_key, tool_key
from argus.toolslist import ToolsCache
from argus.tracing import TracingManager, _DisabledTracingManager
from db.database import utcnow
from db.models import ServerPolicy, ServerRecord
from db.repo import ServerRepo, SettingsRepo, UsageRepo

if TYPE_CHECKING:
    from stoa.webhooks import WebhookDispatcher

logger = logging.getLogger("argus.pipeline")


def _client_ip(request: Request) -> Optional[str]:
    """client_ip is a column in audit_events and a parameter on AuditLogger.log() — every call
    site that has a Request must attribute the event to a source, or incident response has
    nothing to work with. request.client.host is available wherever a Request is; this helper
    centralizes the None-check instead of duplicating it."""
    return request.client.host if request.client else None


class RoutingError(Exception):
    """Raised for conditions that should short-circuit the pipeline with an HTTP response."""

    def __init__(self, status_code: int, body: str, media_type: str = "application/json"):
        self.status_code = status_code
        self.body = body
        self.media_type = media_type
        super().__init__(body)


@dataclass
class _EnforcementOutcome:
    """Result of the shared enforcement prelude (issue #52).

    `blocked_response` non-None means the caller returns it immediately — no forwarding. When
    it is None, `decision`/`policy` describe the (allowed) call the caller is about to forward.
    """

    blocked_response: Optional[Response] = None
    decision: Optional[Decision] = None
    policy: Optional[ServerPolicy] = None


class Pipeline:
    """Per-server proxy that additionally bridges 2026-generation stateless clients to
    2025-generation upstreams. A 2025-generation client is served by raw passthrough; bridging
    only engages when Mcp-Method is present on the request (see
    argus.generation.detect_client_generation).
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
        secret_provider: Optional[SecretProvider] = None,
        tracing: Optional[TracingManager] = None,
        usage_repo: Optional[UsageRepo] = None,
        webhook_dispatcher: Optional["WebhookDispatcher"] = None,
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
        # Defaults to LocalSecretProvider (pass-through) so a Pipeline built without a provider
        # behaves exactly as if no secret tier were configured; app.py wires the real,
        # settings-selected provider.
        self._secrets = secret_provider or LocalSecretProvider()
        # Same "defaults to an inert no-op" shape as _secrets above: a Pipeline built without a
        # TracingManager gets one whose .span() context managers are pure no-ops and whose
        # .active is always False, so the disabled path is identical whether or not
        # ACROPOLIS_OTEL_ENABLED is set.
        self._tracing = tracing or _DisabledTracingManager()
        # usage_repo=None (the default for call sites that don't wire one) means BOTH quota
        # enforcement and usage rollup writes are no-ops — see _check_quota/_record_usage
        # below. Same "absent = disabled" shape as _secrets/_tracing above: a Pipeline built
        # without a UsageRepo enforces nothing and records nothing.
        self._usage = usage_repo
        self._webhooks = webhook_dispatcher

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
        # The root span parents under the CALLER's own inbound traceparent (if any), so a trace
        # the calling agent already started continues through Acropolis rather than starting a
        # new, disconnected trace here. extract_context returns None when tracing is inactive
        # or no traceparent was sent — start_as_current_span(context=None) behaves exactly like
        # calling it with no context kwarg at all in that case.
        parent_ctx = self._tracing.extract_context(
            request.headers.get("traceparent"), request.headers.get("tracestate"),
        )
        with self._tracing.span(
            "request",
            attributes={"acropolis.server_slug": slug, "http.method": request.method},
            parent_context=parent_ctx,
        ) as root_span:
            try:
                server = await self._resolve_server(slug)
                api_key_id = (
                    None if skip_api_key_auth else await self._authenticate(request, slug, server)
                )
                body_bytes = (
                    self._guard_body_size(body_override) if body_override is not None
                    else await self._read_body_guarded(request)
                )
                response = await self._process(
                    request, server, path, body_bytes, api_key_id,
                    force_generation=force_generation, origin=origin,
                )
                root_span.set_attribute("http.status_code", response.status_code)
                return response
            except RoutingError as e:
                root_span.set_attribute("http.status_code", e.status_code)
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

    async def _authenticate(self, request: Request, slug: str, server: ServerRecord) -> Optional[int]:
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
        # A SEPARATE check from key_permits_server above — server_scopes is an
        # operator-configured allowlist of slugs (may be None = "any server"), while this is
        # the project-agreement invariant that must hold regardless: a key minted in project A
        # must never reach a server in project B, even if server_scopes was (mis)configured to
        # name that server by slug. The two checks COMPOSE (both must pass), neither replaces
        # the other. Deliberately does NOT consult any notion of "global admin" — there is no
        # Principal/session on the data plane, only a key; the global-admin-superset rule is a
        # CONTROL-plane (session-based) concept in archon/project_rbac.py and must never leak
        # into this purely key-vs-server check. `server` is the SAME record _resolve_server
        # already fetched in handle() above — reused here rather than re-querying by slug,
        # since this method now runs strictly after that resolution on every real call path.
        #
        # Explicit `is None` check rather than relying on `!=` alone: `None != None` is False
        # in Python, so a bare `record.project_id != server.project_id` would treat a
        # project-less KEY and a project-less SERVER as matching. Currently unreachable
        # (0010_projects.sql backfills every existing row to 'default', and both
        # ApiKeyRepo.create/ServerRepo.create resolve an explicit project_id at write time —
        # see that migration's header), but this is the one project-boundary check in the
        # codebase that must fail closed on NULL the way archon/project_rbac.py's resolvers
        # all deliberately do, even if that invariant is ever violated by a future code path.
        if record.project_id is None or record.project_id != server.project_id:
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

            # A JSON-RPC batch (a top-level array — spec-legal) or a bare top-level JSON
            # string/number both parse successfully but aren't a dict, and body_json.get(...)
            # below would raise AttributeError. Treat anything non-dict the same as
            # unparseable — falls through to the passthrough/forward path below with
            # rpc_method="" untouched, rather than inventing new handling.
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

                # TWO forwarding paths fork below, decided by detect_client_generation
                # (presence of the Mcp-Method header; argus/generation.py):
                #
                #   GEN_2025 -> _forward (line ~900): raw byte proxy. Streams the upstream
                #       response back verbatim (aiter_raw + BackgroundTask(r.aclose)), strips
                #       hop-by-hop and credential headers, keeps no upstream session. Errors
                #       surface as RoutingError(502, ...).
                #   GEN_2026 -> _handle_bridged (line ~510): protocol translation. Buffers the
                #       upstream body, parses SSE, re-envelopes as plain JSON, injects the
                #       cached initialize handshake per server. Errors surface as
                #       BridgeError(502, ...).
                #
                # Only GEN_2026 clients reach bridge_call; only GEN_2025 clients reach _forward.
                # And only when a bridge is configured: if self._bridge is None the 2026 branch
                # is skipped and even a 2026 client falls through to the passthrough path below.
                # Do not merge the two paths — one proxies bytes, the other translates protocol
                # generations. Their shared enforcement prelude lives in _enforce (deduped in
                # issue #52); the paths legitimately diverge after it.
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
                    # Reuse the `params` local computed above (which already has the `or {}`
                    # guard) rather than re-reading body_json.get("params", {}) here — there
                    # is only one place the params-can-be-None case is guarded.
                    tool_name = params.get("name")
                    outcome = await self._enforce(
                        server, rpc_method, rpc_id, params, tool_name, api_key_id,
                        start, client_ip, origin=origin,
                    )
                    if outcome.blocked_response is not None:
                        return outcome.blocked_response

                    # DLP redact: the redacted body MUST be what actually leaves the process —
                    # re-serialize the JSON-RPC envelope with the redacted arguments substituted
                    # in and forward THAT, never the original body_bytes.
                    if (
                        outcome.decision is not None
                        and outcome.decision.dlp_redacted_arguments is not None
                    ):
                        rewritten = dict(body_json)
                        rewritten_params = dict(params)
                        rewritten_params["arguments"] = outcome.decision.dlp_redacted_arguments
                        rewritten["params"] = rewritten_params
                        body_bytes = json.dumps(rewritten).encode("utf-8")
                else:
                    await self._audit.log(
                        server_slug=server.slug, tool=body_name, decision="PASSTHROUGH",
                        endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                        latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
                    )

        try:
            resolved_auth_header = await self._resolve_credential(
                server, rpc_method=rpc_method, rpc_id=rpc_id, tool_name=tool_name,
                api_key_id=api_key_id, start=start, client_ip=client_ip, origin=origin,
            )
        except self._CredentialResolutionFailed as e:
            return e.response
        return await self._forward(request, server, path, body_bytes, resolved_auth_header)

    async def _evaluate_with_tracing(
        self, tool_name: str, arguments: dict, server: ServerRecord, policy: ServerPolicy,
    ):
        """Wraps argus.policy.evaluate with the policy.evaluate span, plus a nested dlp.scan
        span when (and only when) this server's policy actually has a DLP detector or custom
        pattern configured — matching evaluate()'s own "policy.dlp_detectors or
        policy.dlp_custom_patterns" gate (argus/policy.py), so a server with no DLP config never
        gets a dlp.scan span at all, same as it never pays for the scan itself.

        Attribute secrecy (non-negotiable): only server slug, tool name, decision,
        rule name, dlp_detector, dlp_action are ever set here — NEVER decision.matched (the
        DLP/param-rule matched VALUE) and NEVER arguments/args_summary. This mirrors exactly
        which Decision fields the DLP PR already deemed safe to audit/webhook (see
        db/models.py's Decision docstring) versus which it deliberately keeps off every
        observability surface.
        """
        dlp_configured = bool(policy.dlp_detectors or policy.dlp_custom_patterns)
        with self._tracing.span(
            "policy.evaluate",
            attributes={"acropolis.server_slug": server.slug, "acropolis.tool": tool_name},
        ) as policy_span:
            if dlp_configured:
                with self._tracing.span("dlp.scan", attributes={"acropolis.server_slug": server.slug}) as dlp_span:
                    decision = await evaluate(tool_name, arguments, server.name, policy)
                    dlp_span.set_attribute("acropolis.dlp_detector", decision.dlp_detector)
                    dlp_span.set_attribute("acropolis.dlp_action", decision.dlp_action)
            else:
                decision = await evaluate(tool_name, arguments, server.name, policy)
            policy_span.set_attribute("acropolis.decision", "BLOCKED" if decision.blocked else "ALLOWED")
            policy_span.set_attribute("acropolis.rule", decision.rule)
            return decision

    async def _enforce(
        self, server: ServerRecord, rpc_method: str, rpc_id: Any, params: dict,
        tool_name: Optional[str], api_key_id: Optional[int], start: float,
        client_ip: Optional[str], origin: Optional[str] = None, *, bridged: bool = False,
    ) -> _EnforcementOutcome:
        """The enforcement prelude shared by _process (passthrough) and _handle_bridged (issue
        #52): tool_name validation -> get_policy -> rate limits -> quota -> evaluate -> audit ->
        record_usage -> 403-if-blocked, in that order.

        The ordering is the non-negotiable one from 02-quotas-and-usage.md: quota is enforced
        after auth, after rate limiting, before policy evaluation — a quota-exceeded call is
        refused before evaluate() ever runs, so the upstream is never reached and no DLP/param
        rule work is wasted on a call that's about to be rejected anyway.

        The `bridged` flag threads to the audit rows (bridged=True marks the 2026-generation
        forwarding path). The two callers legitimately diverge AFTER this method — one forwards
        raw body bytes, the other translates protocol generations (see _forward vs bridge_call).
        """
        arguments = params.get("arguments") or {}
        audit_common = dict(
            server_slug=server.slug, endpoint="per-server", rpc_method=rpc_method,
            api_key_id=api_key_id, latency_ms=int((time.monotonic() - start) * 1000),
            client_ip=client_ip, origin=origin,
        )
        if bridged:
            audit_common["bridged"] = True

        if not tool_name or not isinstance(tool_name, str):
            await self._audit.log(
                tool="<missing>", decision="BLOCKED",
                reason="tools/call missing required 'name' field", status_code=400,
                **audit_common,
            )
            return _EnforcementOutcome(
                blocked_response=Response(
                    content=rpc_error(rpc_id, "tools/call missing required 'name' field"),
                    status_code=400, media_type="application/json",
                )
            )

        policy = await self._servers.get_policy(server.id)
        blocked_response = await self._check_rate_limits(
            server, policy, tool_name, api_key_id, rpc_id, start, client_ip
        )
        if blocked_response is not None:
            await self._record_usage(server, tool_name, api_key_id)
            return _EnforcementOutcome(blocked_response=blocked_response)

        quota_response = await self._check_quota(
            server, tool_name, api_key_id, rpc_id, start, client_ip
        )
        if quota_response is not None:
            await self._record_usage(server, tool_name, api_key_id)
            return _EnforcementOutcome(blocked_response=quota_response)

        decision = await self._evaluate_with_tracing(tool_name, arguments, server, policy)
        await self._audit.log(
            tool=tool_name,
            decision="BLOCKED" if decision.blocked else "ALLOWED",
            rule=decision.rule, matched=decision.matched,
            args_summary=decision.args_summary, reason=decision.reason,
            dlp_detector=decision.dlp_detector, dlp_action=decision.dlp_action,
            dlp_match_count=decision.dlp_match_count,
            **audit_common,
        )
        await self._record_usage(server, tool_name, api_key_id)

        if decision.blocked:
            return _EnforcementOutcome(
                blocked_response=Response(
                    content=rpc_error(
                        rpc_id, f"Blocked by acropolis: {decision.reason}",
                        data={"tool": tool_name, "rule": decision.rule, "matched": decision.matched},
                    ),
                    status_code=403, media_type="application/json",
                )
            )
        return _EnforcementOutcome(decision=decision, policy=policy)

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
        try:
            resolved_auth_header = await self._resolve_credential(
                server, rpc_method="tools/list", rpc_id=rpc_id, tool_name=None,
                api_key_id=api_key_id, start=start, client_ip=client_ip,
            )
        except self._CredentialResolutionFailed as e:
            return e.response
        policy = await self._servers.get_policy(server.id)
        tools = await self._tools_cache.get_filtered_tools(
            server.id, server.upstream_url, policy, upstream_auth_header=resolved_auth_header
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
            outcome = await self._enforce(
                server, rpc_method, rpc_id, params, tool_name, api_key_id,
                start, client_ip, origin=origin, bridged=True,
            )
            if outcome.blocked_response is not None:
                return outcome.blocked_response

            # DLP redact: the bridged path forwards `params` directly to
            # ProtocolBridge.bridge_call rather than raw body bytes, so redaction here means
            # substituting the redacted arguments into `params` before that call — no
            # body_override needed on this path. Deliberately placed AFTER the blocked-return
            # above (matching the non-bridged path's structure in _process) — a block never
            # carries dlp_redacted_arguments (see argus/policy.py's evaluate: the redact branch
            # always has blocked=False), so this ordering is not currently load-bearing for
            # correctness, but keeping "can this call still be blocked" resolved before "what
            # do we forward" is the safer invariant to read and to preserve under future
            # changes.
            if (
                outcome.decision is not None
                and outcome.decision.dlp_redacted_arguments is not None
            ):
                params = dict(params)
                params["arguments"] = outcome.decision.dlp_redacted_arguments
        else:
            await self._audit.log(
                server_slug=server.slug, tool=None, decision="PASSTHROUGH",
                endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                latency_ms=int((time.monotonic() - start) * 1000), bridged=True,
                client_ip=client_ip, origin=origin,
            )

        try:
            resolved_auth_header = await self._resolve_credential(
                server, rpc_method=rpc_method, rpc_id=rpc_id,
                tool_name=params.get("name") if rpc_method == "tools/call" else None,
                api_key_id=api_key_id, start=start, client_ip=client_ip, origin=origin, bridged=True,
            )
        except self._CredentialResolutionFailed as e:
            return e.response
        try:
            status, body = await self._bridge.bridge_call(
                server_id=server.id, upstream_url=server.upstream_url, rpc_method=rpc_method,
                rpc_id=rpc_id, params=params, meta=meta,
                upstream_auth_header=resolved_auth_header,
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
        # Re-register only when the spec string has changed: always calling register() would
        # reset consumed token state and defeat rate limiting entirely, while never
        # re-registering means an operator's limit change is ignored until restart.
        # RateLimiterRegistry.ensure_current is a no-op on the hot path once the bucket
        # matches the live policy.
        #
        # check_all() treats an unregistered key as "unlimited": only srv_key is registered
        # here, so it is the sole enforced limit. tool_key is checked but never registered —
        # per-tool limits are a tracked gap (tool_policies.rate_limit exists in the schema but
        # ServerPolicy doesn't surface it; see tool_key()'s docstring). Per-API-key limits
        # have no schema field at all; adding one is a real feature (migration + API + UI).
        #
        # `policy` is passed in by the caller, which fetched it once for this request — it is
        # not re-fetched here (two DB reads of request-scoped-immutable data per tools/call).
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

    async def _check_quota(
        self, server: ServerRecord, tool_name: str, api_key_id: Optional[int],
        rpc_id: Any, start: float, client_ip: Optional[str] = None,
    ) -> Optional[Response]:
        """Call-count budget over a billing period, enforced AFTER auth and AFTER the rate
        limiter, BEFORE policy evaluation — the non-negotiable ordering from
        02-quotas-and-usage.md. Rate limiting answers "how fast"; this answers "how much, over
        a period" — a different, complementary primitive (see argus/rate_limiter.py's own
        module-level framing), not a replacement for it.

        FAIL-OPEN, deliberately, and this is the one place in this feature that reverses every
        other enterprise item's fail-CLOSED default (see argus/pipeline.py's
        _resolve_credential for the fail-closed precedent this deliberately departs from, and
        docs/quotas.md for the full rationale written out). If self._usage is None (no
        UsageRepo wired — every pre-feature call site and test), if the key has no quota
        configured, or if the quota check ITSELF fails (a DB error reading total_since), the
        call proceeds exactly as if no quota existed. The only way this method blocks a call is
        a clean, successful read that shows the caller genuinely over budget.

        SECURITY-SCAN NOTE (accepted, not fixed): the read here (total_since) and the write in
        _record_usage happen in two separate steps with the actual upstream forward in between
        — a classic TOCTOU window. A burst of N concurrent requests against a key with
        remaining_budget < N can all read the SAME "still under budget" total before any of
        them increments, and all N get forwarded — a real overshoot past the configured limit
        under concurrency, not merely a theoretical one. This is accepted rather than
        engineered around (e.g. with a single atomic check-and-increment SQL statement) because
        it is consistent with, not a violation of, this feature's own documented threat model:
        quota is a soft budget control, and the fail-open rationale above already establishes
        that forwarding some calls over budget is a business cost, not a security exposure.
        RateLimiterRegistry's token bucket, by contrast, IS atomic per-check (see
        rate_limiter.py's asyncio.Lock) because bursts are exactly the failure mode a rate
        limiter exists to prevent — the two features have different jobs and different
        correctness requirements as a result. Worth being explicit about rather than silent.
        """
        if self._usage is None or api_key_id is None:
            return None
        try:
            key = await self._api_keys.get(api_key_id)
            if key is None or key.quota_calls is None or key.quota_period is None:
                return None
            since = period_start(key.quota_period).isoformat()
            used = await self._usage.total_since(api_key_id=api_key_id, since_iso=since)
        except Exception:
            # Fail open — see docstring. A DB hiccup on the quota check must never take down
            # the data plane; the worst case of forwarding anyway is one call slightly over a
            # soft budget, not a security exposure (contrast with _resolve_credential, where
            # failing open could leak a request to an upstream expecting credentials).
            logger.error(
                "quota check failed for api_key_id=%s server=%s tool=%s — failing open",
                api_key_id, server.slug, tool_name, exc_info=True,
            )
            return None

        if used < key.quota_calls:
            await self._maybe_fire_quota_webhook(key, used + 1, since)
            return None

        await self._audit.log(
            server_slug=server.slug, tool=tool_name, decision="BLOCKED",
            endpoint="per-server", rpc_method="tools/call", api_key_id=api_key_id,
            rule="quota", reason=f"Quota exceeded: {used}/{key.quota_calls} calls this {key.quota_period}",
            latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
        )
        return Response(
            content=rpc_error(
                rpc_id, "Quota exceeded", data={"tool": tool_name, "quota_period": key.quota_period},
            ),
            status_code=429, media_type="application/json",
        )

    async def _maybe_fire_quota_webhook(self, key, projected_used: int, since_iso: str) -> None:
        """Fires the `quota` webhook event at 80%/100% thresholds — see stoa/webhooks.py's
        VALID_EVENTS and docs/quotas.md. `projected_used` is `used + 1` (the count AFTER the
        call currently being evaluated completes), so the threshold fires on the call that
        actually crosses it rather than one call later. Debouncing per key+period (so a busy
        key doesn't spam one webhook per call once over a threshold) and race-safety under a
        concurrent burst are entirely WebhookDispatcher's responsibility (see its
        fire_quota_threshold method) — this call site only computes WHETHER a threshold was
        newly crossed by this specific call, a pure function of (previous count, new count,
        quota), and hands off the decision, not the debounce state.
        """
        if self._webhooks is None or key.quota_calls is None:
            return
        # Security-scan check (division-by-zero on key.quota_calls): the only caller of this
        # method is _check_quota's `if used < key.quota_calls: await
        # self._maybe_fire_quota_webhook(...)` branch — if quota_calls were ever <= 0, that
        # condition could only be true for a negative `used`, which total_since's
        # COALESCE(SUM(calls), 0) can never produce. So this method is unreachable whenever
        # quota_calls <= 0, and the division below is safe by that construction, not by luck.
        # archon/schemas.py's _validate_quota_pairing is the actual enforcement point (rejects
        # quota_calls <= 0 at the API boundary) — this comment documents why a hypothetical
        # bypass of that layer (a direct ApiKeyRepo.create/set_quota call, which has no such
        # guard) still wouldn't crash here, not a claim that this method re-validates anything.
        prior_pct = ((projected_used - 1) / key.quota_calls) * 100
        new_pct = (projected_used / key.quota_calls) * 100
        for threshold in (100, 80):
            if prior_pct < threshold <= new_pct:
                await self._webhooks.fire_quota_threshold(
                    key_prefix=key.key_prefix, key_name=key.name, threshold=threshold,
                    period=key.quota_period, period_start_iso=since_iso,
                )
                break  # only the highest newly-crossed threshold fires for a single call

    async def _record_usage(
        self, server: ServerRecord, tool_name: Optional[str], api_key_id: Optional[int],
    ) -> None:
        """Increments the usage rollup for this call, in the SAME code path that emits the
        tools/call audit event — called immediately alongside (never instead of)
        self._audit.log for every tools/call decision (rate-limit block, quota block, policy
        allow/deny alike), so a rollup total can never drift from a count of the audit rows
        for the same window. See tests/integration/test_quotas.py's
        TestRollupsMatchAuditRows for the test that proves this by direct comparison, and
        AuditLogger.log's own docstring for the parallel "one write path" discipline this
        mirrors.

        Fails open exactly like _check_quota, for the same reason: a rollup WRITE failure is a
        cost-visibility gap, not a security boundary, and must never turn into a 500 on an
        otherwise-successful call.
        """
        if self._usage is None:
            return
        try:
            await self._usage.increment(
                ts_iso=utcnow(), api_key_id=api_key_id, server_id=server.id, tool=tool_name,
                # Attribute the rollup to the SERVER's project (a server belongs to exactly
                # one project; the calling key's project is checked for AGREEMENT with this in
                # _authenticate below, not used as the attribution source here).
                project_id=server.project_id,
            )
        except Exception:
            logger.error(
                "usage rollup write failed for api_key_id=%s server=%s tool=%s",
                api_key_id, server.slug, tool_name, exc_info=True,
            )

    class _CredentialResolutionFailed(Exception):
        """Internal-only signal carrying the already-built error Response — see
        _resolve_credential's docstring on why this doesn't reuse RoutingError (which handle()'s
        top-level except block would audit-log a SECOND time)."""

        def __init__(self, response: Response):
            self.response = response

    async def _resolve_credential(
        self, server: ServerRecord, *, rpc_method: str, rpc_id: Any, tool_name: Optional[str],
        api_key_id: Optional[int], start: float, client_ip: Optional[str],
        origin: Optional[str] = None, bridged: bool = False,
    ) -> Optional[str]:
        """Resolves `server.upstream_auth_header` (a literal OR a reference) to the plaintext
        credential that must be sent to the upstream, via the configured SecretProvider.

        Non-negotiable: failure here must be an explicit ERROR, NEVER a silent fall-through to
        forwarding without the credential — that would risk leaking a request to an upstream
        that expects auth, or turn a Vault blip into a confusing unauthenticated-401 storm.
        Every call site (bridged tools/call, raw passthrough forward, tools/list) routes
        through this one method so that guarantee can't drift between them; see
        tests/integration/test_secret_resolution_failure.py's regression test proving this.

        Raises _CredentialResolutionFailed (never RoutingError) on failure, after logging the
        ERROR audit event itself — mirroring how _check_header_consistency's mismatch case
        logs-then-returns-a-Response directly rather than raising, so the call site can simply
        `return e.response` without handle()'s top-level `except RoutingError` double-logging
        the same failure.
        """
        if server.upstream_auth_header is None:
            return None

        # Only span this when upstream_auth_header is actually a REFERENCE (vault://...,
        # enc:v1:...) that requires a real resolution round-trip. For the "local"/literal case,
        # self._secrets.resolve() is a same-process, zero-I/O pass-through (see
        # archon/secrets/local.py) and a span there would just be noise around a no-op —
        # manual spans, not blanket auto-instrumentation.
        from archon.secrets import is_reference

        traced = is_reference(server.upstream_auth_header)

        # SECURITY: e.reason (built here, inside the try, never inside the span's own except
        # clause) may echo back attacker- or operator-controlled shape (a malformed ref, an HTTP
        # status code) but must NEVER contain the resolved plaintext — SecretResolutionError's
        # own contract (see archon/secrets/__init__.py) is that its message is built only from
        # the reference and a static reason, so this is safe to both audit-log and, when
        # `traced`, let the span() context manager record as an exception. `_CredentialResolutionFailed`
        # is deliberately raised OUTSIDE the `with span:` block below (not from within the except
        # clause) — it's an internal control-flow signal carrying an already-built Response, not
        # a real failure, and recording it as a span exception would be noise, not signal.
        try:
            if traced:
                with self._tracing.span(
                    "secrets.resolve", attributes={"acropolis.server_slug": server.slug},
                ):
                    return await self._secrets.resolve(server.upstream_auth_header)
            return await self._secrets.resolve(server.upstream_auth_header)
        except SecretResolutionError as e:
            reason = f"secret resolution failed: {e.reason}"
            await self._audit.log(
                server_slug=server.slug, tool=tool_name, decision="ERROR",
                endpoint="per-server", rpc_method=rpc_method, api_key_id=api_key_id,
                reason=reason, status_code=502,
                latency_ms=int((time.monotonic() - start) * 1000), client_ip=client_ip,
                origin=origin, bridged=bridged,
            )
            raise self._CredentialResolutionFailed(
                Response(content=rpc_error(rpc_id, reason), status_code=502, media_type="application/json")
            )

    async def _forward(
        self, request: Request, server: ServerRecord, path: str, body_bytes: bytes,
        resolved_auth_header: Optional[str] = None,
    ) -> Response:
        # GEN_2025 passthrough path (see the fork comment in _process): raw byte proxy to the
        # upstream. The bridged counterpart is ProtocolBridge.bridge_call (argus/bridge.py).
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

        # If this server has a configured upstream credential, inject it as the Authorization
        # header sent to the upstream. Appended AFTER strip_hop_by_hop, and as a plain list
        # append rather than a header-merge, so it always wins even though the client's own
        # Authorization was already stripped — there should never be two.
        if resolved_auth_header:
            forward_headers = [
                (k, v) for k, v in forward_headers if k.lower() != b"authorization"
            ]
            forward_headers.append((b"authorization", resolved_auth_header.encode()))

        # traceparent/tracestate are added here — deliberately, inside upstream.forward's
        # span, and ONLY here. argus/headers.py's strip_hop_by_hop already removed any
        # traceparent/tracestate the CLIENT sent (see that module's module-level comment on
        # why: an unmediated client-supplied traceparent passing straight through was never a
        # governed feature, just an accident of a denylist). What crosses the wire now is
        # exclusively the gateway's own span context, correctly parent-chained under whatever
        # inbound traceparent the root `request` span was told to honor (see Pipeline.handle).
        # inject_headers() returns {} when tracing is inactive, making this an unconditional,
        # branch-free no-op on the disabled path — see tests/integration/test_otel_propagation.py.
        with self._tracing.span(
            "upstream.forward", attributes={"acropolis.server_slug": server.slug},
        ) as forward_span:
            trace_headers = self._tracing.inject_headers()
            if trace_headers:
                forward_headers = forward_headers + [
                    (k.encode(), v.encode()) for k, v in trace_headers.items()
                ]

            upstream_req = self._client.build_request(
                method=request.method, url=upstream_url, content=body_bytes, headers=forward_headers,
            )
            # self._client.send() must convert transport errors (refused connection, DNS
            # failure, TLS error) into a RoutingError that gets audited — this is the MOST
            # LIKELY real-world event in a self-hosted deployment (an MCP server container
            # restarting), and an unhandled exception here would escape to Starlette as a bare
            # 500 with a non-JSON-RPC body and nothing in the audit trail. The bridged path
            # (argus/bridge.py) handles the same case; matched here.
            try:
                r = await self._client.send(upstream_req, stream=True)
            except httpx.HTTPError as e:
                raise RoutingError(502, rpc_error(None, f"upstream request failed: {e}"))
            forward_span.set_attribute("http.status_code", r.status_code)

        return StreamingResponse(
            r.aiter_raw(), status_code=r.status_code,
            headers=filter_response_headers(r.headers), background=BackgroundTask(r.aclose),
        )
