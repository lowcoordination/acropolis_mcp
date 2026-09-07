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

from archon.auth.apikeys import ApiKeyService, key_scope_violation
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
from argus.metering import Metering
from argus.policy import Decision, evaluate
from argus.rate_limiter import RateLimiterRegistry
from argus.toolslist import ToolsCache
from argus.tracing import TracingManager, _DisabledTracingManager
from db.models import ApiKeyRecord, ServerPolicy, ServerRecord
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
        # NOTE: metering (rate limits, quota, usage rollups) is deliberately NOT assigned here —
        # see the `_metering` property below for why it is derived on access instead.

    @property
    def _metering(self) -> Metering:
        """Metering built lazily from the collaborators this Pipeline already holds, and
        rebuilt whenever they are replaced.

        Composed rather than injected so that every existing Pipeline(...) call site — app.py,
        the benches, and a large number of tests — keeps its current signature.
        argus/policy_api.py builds its own Metering over the same collaborators; the rules live
        in one place (argus/metering.py), the refusal shapes do not.

        Deliberately not assigned in __init__: tests construct a Pipeline via
        `Pipeline.__new__(Pipeline)` and set only the attributes the path under test needs
        (see tests/unit/test_rate_limiter.py), and code elsewhere may swap self._rate_limiter
        to point at a different backend. Caching a Metering at construction time would make
        those callers exercise a stale backend while appearing to work — the failure mode this
        property exists to prevent. Constructing one is three attribute reads, so the hot path
        pays nothing meaningful for the guarantee.
        """
        cached = getattr(self, "_metering_cache", None)
        deps = (self._rate_limiter, getattr(self, "_usage", None), getattr(self, "_webhooks", None))
        if cached is None or cached[0] != deps:
            metering = Metering(*deps)
            self._metering_cache = (deps, metering)
            return metering
        return cached[1]

    @property
    def tools_cache(self) -> Optional[ToolsCache]:
        return self._tools_cache

    async def handle(
        self, request: Request, slug: str, path: str, body_override: Optional[bytes] = None,
        force_generation: Optional[ClientGeneration] = None,
        skip_api_key_auth: bool = False, origin: Optional[str] = None,
        pre_authenticated: Optional[ApiKeyRecord] = None,
        resolved_server: Optional[ServerRecord] = None,
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

        `pre_authenticated` + `resolved_server` exist for the aggregate re-dispatch (#111):
        the aggregate endpoint has ALREADY verified the bearer key (hash-verify + enabled
        check) and already fetched the target server before it routes a namespaced tools/call
        here, and re-running either is pure duplicate DB work inside the same request. The
        record/server are handed in so this method skips those two reads — but the two SCOPE
        checks (`key_permits_server` + the project-agreement invariant) are still enforced
        here, because they are pure Python over the record and server and `authenticate_no_scope`
        deliberately skipped them at the aggregate layer. This is NOT the `skip_api_key_auth`
        path: that one nulls the key entirely (control-plane Try-it only, no quota attribution),
        while this one threads the verified record through so rate limits, quota, policy, and
        usage attribution all apply identically to a direct per-server call.

        `skip_api_key_auth` and `pre_authenticated` are MUTUALLY EXCLUSIVE auth modes — one
        means "no key at all" (control-plane Try-it), the other means "this key was already
        verified, enforce it." Passing both is a caller bug, not a state this method can
        meaningfully resolve; it is asserted below rather than silently letting one win.
        """
        # Precondition on the caller (the aggregate pipeline is the only one that passes these):
        # the two bypass modes are contradictory, and silently picking a precedence here would
        # either drop an authenticated key or skip the scope checks on a control-plane call.
        assert not (skip_api_key_auth and pre_authenticated is not None), (
            "Pipeline.handle: skip_api_key_auth (control-plane Try-it, no key) and "
            "pre_authenticated (aggregate re-dispatch, verified key) are mutually exclusive"
        )
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
                if resolved_server is not None:
                    server = resolved_server
                else:
                    server = await self._resolve_server(slug)
                if skip_api_key_auth:
                    key_record: Optional[ApiKeyRecord] = None
                elif pre_authenticated is not None:
                    # Aggregate re-dispatch — the key was verified once already this request;
                    # only the per-server scope checks still need to run (see docstring).
                    self._check_key_scope(pre_authenticated, slug, server)
                    key_record = pre_authenticated
                else:
                    key_record = await self._authenticate(request, slug, server)
                api_key_id = key_record.id if key_record is not None else None
                body_bytes = (
                    self._guard_body_size(body_override) if body_override is not None
                    else await self._read_body_guarded(request)
                )
                response = await self._process(
                    request, server, path, body_bytes, key_record,
                    force_generation=force_generation, origin=origin,
                )
                root_span.set_attribute("http.status_code", response.status_code)
                return response
            except RoutingError as e:
                root_span.set_attribute("http.status_code", e.status_code)
                return await self._error(
                    server_slug=slug, tool=None, status=e.status_code,
                    content=e.body, media_type=e.media_type,
                    reason=e.body[:200], start=start,
                    client_ip=_client_ip(request), origin=origin,
                    endpoint="per-server",
                )

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

    async def authenticate_no_scope(self, request: Request) -> Optional[ApiKeyRecord]:
        """Auth check with no per-server scope requirement — for entry points that aren't
        about one specific server (the aggregate endpoint's tools/list and server/discover,
        which span every registered server). Still fully respects auth_mode and requires a
        valid, enabled key when auth_mode is 'keyed'; just skips the scope check that
        _authenticate does for a single-server request.

        Returns the verified ApiKeyRecord (or None in open auth mode) so callers can reuse
        it instead of re-fetching the row by id (#111) — the aggregate passes it on to
        _caller_project_id and, for tools/call, back into Pipeline.handle as
        pre_authenticated."""
        if await self._current_auth_mode() == "open":
            return None
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise RoutingError(401, rpc_error(None, "missing bearer token"))
        plaintext = auth_header[len("Bearer "):]
        record = await self._api_keys.verify(plaintext)
        if record is None:
            raise RoutingError(401, rpc_error(None, "invalid or disabled api key"))
        return record

    async def _authenticate(
        self, request: Request, slug: str, server: ServerRecord,
    ) -> Optional[ApiKeyRecord]:
        if await self._current_auth_mode() == "open":
            return None

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise RoutingError(401, rpc_error(None, "missing bearer token"))
        plaintext = auth_header[len("Bearer "):]
        record = await self._api_keys.verify(plaintext)
        if record is None:
            raise RoutingError(401, rpc_error(None, "invalid or disabled api key"))
        # The two per-server scope checks live in _check_key_scope, shared verbatim with the
        # aggregate re-dispatch path — see that method's docstring for the full reasoning on
        # why each check exists and why both must pass.
        self._check_key_scope(record, slug, server)
        return record

    def _check_key_scope(self, record: ApiKeyRecord, slug: str, server: ServerRecord) -> None:
        """Data-plane raiser for the shared scope predicate. The checks and the full reasoning
        for each of them live in archon/auth/apikeys.py's key_scope_violation, which
        argus/policy_api.py also consumes with a different error shape; this method contributes
        only the JSON-RPC RoutingError that the data plane needs."""
        violation = key_scope_violation(self._api_keys, record, slug, server)
        if violation is not None:
            raise RoutingError(403, rpc_error(None, violation))

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
        key_record: Optional[ApiKeyRecord],
        force_generation: Optional[ClientGeneration] = None,
        origin: Optional[str] = None,
    ) -> Response:
        start = time.monotonic()
        # api_key_id is derived once here for the audit/usage call sites; the record itself
        # rides along for _enforce/_check_quota so the row is never re-fetched by id within
        # the same request (#111).
        api_key_id = key_record.id if key_record is not None else None
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
                    mismatch_response = await self._check_header_consistency(
                        request, rpc_method, body_name, server=server,
                        api_key_id=api_key_id, start=start, client_ip=client_ip,
                    )
                    if mismatch_response is not None:
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
                        key_record, start, client_ip, origin=origin,
                    )

                if rpc_method == "tools/call":
                    # Reuse the `params` local computed above (which already has the `or {}`
                    # guard) rather than re-reading body_json.get("params", {}) here — there
                    # is only one place the params-can-be-None case is guarded.
                    tool_name = params.get("name")
                    outcome = await self._enforce(
                        server, rpc_method, rpc_id, params, tool_name, key_record,
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
        tool_name: Optional[str], key_record: Optional[ApiKeyRecord], start: float,
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
        # latency_ms is NOT included here on purpose (issue #99): this dict is built once, at
        # the top of enforcement, but the ALLOWED audit row below is logged after rate-limit,
        # quota, and policy evaluation have all run. Folding a value computed here into that
        # template freezes latency_ms at ~0 for every forwarded call — the elapsed time at this
        # point is sub-millisecond, so int(...) truncates it away. Each log call below computes
        # latency_ms fresh at its own call site instead, matching how _refuse/_error already do
        # it.
        api_key_id = key_record.id if key_record is not None else None
        audit_common = dict(
            server_slug=server.slug, endpoint="per-server", rpc_method=rpc_method,
            api_key_id=api_key_id, client_ip=client_ip, origin=origin,
        )
        if bridged:
            audit_common["bridged"] = True

        if not tool_name or not isinstance(tool_name, str):
            return _EnforcementOutcome(
                blocked_response=await self._refuse(
                    server_slug=server.slug, tool="<missing>", rpc_id=rpc_id,
                    message="tools/call missing required 'name' field", status=400,
                    rule=None, api_key_id=api_key_id, start=start, client_ip=client_ip,
                    bridged=bridged, origin=origin,
                    endpoint="per-server", rpc_method=rpc_method, status_code=400,
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
            server, tool_name, key_record, rpc_id, start, client_ip
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
            latency_ms=int((time.monotonic() - start) * 1000),
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

    async def _refuse(
        self, *, server_slug, tool, rpc_id, message, status, rule, api_key_id,
        start, client_ip, data=None, reason=None, bridged=False, origin=None,
        **audit_extra,
    ) -> Response:
        """Log a BLOCKED audit row and build the matching JSON-RPC error response (issue #53).

        Pairing refusal-and-audit in one call makes "blocked without an audit row"
        unrepresentable — the compliance-relevant failure for a gateway whose audit trail is a
        product feature. `reason` defaults to `message`; pass it explicitly where the audit
        reason differs from the client-facing message (e.g. the policy-block site logs
        decision.reason but serves "Blocked by acropolis: {reason}"). Pass `status_code` via
        audit_extra when the audit row should carry one (only the missing-name site does today).
        """
        await self._audit.log(
            server_slug=server_slug, tool=tool, decision="BLOCKED", rule=rule,
            reason=reason if reason is not None else message,
            api_key_id=api_key_id, client_ip=client_ip,
            latency_ms=int((time.monotonic() - start) * 1000),
            bridged=bridged, origin=origin, **audit_extra,
        )
        return Response(
            content=rpc_error(rpc_id, message, data=data),
            status_code=status, media_type="application/json",
        )

    async def _error(
        self, *, server_slug, tool, status, content, reason, api_key_id=None,
        start, client_ip, media_type="application/json", bridged=False, origin=None,
        **audit_extra,
    ) -> Response:
        """Log an ERROR audit row and serve the given JSON-RPC error body (issue #53).

        `content` is the exact body to serve, already rpc_error()-built at the call site —
        several ERROR paths serve a body that was constructed elsewhere (RoutingError's or
        BridgeError's); `reason` is what the audit row records and may differ from the
        client-facing message. ERROR audit rows always carry status_code, so unlike _refuse
        this helper passes `status` through to the audit itself.
        """
        await self._audit.log(
            server_slug=server_slug, tool=tool, decision="ERROR",
            reason=reason, status_code=status,
            api_key_id=api_key_id, client_ip=client_ip,
            latency_ms=int((time.monotonic() - start) * 1000),
            bridged=bridged, origin=origin, **audit_extra,
        )
        return Response(content=content, status_code=status, media_type=media_type)

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
        meta: Optional[dict], key_record: Optional[ApiKeyRecord], start: float,
        client_ip: Optional[str] = None, origin: Optional[str] = None,
    ) -> Response:
        api_key_id = key_record.id if key_record is not None else None
        if rpc_method == "tools/call":
            tool_name = params.get("name")
            outcome = await self._enforce(
                server, rpc_method, rpc_id, params, tool_name, key_record,
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
            return await self._error(
                server_slug=server.slug, tool=None, status=e.status_code,
                content=e.body, reason=e.body[:200],
                api_key_id=api_key_id, start=start, client_ip=client_ip,
                bridged=True, origin=origin,
                endpoint="per-server", rpc_method=rpc_method,
            )

        return Response(content=json.dumps(body), status_code=status, media_type="application/json")

    async def _check_header_consistency(
        self, request: Request, rpc_method: str, body_name: Optional[str],
        *, server: ServerRecord, api_key_id: Optional[int], start: float,
        client_ip: Optional[str],
    ) -> Optional[Response]:
        mcp_method_header = request.headers.get(MCP_METHOD_HEADER)
        mcp_name_header = request.headers.get(MCP_NAME_HEADER)
        if not header_matches_body(mcp_method_header, mcp_name_header, rpc_method, body_name):
            return await self._error(
                server_slug=server.slug, tool=body_name, status=400,
                content=rpc_error(
                    None, "Mcp-Method/Mcp-Name header does not match request body",
                    code=HEADER_MISMATCH_ERROR,
                ),
                reason="Mcp-Method/Mcp-Name header mismatch",
                api_key_id=api_key_id, start=start, client_ip=client_ip,
                endpoint="per-server", rpc_method=rpc_method,
            )
        return None

    async def _check_rate_limits(
        self, server: ServerRecord, policy: ServerPolicy, tool_name: str,
        api_key_id: Optional[int], rpc_id: Any, start: float,
        client_ip: Optional[str] = None,
    ) -> Optional[Response]:
        """Data-plane adapter over Metering.check_rate_limits: turns a shape-agnostic verdict
        into this surface's JSON-RPC refusal plus its BLOCKED audit row. The rules — including
        the fail-CLOSED backend-unavailable branch — live in argus/metering.py."""
        verdict = await self._metering.check_rate_limits(server, policy, tool_name)
        if verdict.allowed:
            return None
        return await self._refuse(
            server_slug=server.slug, tool=tool_name, rpc_id=rpc_id,
            message=verdict.message, status=verdict.status, rule=verdict.rule,
            reason=verdict.reason,
            api_key_id=api_key_id, start=start, client_ip=client_ip,
            endpoint="per-server", rpc_method="tools/call",
            data=verdict.data,
        )

    async def _check_quota(
        self, server: ServerRecord, tool_name: str, key_record: Optional[ApiKeyRecord],
        rpc_id: Any, start: float, client_ip: Optional[str] = None,
    ) -> Optional[Response]:
        """Data-plane adapter over Metering.check_quota: turns a shape-agnostic verdict into
        this surface's JSON-RPC refusal plus its BLOCKED audit row. The fail-OPEN posture and
        the 80%/100% threshold webhook live in argus/metering.py."""
        verdict = await self._metering.check_quota(server, tool_name, key_record)
        if verdict.allowed:
            return None
        return await self._refuse(
            server_slug=server.slug, tool=tool_name, rpc_id=rpc_id,
            message=verdict.message, status=verdict.status, rule=verdict.rule,
            reason=verdict.reason,
            api_key_id=key_record.id if key_record is not None else None,
            start=start, client_ip=client_ip,
            endpoint="per-server", rpc_method="tools/call",
            data=verdict.data,
        )

    async def _record_usage(
        self, server: ServerRecord, tool_name: Optional[str], api_key_id: Optional[int],
    ) -> None:
        """Delegates to Metering.record_usage — see there for the "never drifts from the audit
        rows" discipline and the fail-open rationale."""
        await self._metering.record_usage(server, tool_name, api_key_id)

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
            raise self._CredentialResolutionFailed(
                await self._error(
                    server_slug=server.slug, tool=tool_name, status=502,
                    content=rpc_error(rpc_id, reason),
                    reason=reason, api_key_id=api_key_id, start=start,
                    client_ip=client_ip, origin=origin, bridged=bridged,
                    endpoint="per-server", rpc_method=rpc_method,
                )
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
