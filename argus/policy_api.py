"""POST /api/v1/policy/evaluate — evaluate a proposed tool call, forward nothing (#122).

A decision oracle for callers that are not MCP clients. A local agent guard (issue #124) asks
"may I run this bash command?" and gets a Decision back; nothing is sent upstream, no tools/call
is made, and the answer is recorded in the same audit trail as every gateway decision.

Three properties of this module are load-bearing and must survive future edits:

1. NO UPSTREAM CONTACT, guaranteed structurally. This module does not import Pipeline and holds
   no reference to one — the metering rules it shares with the data plane live in
   argus/metering.py precisely so this file never needs the object that knows how to forward.
   `grep -E 'Pipeline|_forward|bridge_call|upstream' argus/policy_api.py` returning nothing is a
   maintained invariant, not a coincidence.

2. AUTHENTICATION IS UNCONDITIONAL. The endpoint requires a valid, enabled API key on every
   request. Neither of the gateway's two "open" modes reaches it:

     * auth_mode == "open" (the data plane's DB-backed setting, Pipeline._current_auth_mode)
       governs /mcp/* only. This module never calls it.
     * require_admin's pre-first-run window (archon/admin_auth.py — no admin_password_hash and
       no admin_token yields a legacy admin Principal) governs /api/v1's session routes. This
       module never calls require_admin either.

   That divergence from "same API-key auth as /mcp/*" is deliberate. auth_mode: open exists for
   single-tenant deployments where the PROXY is trusted-by-network; this endpoint is a policy
   ORACLE, and unauthenticated access to it lets anyone binary-search the operator's
   block_patterns — which encode which paths, hosts, and credentials matter — at forkserver cost
   per probe. That is a strictly worse exposure than an open proxy, so it does not inherit the
   proxy's relaxation. See docs/authentication.md.

3. THE CALLER MUST FAIL CLOSED. Any response that is not 200 with a well-formed body — 401, 403,
   404, 413, 422, 429, 5xx, a timeout, a connection refusal, an unparseable body — must be
   treated by the caller as blocked: true. Only an explicit 200 {"blocked": false} permits the
   call. A guard that treats an unreachable gateway as permission has no security value: the
   cheapest way to defeat it is to make the gateway unreachable. This is a deliberate
   availability trade — gateway down means the agent cannot run local commands. See
   docs/policy-cookbook.md.

Why this lives outside archon/api.py: that router's defining invariant is that every route
carries an explicit `Depends(require_role(...))` and `grep require_role archon/api.py`
enumerates them (see its build function's comment). This route deliberately uses a different
credential, and adding the one unannotated route to that file would poison a property the
codebase relies on to spot an unprotected endpoint.
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from archon.auth.apikeys import ApiKeyService, key_scope_violation
from archon.schemas import PolicyEvaluateRequest, PolicyEvaluateResponse
from archon.settings import Settings
from argus.audit import AuditLogger
from argus.metering import Metering
from argus.policy import evaluate
from db.models import ApiKeyRecord
from db.repo import ServerNotFoundError, ServerRepo

logger = logging.getLogger(__name__)

# The audit `origin` for a local evaluation. Non-NULL, so AuditRepo.count_since's hardcoded
# `origin IS NULL` filter excludes these rows from /stats automatically — an evaluation is not
# traffic and must not move the dashboard's allowed/blocked counters, the same reasoning
# 0004_audit_origin.sql gives for origin='test'.
#
# #123 will replace this with a structured scheme carrying harness and host ("which machine,
# which agent"). It is a single constant, and there is deliberately no CHECK constraint on the
# column, so that issue has exactly one place to change. Origin values are NOT a stable API
# contract.
EVALUATION_ORIGIN = "local-eval"

# The audit `endpoint` for this surface — a third value beside the data plane's "per-server"
# and "aggregate". Plain TEXT, no constraint, no migration needed.
EVALUATION_ENDPOINT = "policy-evaluate"

# The proposed method being evaluated. Recording the real method (rather than something like
# "policy/evaluate") keeps the Audit UI's method column meaningful and lets an operator
# correlate an evaluation with the real call that followed it; `endpoint` is what distinguishes
# the two.
EVALUATION_RPC_METHOD = "tools/call"


def build_policy_evaluation_router(
    server_repo: ServerRepo,
    api_keys: ApiKeyService,
    audit: AuditLogger,
    metering: Metering,
    settings: Settings,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    async def verify_evaluation_key(request: Request) -> ApiKeyRecord:
        """API-key auth for this endpoint, with a Content-Length guard ahead of body parsing.

        Returns the verified ApiKeyRecord — never None, and never consults auth_mode (see the
        module docstring). The per-server scope checks are NOT done here: the server slug
        arrives in the request BODY, not the path, so they run in the handler once the body is
        parsed. This mirrors how archon/api.py's create_server handles a body-named project.

        The size guard is advisory, and deliberately described as such: FastAPI has already
        buffered the body by the time a handler runs, so the data plane's _read_body_guarded
        cannot apply here, and a request that lies about Content-Length or uses chunked encoding
        defeats this check. The real backstop for an oversized body on a FastAPI route is the
        ASGI server's own limit — a deployment concern, see docs/tls-and-reverse-proxy.md. It
        reuses settings.max_body_bytes so an operator tuning that knob gets consistent behaviour
        across both surfaces.
        """
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                raise HTTPException(status_code=400, detail="invalid content-length header")
            if declared > settings.max_body_bytes:
                raise HTTPException(status_code=413, detail="payload too large")

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        record = await api_keys.verify(auth_header[len("Bearer "):])
        if record is None:
            raise HTTPException(status_code=401, detail="invalid or disabled api key")
        return record

    @router.post("/policy/evaluate", response_model=PolicyEvaluateResponse)
    async def evaluate_policy(
        body: PolicyEvaluateRequest,
        request: Request,
        key_record: ApiKeyRecord = Depends(verify_evaluation_key),
    ) -> PolicyEvaluateResponse:
        """Evaluate a proposed tool call against a server's policy without executing it.

        The ordering below mirrors Pipeline._enforce's non-negotiable sequence (resolve ->
        scope -> policy -> rate limit -> quota -> evaluate -> audit -> record usage) from
        02-quotas-and-usage.md, with one deliberate divergence at the end: a blocked decision
        returns 200 {"blocked": true} rather than a 403. This endpoint's job is to REPORT a
        decision, not to enforce one — the caller is the enforcement point, and a non-2xx is
        reserved for "we could not give you an answer", which the caller must treat as a block.

        401/403/404 are deliberately NOT audited. The data plane does not audit failed
        authentication either, and auditing them here would let an unauthenticated caller write
        unbounded rows into audit_events — a log-flooding DoS requiring no credential. Nothing
        is lost: a request that never reached the policy engine is not an evaluation and cannot
        probe policy.
        """
        start = time.monotonic()
        client_ip = request.client.host if request.client else None

        try:
            server = await server_repo.get(body.server)
        except ServerNotFoundError:
            raise HTTPException(status_code=404, detail="server not found")
        # A disabled server 404s exactly as it does on the data plane (Pipeline._resolve_server):
        # evaluating against the policy of a server that cannot be called would be a misleading
        # answer.
        if not server.enabled:
            raise HTTPException(status_code=404, detail="server not found")

        # Project scoping, resolved entirely from the KEY — no global-admin superset, matching
        # the data plane and AggregatePipeline._caller_project_id. This is why the endpoint
        # authenticates with an API key: the caller's project is a property of the key row, not
        # of whatever role its owner's session happens to hold.
        #
        # Note the ordering: an unknown slug 404s before this check, so a valid key can learn
        # whether a slug exists outside its project. That matches _project_id_from_server_slug
        # and the data plane's _resolve_server exactly; a third convention here would be worse
        # than the disclosure.
        violation = key_scope_violation(api_keys, key_record, body.server, server)
        if violation is not None:
            raise HTTPException(status_code=403, detail=violation)

        policy = await server_repo.get_policy(server.id)

        audit_common = dict(
            server_slug=server.slug,
            endpoint=EVALUATION_ENDPOINT,
            rpc_method=EVALUATION_RPC_METHOD,
            api_key_id=key_record.id,
            client_ip=client_ip,
            origin=EVALUATION_ORIGIN,
            tool=body.tool_name,
        )

        # Rate limit, then quota — the same order and the same buckets as the data plane, so an
        # evaluation cannot be used to double an effective budget by alternating surfaces. Both
        # refusals still produce a BLOCKED audit row: "blocked without an audit row" must stay
        # unrepresentable on this surface too.
        for verdict in (
            await metering.check_rate_limits(server, policy, body.tool_name),
            await metering.check_quota(server, body.tool_name, key_record),
        ):
            if not verdict.allowed:
                await audit.log(
                    decision="BLOCKED", rule=verdict.rule,
                    reason=verdict.reason or verdict.message,
                    status_code=verdict.status,
                    latency_ms=int((time.monotonic() - start) * 1000),
                    **audit_common,
                )
                await metering.record_usage(server, body.tool_name, key_record.id)
                raise HTTPException(status_code=verdict.status, detail=verdict.message)

        decision = await evaluate(body.tool_name, body.arguments, server.name, policy)

        await audit.log(
            decision="BLOCKED" if decision.blocked else "ALLOWED",
            rule=decision.rule, matched=decision.matched,
            args_summary=decision.args_summary, reason=decision.reason,
            dlp_detector=decision.dlp_detector, dlp_action=decision.dlp_action,
            dlp_match_count=decision.dlp_match_count,
            status_code=200,
            latency_ms=int((time.monotonic() - start) * 1000),
            **audit_common,
        )
        await metering.record_usage(server, body.tool_name, key_record.id)

        # Constructed field by field, never from asdict(decision) — see
        # PolicyEvaluateResponse's docstring. dlp_redacted_arguments must not reach a response.
        return PolicyEvaluateResponse(
            blocked=decision.blocked,
            reason=decision.reason,
            rule=decision.rule,
            matched=decision.matched,
        )

    return router
