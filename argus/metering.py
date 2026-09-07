"""Rate-limit and quota enforcement, decoupled from any particular response shape.

Extracted from argus/pipeline.py so two surfaces can share one implementation of the metering
rules without sharing a response format:

  * the data plane (/mcp/*), which refuses with a JSON-RPC error body, and
  * POST /api/v1/policy/evaluate (argus/policy_api.py), which answers with REST JSON.

The split is deliberate about WHERE the shape lives. These methods return a _MeteringVerdict —
a plain description of "allowed, or refused for this reason" — and never build a Response or
write an audit row. Each caller owns its own refusal: Pipeline turns a verdict into
_refuse(...) (JSON-RPC body + BLOCKED audit row with endpoint="per-server"), and policy_api
turns the same verdict into its own REST body and its own audit row with
endpoint="policy-evaluate". Before this split, the refusal shape and the audit row's endpoint
were both hardcoded inside the check itself, which made the checks unusable from anywhere but
the data plane — and, because _refuse writes the audit row BEFORE returning, unfixable by
translating the Response afterwards.

The rules themselves are unchanged and deliberately so: the fail-CLOSED branch when the rate
limit backend is unavailable (issue #31) and the fail-OPEN posture of every quota branch (see
check_quota_verdict's docstring and docs/quotas.md) are the behaviour the data plane has
always had, now shared rather than duplicated.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from argus.quotas import period_start
from argus.rate_limiter import (
    RateLimitBackendUnavailable,
    RateLimiterRegistry,
    server_key,
    tool_key,
)
from db.database import utcnow
from db.models import ApiKeyRecord, ServerPolicy, ServerRecord
from db.repo import UsageRepo

if TYPE_CHECKING:
    from stoa.webhooks import WebhookDispatcher

logger = logging.getLogger(__name__)


@dataclass
class MeteringVerdict:
    """The outcome of one metering check, with everything a caller needs to build its own
    refusal and its own audit row — and nothing about how either should look.

    `allowed=True` carries no other fields. A refusal always carries `rule` (the audit row's
    rule column, and the value operators filter on) and `reason`; `message` is the short
    client-facing text and `data` the structured detail the data plane attaches to its JSON-RPC
    error. `status` is 429 for both refusal kinds today.
    """

    allowed: bool
    rule: Optional[str] = None
    reason: Optional[str] = None
    message: Optional[str] = None
    status: int = 200
    data: Optional[dict] = None


_ALLOWED = MeteringVerdict(allowed=True)


class Metering:
    """Rate limiting, quota enforcement, and usage rollups over a (rate_limiter, usage_repo,
    webhook_dispatcher) trio.

    usage_repo=None means BOTH quota enforcement and rollup writes are no-ops — the same
    "absent = disabled" shape Pipeline uses for its secret provider and tracing manager, and
    the default for every call site that never wired a UsageRepo.
    """

    def __init__(
        self,
        rate_limiter: RateLimiterRegistry,
        usage_repo: Optional[UsageRepo] = None,
        webhook_dispatcher: Optional["WebhookDispatcher"] = None,
    ):
        self._rate_limiter = rate_limiter
        self._usage = usage_repo
        self._webhooks = webhook_dispatcher

    async def check_rate_limits(
        self, server: ServerRecord, policy: ServerPolicy, tool_name: str,
    ) -> MeteringVerdict:
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
        #
        # The keys are deliberately the SAME ones the data plane uses, for every caller: an
        # evaluation via /api/v1/policy/evaluate consumes the same srv:{slug} bucket as a real
        # tools/call, so a caller cannot double its effective budget by alternating between the
        # two surfaces. See docs/rate-limiting.md.
        srv_key = server_key(server.slug)
        if policy.rate_limit:
            self._rate_limiter.ensure_current(srv_key, policy.rate_limit)
        else:
            self._rate_limiter.unregister(srv_key)

        keys = [srv_key] if policy.rate_limit else []
        keys.append(tool_key(server.slug, tool_name))
        try:
            allowed = await self._rate_limiter.check_all(keys)
        except RateLimitBackendUnavailable:
            # Issue #31: fail CLOSED, deliberately — see RateLimitBackendUnavailable's
            # docstring for the reasoning (an adversary trying to bypass a rate limit already
            # controls the load needed to make a shared backend unavailable; fail-open there
            # would hand them the bypass for free). Own `rule` value so this is distinguishable
            # in the audit trail from a genuine over-limit block — an operator seeing a spike of
            # `rate_limit_backend_unavailable` needs a different response (check the backend)
            # than one seeing `rate_limit` (the configured limit is doing its job).
            logger.error(
                "rate limit backend unavailable for server=%s tool=%s — failing closed",
                server.slug, tool_name,
            )
            return MeteringVerdict(
                allowed=False, rule="rate_limit_backend_unavailable",
                reason="rate limit backend unreachable; failing closed",
                message="Rate limit unavailable", status=429,
                data={"tool": tool_name},
            )
        if not allowed:
            return MeteringVerdict(
                allowed=False, rule="rate_limit", message="Rate limit exceeded",
                status=429, data={"tool": tool_name},
            )
        return _ALLOWED

    async def check_quota(
        self, server: ServerRecord, tool_name: str, key_record: Optional[ApiKeyRecord],
    ) -> MeteringVerdict:
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
        configured, or if the quota check ITSELF fails (a DB error reading total_since — the
        key row itself is never re-read here, see the code comment), the call proceeds exactly
        as if no quota existed. The only way this method refuses a call is a clean, successful
        read that shows the caller genuinely over budget.

        SECURITY-SCAN NOTE (accepted, not fixed): the read here (total_since) and the write in
        record_usage happen in two separate steps with the actual upstream forward in between
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
        if self._usage is None or key_record is None:
            return _ALLOWED
        # #111: `key_record` is the SAME row _authenticate/authenticate_no_scope already
        # verified this request — it is passed through rather than re-fetched by id. The old
        # api_keys.get() here was a second get_by_id of an identical, request-scoped record.
        key = key_record
        if key.quota_calls is None or key.quota_period is None:
            return _ALLOWED
        try:
            since = period_start(key.quota_period).isoformat()
            used = await self._usage.total_since(api_key_id=key.id, since_iso=since)
        except Exception:
            # Fail open — see docstring. A DB hiccup on the quota check must never take down
            # the data plane; the worst case of forwarding anyway is one call slightly over a
            # soft budget, not a security exposure (contrast with _resolve_credential, where
            # failing open could leak a request to an upstream expecting credentials).
            logger.error(
                "quota check failed for api_key_id=%s server=%s tool=%s — failing open",
                key_record.id, server.slug, tool_name, exc_info=True,
            )
            return _ALLOWED

        if used < key.quota_calls:
            await self._maybe_fire_quota_webhook(key, used + 1, since)
            return _ALLOWED

        return MeteringVerdict(
            allowed=False, rule="quota", message="Quota exceeded", status=429,
            reason=f"Quota exceeded: {used}/{key.quota_calls} calls this {key.quota_period}",
            data={"tool": tool_name, "quota_period": key.quota_period},
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
        # method is check_quota's `if used < key.quota_calls: await
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

    async def record_usage(
        self, server: ServerRecord, tool_name: Optional[str], api_key_id: Optional[int],
    ) -> None:
        """Increments the usage rollup for this call, in the SAME code path that emits the
        tools/call audit event — called immediately alongside (never instead of)
        AuditLogger.log for every tools/call decision (rate-limit block, quota block, policy
        allow/deny alike), so a rollup total can never drift from a count of the audit rows
        for the same window. See tests/integration/test_quotas.py's
        TestRollupsMatchAuditRows for the test that proves this by direct comparison, and
        AuditLogger.log's own docstring for the parallel "one write path" discipline this
        mirrors.

        Fails open exactly like check_quota, for the same reason: a rollup WRITE failure is a
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
                # _authenticate, not used as the attribution source here).
                project_id=server.project_id,
            )
        except Exception:
            logger.error(
                "usage rollup write failed for api_key_id=%s server=%s tool=%s",
                api_key_id, server.slug, tool_name, exc_info=True,
            )
