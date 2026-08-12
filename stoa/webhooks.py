from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from archon.background import BackgroundLoop
from db.repo import SettingsRepo

logger = logging.getLogger("stoa.webhooks")

# Item 3 (features_08_05_26): a webhook failure or a slow/hung receiver must never add latency
# to a tool call — this budget is deliberately short and independent of upstream_timeout_seconds,
# which is sized for real MCP tool calls, not a fire-and-forget notification.
WEBHOOK_TIMEOUT_SECONDS = 5.0

DEBOUNCE_WINDOW_SECONDS = 60.0
CAP_WINDOW_SECONDS = 3600.0
CAP_MAX_PER_WINDOW = 20

VALID_EVENTS = ("blocked", "unhealthy", "drift", "quota", "approval_pending")

# Bound on WebhookDispatcher._quota_fired's size — see fire_quota_threshold's self-review-fix
# comment. 10,000 distinct (key_prefix, period_start) entries is generously above what any
# reasonably-sized deployment's key count x active-period count would produce; this exists to
# cap worst-case memory, not to be a limit anyone should expect to approach in practice.
_QUOTA_FIRED_MAX_ENTRIES = 10_000


@dataclass
class _DebounceEntry:
    first_seen: float
    count: int = 0
    task: Optional[asyncio.Task] = None


@dataclass
class _CapState:
    window_start: float = field(default_factory=time.monotonic)
    count: int = 0
    suppressed: int = 0


class WebhookDispatcher(BackgroundLoop):
    """Subscribes to AuditLogger's live-tail pub/sub (the same seam the SSE tail and Item 1's
    tool tester use) and fires an outbound webhook on BLOCKED decisions and health-status
    transitions. A new subscriber, not new plumbing — per the plan's framing of why this is
    cheap to wire.

    Settings (webhook_url/enabled/events/allow_private, the signing secret) are read from
    SettingsRepo live on every fire, not cached at start() — same DB-is-authoritative pattern as
    Pipeline._current_auth_mode and AuditRetentionJob, so a change made on the Settings page
    takes effect on the next event without a restart.
    """

    _log_name = "webhook dispatcher task"
    _logger = logger

    def __init__(
        self,
        audit_logger,
        settings_repo: SettingsRepo,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        super().__init__()
        self._audit = audit_logger
        self._settings_repo = settings_repo
        # A DEDICATED client, not the shared app-wide one: that client's Limits/Timeout are
        # sized for upstream MCP traffic and, more importantly, sharing it would mean a webhook
        # dispatch competes for the same connection-pool slots as real tool calls. Also
        # explicitly follow_redirects=False — a 302 to a private/link-local address is the
        # specific bypass that makes the pre-flight _validate_webhook_url check insufficient on
        # its own (see that function's docstring).
        self._http = http_client or httpx.AsyncClient(
            timeout=WEBHOOK_TIMEOUT_SECONDS, follow_redirects=False
        )
        self._owns_http = http_client is None
        self._queue: Optional[asyncio.Queue] = None
        self._debounce: dict[tuple[str, str], _DebounceEntry] = {}
        self._cap = _CapState()
        # Enterprise #11: (key_prefix, period_start_iso) -> highest threshold already fired
        # this period. Per-PERIOD debounce, not the time-windowed DEBOUNCE_WINDOW_SECONDS
        # pattern the rest of this class uses for BLOCKED/unhealthy/drift — a quota alert's
        # correct debounce boundary is "once per threshold per billing period," which could be
        # hours or a month wide, not a fixed 60s window. period_start_iso is part of the key so
        # a NEW period (the caller computes a new start via argus.quotas.period_start) starts
        # with a clean slate automatically, with no separate reset job needed.
        self._quota_fired: dict[tuple[str, str], int] = {}
        # Enterprise #11 self-review fix: a burst of concurrent requests can all read
        # self._quota_fired BEFORE any of them writes it back — the classic check-then-act race
        # (see tests/integration/test_quotas.py::test_concurrent_burst_crossing_threshold_
        # fires_webhook_exactly_once for the regression test). One lock, keyed by
        # (key_prefix, period_start_iso), makes "check what's fired, then record what just
        # fired" atomic across concurrent callers instead of two separate awaits with a gap
        # between them.
        self._quota_lock = asyncio.Lock()

    async def fire(self, event_type: str, payload: dict) -> None:
        """Fire a webhook event of the given type. Generic entry point for non-audit events
        (e.g. GitOps drift detection). Debounced and capped the same as audit-driven events."""
        config = await self._load_config()
        if config is None or event_type not in config["events"]:
            return

        key = (event_type, payload.get("status", ""))
        now = time.monotonic()
        entry = self._debounce.get(key)
        if entry is not None and now - entry.first_seen < DEBOUNCE_WINDOW_SECONDS:
            entry.count += 1
            return

        entry = _DebounceEntry(first_seen=now, count=1)
        self._debounce[key] = entry
        entry.task = asyncio.create_task(self._debounced_send_generic(key, event_type, payload, config))

    async def _debounced_send_generic(
        self, key: tuple[str, str], event_type: str, payload: dict, config: dict
    ) -> None:
        """Wait out the debounce window, then send with the final count."""
        await asyncio.sleep(DEBOUNCE_WINDOW_SECONDS)
        entry = self._debounce.pop(key, None)
        if entry is None:
            return
        await self._send_if_under_cap(config, {
            "event": event_type,
            "count": entry.count,
            **payload,
        })

    def start(self) -> None:
        if self._task is None:
            self._queue = self._audit.subscribe()
            self._task = asyncio.create_task(self._loop())

    async def _on_stop(self) -> None:
        # Teardown beyond the base's task join: unsubscribe from the audit tail, cancel
        # in-flight debounce sends, and close an owned client. The debounce-task management
        # stays here deliberately — it is genuinely different from the single-task lifecycle
        # and does not belong in the base.
        if self._queue is not None:
            self._audit.unsubscribe(self._queue)
            self._queue = None
        for entry in self._debounce.values():
            if entry.task is not None:
                entry.task.cancel()
        self._debounce.clear()
        await self._flush_pending_suppression()
        if self._owns_http:
            await self._http.aclose()

    async def _loop(self) -> None:
        assert self._queue is not None
        while True:
            try:
                event = await self._queue.get()
                if event.get("decision") == "BLOCKED" and event.get("origin") != "test":
                    await self._handle_blocked(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("webhook dispatcher failed to process an audit event")

    async def _handle_blocked(self, event: dict) -> None:
        config = await self._load_config()
        if config is None or "blocked" not in config["events"]:
            return

        key = (event.get("server_slug") or "", event.get("rule") or "")
        now = time.monotonic()
        entry = self._debounce.get(key)
        if entry is not None and now - entry.first_seen < DEBOUNCE_WINDOW_SECONDS:
            # Collapse this repeat into the pending window — the eventual send reports the
            # final count, not "1 blocked" repeated N times.
            entry.count += 1
            return

        entry = _DebounceEntry(first_seen=now, count=1)
        self._debounce[key] = entry
        entry.task = asyncio.create_task(self._debounced_send(key, event, config))

    async def _debounced_send(self, key: tuple[str, str], event: dict, config: dict) -> None:
        try:
            await asyncio.sleep(DEBOUNCE_WINDOW_SECONDS)
            entry = self._debounce.get(key)
            count = entry.count if entry is not None else 1
            await self._send_if_under_cap(
                config,
                {
                    "event": "blocked",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "server_slug": event.get("server_slug"),
                    "tool": event.get("tool"),
                    "rule": event.get("rule"),
                    "matched": event.get("matched"),
                    "reason": event.get("reason"),
                    "count": count,
                    # Enterprise #10 (DLP): the detector NAME is safe to send (operator-facing
                    # metadata, same trust level as `rule`) — the matched/redacted VALUE never
                    # is. `event.get("matched")` above is None on a DLP-driven block (see
                    # argus/policy.py's Decision — DLP never populates `matched`), so this key
                    # is the only DLP-specific field this payload ever carries, mirroring the
                    # existing deliberate exclusion of args_summary from webhook payloads.
                    "dlp_detector": event.get("dlp_detector"),
                },
            )
        finally:
            self._debounce.pop(key, None)

    async def notify_unhealthy(self, server_slug: str) -> None:
        """Called from stoa/health.py on the healthy->unhealthy EDGE only — never on every poll
        tick while a server stays down. No debounce needed here: an edge fires at most once per
        transition by construction, unlike BLOCKED, which fires once per matching request."""
        config = await self._load_config()
        if config is None or "unhealthy" not in config["events"]:
            return
        await self._send_if_under_cap(
            config,
            {
                "event": "unhealthy",
                "ts": datetime.now(timezone.utc).isoformat(),
                "server_slug": server_slug,
                "count": 1,
            },
        )

    async def notify_approval_pending(
        self, *, proposal_id: int, target_type: str, target_id: str, proposer: str,
    ) -> None:
        """Enterprise #9: fires the `approval_pending` webhook event when a proposal is created
        (called from archon/approvals.py). Edge semantics like notify_unhealthy — a proposal
        creation happens at most once per proposal by construction, so there is nothing to
        debounce (unlike BLOCKED/quota, which fire per matching request and need the window).

        PAYLOAD SECRECY (non-negotiable, matching the DLP/secrets discipline elsewhere): the
        payload carries the proposal id, its target, and the proposer's actor label — NOTHING
        else. No diff contents, no policy payload, no YAML, no matched values (same reason
        `blocked` events exclude args_summary and the DLP detector name is the only DLP field
        that ever leaves). The id is the receiver's handle for pulling detail over the
        authenticated API if it wants it."""
        config = await self._load_config()
        if config is None or "approval_pending" not in config["events"]:
            return
        await self._send_if_under_cap(
            config,
            {
                "event": "approval_pending",
                "ts": datetime.now(timezone.utc).isoformat(),
                "proposal_id": proposal_id,
                "target_type": target_type,
                "target_id": target_id,
                "proposer": proposer,
                "count": 1,
            },
        )

    async def fire_quota_threshold(
        self, *, key_prefix: str, key_name: str, threshold: int, period: str, period_start_iso: str,
    ) -> None:
        """Enterprise #11: fires the `quota` webhook event when a call crosses an
        80%/100%-of-quota threshold. Called from argus/pipeline.py's _check_quota /
        _maybe_fire_quota_webhook, which already determined THAT a threshold was newly crossed
        by the call currently being evaluated — this method's only remaining job is the
        once-per-threshold-per-period debounce and the actual send.

        PAYLOAD SECRECY (non-negotiable, matching the DLP/secrets discipline elsewhere in this
        codebase): only `key_prefix` (already a public, truncated, non-secret identifier shown
        in the UI — see ApiKeyRecord/ApiKeyService, which only ever store a SHA-256 hash of the
        real key) and `key_name` (operator-assigned label, not secret) leave this method. The
        key's plaintext is never available past creation time (show-once by design) and its
        hash is never put on any outbound surface, webhook payloads included — same rule
        test_webhooks.py already enforces for the `blocked` event's exclusion of args_summary.
        """
        config = await self._load_config()
        if config is None or "quota" not in config["events"]:
            return

        debounce_key = (key_prefix, period_start_iso)
        # Self-review fix: the check (has this threshold already fired this period?) and the
        # record (mark it fired) must be atomic across concurrent callers, or a burst of
        # simultaneous requests all crossing 80% at once can all pass the check before any of
        # them records it — firing the webhook N times instead of once. One lock held across
        # both halves closes that window; see test_quotas.py's concurrent-burst regression test.
        async with self._quota_lock:
            already_fired = self._quota_fired.get(debounce_key, 0)
            if already_fired >= threshold:
                return
            self._quota_fired[debounce_key] = threshold
            # Self-review fix: unlike self._debounce (whose entries are popped once their
            # window's debounced send completes — see _debounced_send), nothing was ever
            # removing an entry from self._quota_fired. Every distinct (key_prefix,
            # period_start) combination a quota-configured key ever crosses a threshold in
            # accumulates one entry, forever, for the life of the process — an unbounded
            # per-process memory leak on a long-running gateway (one entry per key per day for
            # daily quotas, indefinitely). There's no natural "period ended" signal to hook a
            # real eviction on without parsing period lengths this class doesn't otherwise need
            # to know, so this is a simple bound instead: once the map exceeds a generous cap,
            # drop the oldest half (insertion order, since dicts preserve it) — old periods are
            # exactly the ones safe to forget, since their debounce guarantee no longer matters
            # once the period itself is over.
            if len(self._quota_fired) > _QUOTA_FIRED_MAX_ENTRIES:
                stale_keys = list(self._quota_fired.keys())[: len(self._quota_fired) // 2]
                for stale_key in stale_keys:
                    self._quota_fired.pop(stale_key, None)

        await self._send_if_under_cap(
            config,
            {
                "event": "quota",
                "ts": datetime.now(timezone.utc).isoformat(),
                "server_slug": None,
                "key_prefix": key_prefix,
                "key_name": key_name,
                "threshold_percent": threshold,
                "period": period,
                "count": 1,
            },
        )

    async def send_test(self) -> tuple[bool, Optional[int], Optional[str]]:
        """Backs the Settings page's "Send test webhook" button — bypasses debounce and the cap
        entirely (it's a single, deliberate, operator-initiated action, not traffic) and reports
        the outcome synchronously so a misconfigured URL is visible immediately rather than
        silently dropped like a real alert would be."""
        config = await self._load_config()
        if config is None:
            return False, None, "webhook_url is not configured"
        payload = {
            "event": "test",
            "ts": datetime.now(timezone.utc).isoformat(),
            "server_slug": None,
            "count": 1,
        }
        try:
            resp = await self._post(config, payload)
            return (200 <= resp.status_code < 300), resp.status_code, None
        except httpx.HTTPError as e:
            return False, None, str(e)

    async def _send_if_under_cap(self, config: dict, payload: dict) -> None:
        now = time.monotonic()
        if now - self._cap.window_start >= CAP_WINDOW_SECONDS:
            # Window rolled over — flush the PREVIOUS window's tally as one notice reporting
            # the true total (not "1 suppressed" sent the instant the cap first tripped, which
            # would undercount every window that goes on to suppress far more than that). A
            # window that suppressed nothing has nothing to flush.
            if self._cap.suppressed:
                await self._send_suppression_notice(config, self._cap.suppressed)
            self._cap = _CapState(window_start=now)

        if self._cap.count >= CAP_MAX_PER_WINDOW:
            self._cap.suppressed += 1
            return

        self._cap.count += 1
        try:
            await self._post(config, payload)
        except httpx.HTTPError:
            logger.warning("webhook delivery failed", exc_info=True)

    async def _send_suppression_notice(self, config: dict, suppressed: int) -> None:
        try:
            await self._post(
                config,
                {
                    "event": "suppressed",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "server_slug": None,
                    "count": suppressed,
                },
            )
        except httpx.HTTPError:
            logger.warning("webhook suppression notice failed to send", exc_info=True)

    async def _flush_pending_suppression(self) -> None:
        """Called from stop() so a suppression tally accrued right before shutdown is never
        silently lost — "silence and nothing happened must never look alike" applies here too:
        an operator restarting the gateway mid-flood shouldn't have the last window's count
        vanish along with the process."""
        if self._cap.suppressed:
            config = await self._load_config()
            if config is not None:
                await self._send_suppression_notice(config, self._cap.suppressed)
            self._cap = _CapState()

    async def _post(self, config: dict, payload: dict) -> httpx.Response:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if config["secret"]:
            # HMAC-SHA256 over the exact bytes sent, so the receiver can verify origin +
            # integrity without the gateway ever needing a response body back.
            signature = hmac.new(config["secret"].encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Acropolis-Signature"] = f"sha256={signature}"
        return await self._http.post(config["url"], content=body, headers=headers)

    async def _load_config(self) -> Optional[dict]:
        values = await self._settings_repo.get_all()
        url = values.get("webhook_url")
        enabled = values.get("webhook_enabled") == "true"
        if not url or not enabled:
            return None
        raw_events = values.get("webhook_events")
        events = set(raw_events.split(",")) if raw_events else {"blocked", "unhealthy"}
        return {
            "url": url,
            "secret": values.get("webhook_secret"),
            "events": events,
        }
