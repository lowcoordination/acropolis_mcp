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

from db.repo import SettingsRepo

logger = logging.getLogger("stoa.webhooks")

# Item 3 (features_08_05_26): a webhook failure or a slow/hung receiver must never add latency
# to a tool call — this budget is deliberately short and independent of upstream_timeout_seconds,
# which is sized for real MCP tool calls, not a fire-and-forget notification.
WEBHOOK_TIMEOUT_SECONDS = 5.0

DEBOUNCE_WINDOW_SECONDS = 60.0
CAP_WINDOW_SECONDS = 3600.0
CAP_MAX_PER_WINDOW = 20

VALID_EVENTS = ("blocked", "unhealthy")


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


class WebhookDispatcher:
    """Subscribes to AuditLogger's live-tail pub/sub (the same seam the SSE tail and Item 1's
    tool tester use) and fires an outbound webhook on BLOCKED decisions and health-status
    transitions. A new subscriber, not new plumbing — per the plan's framing of why this is
    cheap to wire.

    Settings (webhook_url/enabled/events/allow_private, the signing secret) are read from
    SettingsRepo live on every fire, not cached at start() — same DB-is-authoritative pattern as
    Pipeline._current_auth_mode and AuditRetentionJob, so a change made on the Settings page
    takes effect on the next event without a restart.
    """

    def __init__(
        self,
        audit_logger,
        settings_repo: SettingsRepo,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
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
        self._task: Optional[asyncio.Task] = None
        self._debounce: dict[tuple[str, str], _DebounceEntry] = {}
        self._cap = _CapState()

    def start(self) -> None:
        if self._task is None:
            self._queue = self._audit.subscribe()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("webhook dispatcher task did not stop within 5s; abandoning it")
            self._task = None
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
