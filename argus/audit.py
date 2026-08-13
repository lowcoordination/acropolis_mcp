from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from archon.background import BackgroundLoop
from db.repo import AuditRepo

logger = logging.getLogger("argus.audit")

FLUSH_INTERVAL_SECONDS = 0.1
MAX_BATCH_SIZE = 200


class AuditLogger(BackgroundLoop):
    """Async queue -> batched INSERT into the audit_events table.

    Callers enqueue events without blocking on the write; a background task flushes
    on a fixed interval or when the batch grows large, whichever comes first.

    (Pre-Postgres-cutover this wrote to a separate audit.db SQLite file, which some older
    comments still reference. It is one table in the shared database now.)
    """

    _log_name = "audit flush task"
    _logger = logger

    def __init__(self, repo: AuditRepo) -> None:
        super().__init__()
        self._repo = repo
        self._queue: asyncio.Queue[dict] = asyncio.Queue()
        self._subscribers: set[asyncio.Queue] = set()

    async def _on_stop(self) -> None:
        # Drain anything left in the queue on shutdown. Bounded like the task join (in the
        # base) — this is a DB write precisely when the pool is most likely to be contended,
        # and an unbounded flush here used to be able to hang app shutdown (issue #48).
        try:
            await asyncio.wait_for(self._flush_batch(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("final audit flush did not complete within 5s; some events may be lost")

    async def log(
        self,
        server_slug: Optional[str],
        tool: Optional[str],
        decision: str,  # ALLOWED | BLOCKED | PASSTHROUGH | ERROR
        endpoint: Optional[str] = None,
        rpc_method: Optional[str] = None,
        api_key_id: Optional[int] = None,
        client_ip: Optional[str] = None,
        rule: Optional[str] = None,
        matched: Optional[str] = None,
        args_summary: Optional[dict] = None,
        reason: Optional[str] = None,
        bridged: bool = False,
        status_code: Optional[int] = None,
        latency_ms: Optional[int] = None,
        origin: Optional[str] = None,  # None (normal traffic) | "test" (admin Try-it call)
        dlp_detector: Optional[str] = None,  # enterprise #10 — which detector fired, if any
        dlp_action: Optional[str] = None,  # "block" | "redact" — never the matched/redacted value
        dlp_match_count: Optional[int] = None,
    ) -> None:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "server_slug": server_slug,
            "api_key_id": api_key_id,
            "client_ip": client_ip,
            "endpoint": endpoint,
            "rpc_method": rpc_method,
            "tool": tool,
            "decision": decision,
            "rule": rule,
            "matched": matched,
            "reason": reason,
            "args_summary": json.dumps(args_summary) if args_summary is not None else None,
            # Postgres cutover (enterprise #7): audit_events.bridged is a real BOOLEAN column now,
            # not SQLite's 0/1 INTEGER, and Postgres will not coerce an int into it. Passed
            # through as the bool it already is — `int()` here was only ever a SQLite storage
            # detail leaking into the event dict.
            "bridged": bool(bridged),
            "status_code": status_code,
            "latency_ms": latency_ms,
            "origin": origin,
            "dlp_detector": dlp_detector,
            "dlp_action": dlp_action,
            "dlp_match_count": dlp_match_count,
        }

        level = logging.WARNING if decision == "BLOCKED" else logging.INFO
        logger.log(level, "%s server=%s tool=%s rule=%s", decision, server_slug, tool, rule)

        await self._queue.put(event)
        self._broadcast(event)

    def subscribe(self) -> asyncio.Queue:
        """Register for the live tail. Caller MUST call unsubscribe() when done (e.g. on
        client disconnect) or the queue leaks for the lifetime of the process."""
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _broadcast(self, event: dict) -> None:
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # A slow/stuck subscriber must not block or crash ingestion for everyone else —
                # drop the event for that one subscriber (their tail will show a gap, not stall).
                logger.warning("audit tail subscriber queue full, dropping event")

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                await self._flush_batch()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("audit flush failed")

    async def _flush_batch(self) -> None:
        batch: list[dict] = []
        while not self._queue.empty() and len(batch) < MAX_BATCH_SIZE:
            batch.append(self._queue.get_nowait())
        if batch:
            try:
                await self._repo.insert_many(batch)
            except Exception:
                logger.exception("failed to persist %d audit events", len(batch))
