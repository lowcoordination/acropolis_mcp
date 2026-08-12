"""Shared start/stop lifecycle for cancellable periodic background tasks.

Six classes across argus/stoa hand-copied this lifecycle; the copies had already drifted —
argus/audit.py's stop() omitted the timeout entirely and could hang app shutdown (fixed in
issue #48). Keeping the lifecycle in one place means the next fix lands once. Epic #57, #49.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger("archon.background")


class BackgroundLoop:
    """Start/stop lifecycle for a cancellable periodic task.

    Subclasses implement _loop(). Override _on_stop() for teardown that must happen after the
    task is cancelled (closing owned clients, unsubscribing from queues).
    """

    # Bounded: cancellation of a task parked in a plain asyncio.sleep() is normally near-instant,
    # but under real ASGI server shutdown (uvicorn + anyio task groups from in-flight MCP
    # sessions) this has been observed to stall well past that. A background task must never be
    # allowed to block app shutdown indefinitely — abandon it after a bounded wait rather than
    # hang the process. (Comment moved verbatim from stoa/health.py's stop(), where it
    # originated.)
    _stop_timeout = 5.0
    _log_name = "background task"
    # Each subclass points this at its own module logger so the warning's provenance is
    # unchanged from the pre-base copies (e.g. "stoa.health", "argus.audit").
    _logger = logger

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=self._stop_timeout)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                # %g formats 5.0 as "5", keeping the message byte-identical to the pre-base
                # copies (e.g. "health poller task did not stop within 5s; abandoning it").
                self._logger.warning(
                    "%s did not stop within %gs; abandoning it",
                    self._log_name, self._stop_timeout,
                )
            self._task = None
        await self._on_stop()

    async def _on_stop(self) -> None:
        return None

    async def _loop(self) -> None:
        raise NotImplementedError
