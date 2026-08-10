"""Background TTL sweep for approval-workflow proposals (enterprise #9, issue #10).

Piggybacks the AuditRetentionJob's interval-loop pattern (stoa/retention.py) deliberately — the
plan names that pattern as the expiry mechanism, and this module mirrors its shape exactly:
start()/stop()/run_once()/_loop, DB-is-authoritative settings read on every tick, disabled-in-
test-suite via the same fixture knobs.
"""
from __future__ import annotations

import asyncio
import logging

from archon.approvals import ApprovalService
from db.repo import SettingsRepo

logger = logging.getLogger("stoa.proposals")

DEFAULT_CHECK_INTERVAL_SECONDS = 3600.0


class ProposalExpiryJob:
    """Background task: expires pending proposals older than the live
    settings.approvals_ttl_days value.

    Reads the TTL from SettingsRepo on every run (not once at startup) so a change made through
    the Settings page takes effect on the job's next tick without a restart — the same
    DB-is-authoritative pattern as AuditRetentionJob and the webhook dispatcher. When approvals
    are disabled the table stays empty, so run_once() is a cheap no-op rather than a thing that
    needs its own gate.
    """

    def __init__(
        self,
        approvals: ApprovalService,
        settings_repo: SettingsRepo,
        check_interval_seconds: float = DEFAULT_CHECK_INTERVAL_SECONDS,
    ):
        self._approvals = approvals
        self._settings_repo = settings_repo
        self._interval = check_interval_seconds
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("proposal expiry job did not stop within 5s; abandoning it")
            self._task = None

    async def run_once(self) -> int:
        # All TTL/expiry logic lives in ApprovalService.expire_due so it is unit-testable
        # without a running loop; this job only owns the cadence, exactly like
        # AuditRetentionJob delegates its window/delete logic to the repos.
        return await self._approvals.expire_due()

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("proposal expiry iteration failed")
            await asyncio.sleep(self._interval)
