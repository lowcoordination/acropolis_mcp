from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from db.repo import AuditRepo, SettingsRepo

logger = logging.getLogger("stoa.retention")

DEFAULT_CHECK_INTERVAL_SECONDS = 3600.0


class AuditRetentionJob:
    """Background task: periodically prunes audit_events older than the live
    settings.audit_retention_days value.

    Reads the retention window from SettingsRepo on every run (not once at startup) so a
    change made through the Settings page — same DB-is-authoritative pattern as
    Pipeline._current_auth_mode — takes effect on the job's next tick without a restart.
    """

    def __init__(
        self,
        audit_repo: AuditRepo,
        settings_repo: SettingsRepo,
        check_interval_seconds: float = DEFAULT_CHECK_INTERVAL_SECONDS,
    ):
        self._audit_repo = audit_repo
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
                logger.warning("audit retention job did not stop within 5s; abandoning it")
            self._task = None

    async def run_once(self) -> int:
        raw_days = await self._settings_repo.get("audit_retention_days")
        try:
            days = int(raw_days) if raw_days is not None else 30
        except ValueError:
            days = 30
        if days <= 0:
            # 0 or negative means "keep forever" — an explicit opt-out, not a bug.
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        deleted = await self._audit_repo.prune_older_than(cutoff_iso)
        if deleted:
            logger.info("audit retention: pruned %d event(s) older than %d day(s)", deleted, days)
        return deleted

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("audit retention iteration failed")
            await asyncio.sleep(self._interval)
