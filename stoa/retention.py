from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from archon.background import BackgroundLoop
from db.repo import AuditRepo, SettingsRepo

logger = logging.getLogger("stoa.retention")

DEFAULT_CHECK_INTERVAL_SECONDS = 3600.0


class AuditRetentionJob(BackgroundLoop):
    """Background task: periodically prunes audit_events older than the live
    settings.audit_retention_days value.

    Reads the retention window from SettingsRepo on every run (not once at startup) so a
    change made through the Settings page — same DB-is-authoritative pattern as
    Pipeline._current_auth_mode — takes effect on the job's next tick without a restart.
    """

    _log_name = "audit retention job"
    _logger = logger

    def __init__(
        self,
        audit_repo: AuditRepo,
        settings_repo: SettingsRepo,
        check_interval_seconds: float = DEFAULT_CHECK_INTERVAL_SECONDS,
    ):
        super().__init__()
        self._audit_repo = audit_repo
        self._settings_repo = settings_repo
        self._interval = check_interval_seconds

    async def run_once(self) -> int:
        raw_days = await self._settings_repo.get("audit_retention_days")
        try:
            days = int(raw_days) if raw_days is not None else 30
        except ValueError:
            days = 30
        if days <= 0:
            # 0 or negative means "keep forever" — an explicit opt-out, not a bug.
            return 0

        # §26 fix (review 2026-08-04): this used to format the cutoff as `...Z` while every
        # stored ts value (db/database.py's utcnow(), used by AuditLogger) is
        # datetime.isoformat() — `...+00:00`. audit_events.ts is a TEXT column compared via
        # plain string `<` in SQL, so the two suffix styles are NOT guaranteed to sort the same
        # as they compare chronologically: at the exact same instant, `+00:00` (ASCII '+' = 43)
        # sorts before `Z` (ASCII 'Z' = 90), so a row stored at precisely the cutoff instant
        # would incorrectly compare as "older than cutoff" and get pruned one tick early.
        # Using the same isoformat() as utcnow() guarantees string order matches chronological
        # order for every pair of timestamps this codebase produces.
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_iso = cutoff.isoformat()
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
