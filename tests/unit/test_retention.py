from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from db.database import Database
from db.repo import AuditRepo, SettingsRepo
from stoa.retention import AuditRetentionJob


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


async def _seed_event(repo: AuditRepo, age_days: float, server_slug: str = "shell") -> None:
    ts = _iso(datetime.now(timezone.utc) - timedelta(days=age_days))
    await repo._conn.execute(
        "INSERT INTO audit_events (ts, server_slug, decision) VALUES (?, ?, ?)",
        (ts, server_slug, "ALLOWED"),
    )
    await repo._conn.commit()


async def test_prunes_events_older_than_configured_days(db):
    audit_repo = AuditRepo(db)
    settings_repo = SettingsRepo(db)
    await settings_repo.set_many({"audit_retention_days": "7"})

    await _seed_event(audit_repo, age_days=10)
    await _seed_event(audit_repo, age_days=1)

    job = AuditRetentionJob(audit_repo, settings_repo)
    deleted = await job.run_once()

    assert deleted == 1
    remaining = await audit_repo.query()
    assert len(remaining) == 1


async def test_defaults_to_thirty_days_when_setting_unset(db):
    audit_repo = AuditRepo(db)
    settings_repo = SettingsRepo(db)
    # audit_retention_days deliberately never set — job must not crash or prune everything.

    await _seed_event(audit_repo, age_days=45)
    await _seed_event(audit_repo, age_days=5)

    job = AuditRetentionJob(audit_repo, settings_repo)
    deleted = await job.run_once()

    assert deleted == 1
    remaining = await audit_repo.query()
    assert len(remaining) == 1


async def test_zero_retention_days_means_keep_forever(db):
    audit_repo = AuditRepo(db)
    settings_repo = SettingsRepo(db)
    await settings_repo.set_many({"audit_retention_days": "0"})

    await _seed_event(audit_repo, age_days=9999)

    job = AuditRetentionJob(audit_repo, settings_repo)
    deleted = await job.run_once()

    assert deleted == 0
    remaining = await audit_repo.query()
    assert len(remaining) == 1


async def test_start_stop_lifecycle_does_not_hang():
    # Mirrors HealthPoller's bounded-shutdown contract — a background job must never block
    # app shutdown, even one that hasn't done any real work yet.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp))
        await db.connect()
        try:
            audit_repo = AuditRepo(db)
            settings_repo = SettingsRepo(db)
            job = AuditRetentionJob(audit_repo, settings_repo, check_interval_seconds=3600.0)
            job.start()
            await job.stop()
        finally:
            await db.close()
