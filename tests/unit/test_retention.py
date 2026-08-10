from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
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
    # Postgres cutover: seeds go through the repo's public insert_many() rather than a private
    # connection (repos no longer hold one — they acquire from a pool per call).
    await repo.insert_many([{"ts": ts, "server_slug": server_slug, "decision": "ALLOWED"}])


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


async def test_boundary_row_at_exact_cutoff_instant_is_not_pruned(db, monkeypatch):
    """§26 fix (review 2026-08-04): run_once() used to format its cutoff as `...Z`
    (strftime + manual suffix) while every real stored ts value comes from
    db.database.utcnow() = datetime.isoformat() = `...+00:00`. audit_events.ts is a TEXT
    column compared via plain string `<` in SQL — the two suffix styles don't sort the same as
    they compare chronologically. At the EXACT same instant, '+00:00' (ASCII '+' = 43) sorts
    before 'Z' (ASCII 'Z' = 90), so a row stored at precisely the cutoff instant used to
    compare as "older than cutoff" and get incorrectly pruned.

    Freezes stoa.retention's `datetime.now` to a fixed instant (rather than reading the real
    clock, which previously made an equivalent test flaky — two real-clock reads a few
    microseconds apart made the row LEGITIMATELY older than the cutoff, passing/failing for the
    wrong reason). With the clock frozen, a row seeded at exactly retention_days ago (using
    utcnow()'s own isoformat()) and the job's own freshly-computed cutoff are the SAME instant —
    the only way to prove the fix without a race."""
    import stoa.retention as retention_module

    frozen_now = datetime(2026, 8, 4, 10, 0, 0, 0, tzinfo=timezone.utc)

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen_now

    monkeypatch.setattr(retention_module, "datetime", _FrozenDatetime)

    audit_repo = AuditRepo(db)
    settings_repo = SettingsRepo(db)
    await settings_repo.set_many({"audit_retention_days": "7"})

    boundary_instant = frozen_now - timedelta(days=7)
    await audit_repo.insert_many([
        {"ts": boundary_instant.isoformat(), "server_slug": "shell", "decision": "ALLOWED"}
    ])

    job = AuditRetentionJob(audit_repo, settings_repo)
    await job.run_once()

    remaining = await audit_repo.query()
    assert len(remaining) == 1, (
        "a row stored at exactly the cutoff instant was incorrectly pruned — the retention "
        "job's cutoff format doesn't string-sort the same as utcnow()'s stored format"
    )


async def test_prune_older_than_batches_large_deletes(db):
    """§26 fix (review 2026-08-04): prune_older_than used to run a single unbounded DELETE. The
    original SQLite-specific harm (one long transaction on audit.db's single connection blocking
    AuditLogger's flush loop) no longer applies post-cutover, but batching is deliberately KEPT —
    a single giant DELETE bloats WAL, defers autovacuum's ability to reclaim any dead tuples
    until it commits, and holds a long-lived lock set. See AuditRepo.prune_older_than's comment.

    Asserting only the end result (all rows gone) does NOT distinguish batched from unbatched —
    a single unbounded DELETE satisfies that just as well, which is precisely why an earlier
    version of this test passed against the pre-fix code by accident. The distinguishing
    behavior is that MULTIPLE delete statements run (one per batch) rather than one.

    Postgres cutover: the spy moved from the repo's (now nonexistent) private connection to
    asyncpg's Connection.fetchval, which is what the batched delete CTE runs through. Counting
    is filtered to statements containing DELETE so unrelated reads don't inflate it."""
    audit_repo = AuditRepo(db)

    for _ in range(25):
        await _seed_event(audit_repo, age_days=10)

    delete_statement_count = 0
    original_fetchval = asyncpg.Connection.fetchval

    async def counting_fetchval(self, query, *args, **kwargs):
        nonlocal delete_statement_count
        if "DELETE" in query.upper():
            delete_statement_count += 1
        return await original_fetchval(self, query, *args, **kwargs)

    asyncpg.Connection.fetchval = counting_fetchval
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        deleted = await audit_repo.prune_older_than(cutoff, batch_size=10)
    finally:
        asyncpg.Connection.fetchval = original_fetchval

    assert deleted == 25
    remaining = await audit_repo.query()
    assert len(remaining) == 0
    # 25 rows at batch_size=10 -> 3 DELETE statements (10, 10, 5-then-stop): the loop's own
    # "deleted < batch_size" termination means it always runs one extra (empty or partial)
    # DELETE to detect it's done, so 3 here, never 1.
    assert delete_statement_count == 3, (
        f"expected multiple batched DELETE statements (not one unbounded DELETE), "
        f"got {delete_statement_count}"
    )
