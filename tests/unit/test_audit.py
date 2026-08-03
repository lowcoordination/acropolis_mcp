from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from argus.audit import AuditLogger
from db.database import Database
from db.repo import AuditRepo


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


async def test_log_and_flush_persists_event(db):
    repo = AuditRepo(db)
    logger = AuditLogger(repo)
    logger.start()
    try:
        await logger.log(
            server_slug="shell", tool="shell_run", decision="BLOCKED",
            rule="block_pattern", reason="matched sudo",
        )
        # Flush interval is 0.1s — wait past it rather than racing the background task.
        await asyncio.sleep(0.25)
        events = await repo.query()
        assert len(events) == 1
        assert events[0]["server_slug"] == "shell"
        assert events[0]["decision"] == "BLOCKED"
        assert events[0]["rule"] == "block_pattern"
    finally:
        await logger.stop()


async def test_stop_drains_pending_queue(db):
    repo = AuditRepo(db)
    logger = AuditLogger(repo)
    logger.start()
    await logger.log(server_slug="fetch", tool=None, decision="PASSTHROUGH")
    await logger.stop()  # should flush immediately without waiting for the interval
    events = await repo.query()
    assert len(events) == 1
    assert events[0]["decision"] == "PASSTHROUGH"


async def test_query_filters_by_server_and_decision(db):
    repo = AuditRepo(db)
    logger = AuditLogger(repo)
    logger.start()
    await logger.log(server_slug="shell", tool="a", decision="ALLOWED")
    await logger.log(server_slug="shell", tool="b", decision="BLOCKED")
    await logger.log(server_slug="fetch", tool="c", decision="BLOCKED")
    await logger.stop()

    shell_events = await repo.query(server_slug="shell")
    assert len(shell_events) == 2

    blocked_events = await repo.query(decision="BLOCKED")
    assert len(blocked_events) == 2
    assert {e["server_slug"] for e in blocked_events} == {"shell", "fetch"}
