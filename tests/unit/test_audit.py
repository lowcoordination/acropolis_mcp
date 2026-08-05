from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from argus.audit import AuditLogger
from db.database import Database
from db.repo import AuditRepo


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


async def _seed(repo: AuditRepo, **overrides) -> None:
    row = {
        "ts": _iso(datetime.now(timezone.utc)), "server_slug": "shell", "api_key_id": None,
        "client_ip": None, "endpoint": None, "rpc_method": None, "tool": None,
        "decision": "ALLOWED", "rule": None, "matched": None, "reason": None,
        "args_summary": None, "bridged": 0, "status_code": None, "latency_ms": None,
    }
    row.update(overrides)
    await repo._conn.execute(
        """INSERT INTO audit_events
           (ts, server_slug, api_key_id, client_ip, endpoint, rpc_method, tool,
            decision, rule, matched, reason, args_summary, bridged, status_code, latency_ms)
           VALUES (:ts, :server_slug, :api_key_id, :client_ip, :endpoint, :rpc_method, :tool,
                   :decision, :rule, :matched, :reason, :args_summary, :bridged, :status_code, :latency_ms)""",
        row,
    )
    await repo._conn.commit()


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


async def test_query_filters_by_api_key_id(db):
    repo = AuditRepo(db)
    await _seed(repo, api_key_id=1, tool="a")
    await _seed(repo, api_key_id=2, tool="b")
    await _seed(repo, api_key_id=None, tool="c")

    events = await repo.query(api_key_id=1)
    assert len(events) == 1
    assert events[0]["tool"] == "a"


async def test_query_filters_by_after_and_before(db):
    repo = AuditRepo(db)
    now = datetime.now(timezone.utc)
    await _seed(repo, ts=_iso(now - timedelta(days=3)), tool="old")
    await _seed(repo, ts=_iso(now - timedelta(days=1)), tool="middle")
    await _seed(repo, ts=_iso(now), tool="new")

    after_only = await repo.query(after=_iso(now - timedelta(days=2)))
    assert {e["tool"] for e in after_only} == {"middle", "new"}

    before_only = await repo.query(before=_iso(now - timedelta(days=2)))
    assert {e["tool"] for e in before_only} == {"old"}

    ranged = await repo.query(after=_iso(now - timedelta(days=2)), before=_iso(now - timedelta(hours=1)))
    assert {e["tool"] for e in ranged} == {"middle"}


async def test_query_search_matches_reason_args_and_matched(db):
    repo = AuditRepo(db)
    await _seed(repo, tool="a", reason="matched sudo rm -rf")
    await _seed(repo, tool="b", args_summary="path=/etc/passwd")
    await _seed(repo, tool="c", matched="block_pattern:sudo")
    await _seed(repo, tool="d", reason="unrelated")

    events = await repo.query(search="sudo")
    assert {e["tool"] for e in events} == {"a", "c"}

    events = await repo.query(search="/etc/passwd")
    assert {e["tool"] for e in events} == {"b"}


async def test_query_search_escapes_percent_and_underscore_wildcards(db):
    repo = AuditRepo(db)
    await _seed(repo, tool="literal", reason="rate limited: 100% quota used")
    await _seed(repo, tool="decoy", reason="rate limited: 100X quota used")
    await _seed(repo, tool="underscore", reason="key_id_123")
    await _seed(repo, tool="underscore_decoy", reason="keyXidX123")

    events = await repo.query(search="100%")
    assert {e["tool"] for e in events} == {"literal"}

    events = await repo.query(search="key_id")
    assert {e["tool"] for e in events} == {"underscore"}


async def test_query_combines_multiple_new_filters(db):
    repo = AuditRepo(db)
    now = datetime.now(timezone.utc)
    await _seed(repo, ts=_iso(now), api_key_id=1, decision="BLOCKED", reason="sudo blocked", tool="match")
    await _seed(repo, ts=_iso(now), api_key_id=2, decision="BLOCKED", reason="sudo blocked", tool="wrong-key")
    await _seed(repo, ts=_iso(now), api_key_id=1, decision="ALLOWED", reason="sudo ok", tool="wrong-decision")
    await _seed(repo, ts=_iso(now - timedelta(days=10)), api_key_id=1, decision="BLOCKED", reason="sudo blocked", tool="too-old")

    events = await repo.query(
        api_key_id=1, decision="BLOCKED", search="sudo",
        after=_iso(now - timedelta(days=1)),
    )
    assert len(events) == 1
    assert events[0]["tool"] == "match"
