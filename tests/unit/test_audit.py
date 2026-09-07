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
        # bridged is a real BOOLEAN column post-cutover, not SQLite's 0/1 INTEGER.
        "args_summary": None, "bridged": False, "status_code": None, "latency_ms": None,
        "origin": None,
    }
    row.update(overrides)
    # Postgres cutover: seeds now go through the repo's own public insert_many() rather than
    # reaching into a private connection (`repo._conn`, which no longer exists — repos acquire
    # from a pool per call instead of holding one). This is strictly better as a test: it
    # exercises the same write path production uses, so a bug in insert_many's column mapping
    # can't hide behind a hand-written INSERT in the test helper.
    await repo.insert_many([row])


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


async def test_stop_is_bounded_when_flush_blocks(db, monkeypatch):
    """Regression for #48: stop() must not hang shutdown when the final DB flush blocks.

    Before the fix, both the task await and the final _flush_batch() were unbounded — a pool
    contention stall during shutdown would block the lifespan finally block indefinitely,
    leaking the shared httpx client, the secret provider's client, and unexported OTel spans
    behind it. The bound is 5s per await; give stop() a generous margin and assert it returns
    at all (and still cleans up the task reference).
    """
    logger = AuditLogger(AuditRepo(db))

    async def _blocking_flush() -> None:
        await asyncio.sleep(30)

    monkeypatch.setattr(logger, "_flush_batch", _blocking_flush)

    logger.start()
    await logger.log(server_slug="fetch", tool=None, decision="PASSTHROUGH")

    await asyncio.wait_for(logger.stop(), timeout=6.5)
    assert logger._task is None


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


async def test_query_origin_unfiltered_by_default_returns_both(db):
    repo = AuditRepo(db)
    await _seed(repo, tool="real", origin=None)
    await _seed(repo, tool="tested", origin="test")

    events = await repo.query()
    assert {e["tool"] for e in events} == {"real", "tested"}


async def test_query_origin_none_returns_only_normal_traffic(db):
    """`origin=None` is a real filter value ('only rows where origin IS NULL'), distinct from
    the default (`_UNSET`, meaning 'don't filter on origin at all') — this is the case that
    /stats and the Audit page's default view rely on to hide Try-it test calls."""
    repo = AuditRepo(db)
    await _seed(repo, tool="real", origin=None)
    await _seed(repo, tool="tested", origin="test")

    events = await repo.query(origin=None)
    assert {e["tool"] for e in events} == {"real"}


async def test_query_origin_explicit_value_returns_only_that_origin(db):
    repo = AuditRepo(db)
    await _seed(repo, tool="real", origin=None)
    await _seed(repo, tool="tested", origin="test")

    events = await repo.query(origin="test")
    assert {e["tool"] for e in events} == {"tested"}


async def test_count_since_excludes_test_traffic(db):
    repo = AuditRepo(db)
    since = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    await _seed(repo, decision="BLOCKED", origin=None)
    await _seed(repo, decision="BLOCKED", origin="test")
    await _seed(repo, decision="BLOCKED", origin="test")

    count = await repo.count_since(since, decision="BLOCKED")
    assert count == 1


# ---------------------------------------------------------------------------
# #123: origin CLASS filtering and the grouped by-class count.
#
# Exact-match on origin becomes unusable for "show me every local evaluation" once the detail
# half carries a key name and a caller-asserted hostname — a filter would have to enumerate
# every host that has ever called.
# ---------------------------------------------------------------------------


async def test_origin_class_gateway_returns_only_null_origin(db):
    repo = AuditRepo(db)
    await _seed(repo, tool="real", origin=None)
    await _seed(repo, tool="tryit", origin="test")
    await _seed(repo, tool="eval", origin="local:guard")

    events = await repo.query(origin_class="gateway")
    assert {e["tool"] for e in events} == {"real"}


async def test_origin_class_local_matches_every_detail_variant(db):
    repo = AuditRepo(db)
    await _seed(repo, tool="plain", origin="local:guard")
    await _seed(repo, tool="asserted", origin="local:guard/pi@laptop")
    await _seed(repo, tool="otherkey", origin="local:other/claude-code@ci-box")
    await _seed(repo, tool="real", origin=None)
    await _seed(repo, tool="tryit", origin="test")

    events = await repo.query(origin_class="local")
    assert {e["tool"] for e in events} == {"plain", "asserted", "otherkey"}


async def test_origin_class_test_matches_the_legacy_bare_token(db):
    """origin='test' has no colon — it predates the class:detail scheme and those rows are
    already on disk, so the prefix match must cover a bare class token too."""
    repo = AuditRepo(db)
    await _seed(repo, tool="tryit", origin="test")
    await _seed(repo, tool="eval", origin="local:guard")

    events = await repo.query(origin_class="test")
    assert {e["tool"] for e in events} == {"tryit"}


async def test_origin_class_does_not_match_a_longer_class_name(db):
    """'local' must not match a hypothetical 'localhost:...' — the match is on the full leading
    segment, not a bare string prefix."""
    repo = AuditRepo(db)
    await _seed(repo, tool="notlocal", origin="localhost:x")
    await _seed(repo, tool="islocal", origin="local:guard")

    events = await repo.query(origin_class="local")
    assert {e["tool"] for e in events} == {"islocal"}


async def test_count_by_origin_class_groups_by_class_and_decision(db):
    repo = AuditRepo(db)
    await _seed(repo, origin=None, decision="ALLOWED")
    await _seed(repo, origin=None, decision="BLOCKED")
    await _seed(repo, origin=None, decision="BLOCKED")
    await _seed(repo, origin="local:guard/pi@box", decision="BLOCKED")
    await _seed(repo, origin="local:other", decision="ALLOWED")
    await _seed(repo, origin="test", decision="ALLOWED")

    counts = await repo.count_by_origin_class_since("1970-01-01T00:00:00.000Z")
    assert counts["gateway"] == {"ALLOWED": 1, "BLOCKED": 2}
    assert counts["local"] == {"BLOCKED": 1, "ALLOWED": 1}
    assert counts["test"] == {"ALLOWED": 1}


async def test_count_by_origin_class_never_exposes_the_detail_half(db):
    """The hostname must never reach a Prometheus label — grouping returns classes only."""
    repo = AuditRepo(db)
    await _seed(repo, origin="local:guard/pi@secret-hostname", decision="ALLOWED")

    counts = await repo.count_by_origin_class_since("1970-01-01T00:00:00.000Z")
    assert list(counts) == ["local"]
    assert not any("secret-hostname" in key for key in counts)


async def test_count_by_origin_class_respects_the_since_bound(db):
    repo = AuditRepo(db)
    old_ts = _iso(datetime.now(timezone.utc) - timedelta(days=2))
    await _seed(repo, origin=None, decision="ALLOWED", ts=old_ts)
    await _seed(repo, origin=None, decision="BLOCKED")

    since = _iso(datetime.now(timezone.utc) - timedelta(days=1))
    counts = await repo.count_by_origin_class_since(since)
    assert counts == {"gateway": {"BLOCKED": 1}}


async def test_count_by_origin_class_counts_every_decision_including_passthrough(db):
    """PASSTHROUGH is a legal decision (0001_init's CHECK) and the most common one on the data
    plane, but /metrics only names ALLOWED/BLOCKED/ERROR explicitly and derives OTHER by
    subtraction. If the grouped read dropped or mis-bucketed a decision, OTHER would silently
    absorb the error — so pin that every decision is returned, per class."""
    repo = AuditRepo(db)
    await _seed(repo, origin=None, decision="PASSTHROUGH")
    await _seed(repo, origin=None, decision="ALLOWED")
    await _seed(repo, origin="local:guard", decision="PASSTHROUGH")

    counts = await repo.count_by_origin_class_since("1970-01-01T00:00:00.000Z")
    assert counts["gateway"] == {"PASSTHROUGH": 1, "ALLOWED": 1}
    assert counts["local"] == {"PASSTHROUGH": 1}


async def test_origin_class_treats_like_metacharacters_literally(db):
    """A class containing `%` or `_` must not act as a SQL LIKE wildcard.

    Found by /security-scan on #123: the class is used in a LIKE prefix match, so an unescaped
    `%` matched EVERY structured origin — a filter that silently widens instead of narrowing,
    which is the worst direction for an audit filter to fail in. archon/api.py validates the
    class against a fixed vocabulary, but AuditRepo.query is a public method reached directly by
    argus/metrics.py and by future callers, so the escaping belongs here. Mirrors the same
    escaping the `search` filter has always done.
    """
    repo = AuditRepo(db)
    await _seed(repo, tool="structured", origin="local:secret-key")
    await _seed(repo, tool="legacy", origin="test")

    for hostile in ("%", "_", "local%", "loca_", "' OR 1=1 --", "local'"):
        assert await repo.query(origin_class=hostile) == [], (
            f"{hostile!r} must match nothing, not act as a wildcard"
        )

    # Positive control: a legitimate class on the same fixture still matches, so the assertions
    # above are not passing merely because the search space is empty.
    assert {e["tool"] for e in await repo.query(origin_class="local")} == {"structured"}
