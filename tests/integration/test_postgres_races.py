"""Race coverage for every converted `gateway_write_lock` call site (enterprise #7, issue #8).

WHY THIS FILE EXISTS. Before the Postgres cutover, every write path in db/repo.py and
argus/toolslist.py ran inside `async with db.gateway_write_lock` — a per-process asyncio.Lock
that serialized all writes because SQLite has exactly one writer. That lock is deleted. Deleting
a lock is the single easiest way to ship a TOCTOU into code that never had to survive concurrency
before, so the plan's requirement is explicit: every converted site gets a barrier-synchronized
race test PROVING the replacement shape actually closes the race, rather than an argument that it
ought to.

Each test here drives two (or more) tasks at the same code path, released simultaneously from an
asyncio.Barrier so they collide as tightly as the event loop allows, and asserts the invariant the
lock used to provide. The replacement shapes under test — [TRANSACTION], [UPSERT], [ATOMIC-RMW],
[SINGLE-STATEMENT] — are named in db/repo.py's conversion-audit header and at each call site.

A note on what these tests can and cannot prove: a passing race test does not prove the absence of
a race (interleavings are scheduler-dependent). What it does prove is that the invariant holds
under real simultaneous pressure against a real Postgres, and — crucially — several of these
tests FAIL against a naive lock-removal. They are regression guards for the specific mistakes this
cutover could have made, not a formal proof.

The two-real-instances test (two separate Database objects, two separate pool sets, ONE Postgres
database) lives in test_postgres_concurrency.py — that one is about multi-replica behaviour, which
the in-process lock could never have provided at all. This file is about per-call-site correctness.
"""

from __future__ import annotations

import asyncio

import pytest

from db.database import Database
from db.models import ServerPolicy
from db.repo import (
    AdminEventRepo,
    ApiKeyRepo,
    ProjectMemberRepo,
    ProjectRepo,
    ProjectSlugConflictError,
    ServerRepo,
    SettingsRepo,
    SlugConflictError,
    UsageRepo,
    UserNotFoundError,
    UsernameConflictError,
    UserRepo,
)


@pytest.fixture
async def db(pg_dsn):
    database = Database(pg_dsn)
    await database.connect()
    yield database
    await database.close()


async def _run_barriered(n: int, make_coro):
    """Release `n` tasks simultaneously from a barrier and gather their results/exceptions.

    The barrier is the point of the whole file: without it, task 1 typically runs to completion
    before task 2 is scheduled, and the test silently proves nothing. With it, every task is
    parked at the same instant and released together, so they enter the code path under test as
    close to simultaneously as asyncio permits.
    """
    barrier = asyncio.Barrier(n)

    async def _one(i: int):
        await barrier.wait()
        return await make_coro(i)

    return await asyncio.gather(*(_one(i) for i in range(n)), return_exceptions=True)


class TestServerCreateRace:
    """ServerRepo.create — [TRANSACTION + UNIQUE-violation catch].

    The old lock made check-slug-then-INSERT atomic within one process. The replacement relies on
    `servers.slug UNIQUE` plus converting the violation to SlugConflictError, so the loser of a
    race sees the same typed error as a caller who never raced at all.
    """

    async def test_concurrent_same_slug_yields_exactly_one_server_and_one_typed_conflict(self, db):
        repo = ServerRepo(db)

        results = await _run_barriered(
            8,
            lambda i: repo.create(
                slug="contended", name=f"attempt-{i}", upstream_url="http://u.test"
            ),
        )

        created = [r for r in results if not isinstance(r, BaseException)]
        conflicts = [r for r in results if isinstance(r, SlugConflictError)]
        other = [
            r for r in results
            if isinstance(r, BaseException) and not isinstance(r, SlugConflictError)
        ]

        assert other == [], f"race produced non-SlugConflictError exceptions: {other!r}"
        assert len(created) == 1, f"expected exactly one winner, got {len(created)}"
        assert len(conflicts) == 7

        # And exactly one row actually exists — no duplicate slid past the constraint.
        servers = await repo.list()
        assert [s.slug for s in servers] == ["contended"]

    async def test_paired_policy_row_is_never_missing_after_concurrent_creates(self, db):
        """The transaction half: create() writes `servers` AND its paired `server_policies` row.
        A create that committed the server but not the policy row would leave a server whose
        policy silently defaults — the atomicity the lock used to provide."""
        repo = ServerRepo(db)

        await _run_barriered(
            6,
            lambda i: repo.create(
                slug=f"srv-{i}", name=f"s{i}", upstream_url="http://u.test"
            ),
        )

        servers = await repo.list()
        assert len(servers) == 6
        policies = await repo.get_policies_for([s.id for s in servers])
        for s in servers:
            # A missing policy row would fall back to the passthrough default and be
            # indistinguishable here, so assert the ROW exists rather than the resolved value.
            assert policies[s.id].mode == "passthrough"
        async with db.reader.acquire() as conn:
            n = await conn.fetchval("SELECT COUNT(*) FROM server_policies")
        assert n == 6, "every created server must have its paired policy row"


class TestPolicyWriteRace:
    """ServerRepo.set_policy — [TRANSACTION].

    THE motivating case for the whole pre-cutover F7 machinery: set_policy does
    DELETE-then-reinsert across three tables, and a reader catching the gap saw an EMPTY denylist
    — the gateway transiently failing open on every policy save.
    """

    async def test_concurrent_reader_never_observes_an_empty_denylist(self, db):
        repo = ServerRepo(db)
        server = await repo.create(slug="pol", name="pol", upstream_url="http://u.test")

        denied = [f"tool-{i}" for i in range(40)]
        await repo.set_policy(server.id, ServerPolicy(mode="denylist", denied=denied))

        stop = asyncio.Event()
        observations: list[int] = []

        async def writer():
            # Rewrite the same policy repeatedly — each rewrite is a DELETE of all 40 rows
            # followed by 40 INSERTs, i.e. a wide window for a reader to fall into.
            for _ in range(25):
                await repo.set_policy(server.id, ServerPolicy(mode="denylist", denied=denied))
            stop.set()

        async def reader():
            while not stop.is_set():
                policy = await repo.get_policy(server.id)
                observations.append(len(policy.denied))
                await asyncio.sleep(0)

        await asyncio.gather(writer(), reader())

        assert observations, "reader never sampled — test proved nothing"
        # The invariant: a reader sees the full denylist or the full denylist. Never a partial
        # one, and above all never an empty one (which would mean "deny nothing" — fail open).
        assert set(observations) == {40}, (
            f"reader observed partially-applied policy states: {sorted(set(observations))}. "
            "A value of 0 means the gateway transiently failed open mid-write."
        )

    async def test_concurrent_set_policy_leaves_a_consistent_final_state(self, db):
        repo = ServerRepo(db)
        server = await repo.create(slug="pol2", name="pol2", upstream_url="http://u.test")

        async def write(i: int):
            return await repo.set_policy(
                server.id,
                ServerPolicy(mode="denylist", denied=[f"w{i}-a", f"w{i}-b"]),
            )

        results = await _run_barriered(6, write)
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent set_policy raised: {errors!r}"

        # Last writer wins wholesale — the final state must be exactly ONE writer's payload,
        # never a mixture of two writers' tools (which is what a torn read-modify-write looks
        # like).
        final = await repo.get_policy(server.id)
        assert len(final.denied) == 2
        prefixes = {t.split("-")[0] for t in final.denied}
        assert len(prefixes) == 1, f"final policy mixes two writers' payloads: {final.denied}"


class TestUsageIncrementRace:
    """UsageRepo.increment — [UPSERT].

    The hottest write in the system (once per forwarded tools/call) and a textbook lost-update
    shape: "add N to this bucket". Correctness comes from expressing the increment against the
    STORED value inside one statement, so concurrent callers serialize on the row.
    """

    async def test_concurrent_increments_lose_nothing(self, db):
        repo = UsageRepo(db)
        ts = "2026-08-09T14:30:00+00:00"

        n = 60
        results = await _run_barriered(
            n,
            lambda i: repo.increment(ts_iso=ts, api_key_id=7, server_id=3, tool="search"),
        )
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent increment raised: {errors!r}"

        total = await repo.total_since(api_key_id=7, since_iso="2026-08-09T00:00:00+00:00")
        assert total == n, (
            f"lost update: fired {n} concurrent increments, bucket holds {total}. "
            "A count below N means two callers read the same value and both wrote value+1."
        )

    async def test_concurrent_first_increments_create_exactly_one_bucket_row(self, db):
        """The upsert's INSERT half racing itself: N callers all find no row and all try to
        create it. Exactly one row must exist, holding the full total."""
        repo = UsageRepo(db)
        ts = "2026-08-09T15:00:00+00:00"

        n = 30
        await _run_barriered(
            n, lambda i: repo.increment(ts_iso=ts, api_key_id=9, server_id=1, tool="fresh")
        )

        rows = await repo.query(api_key_id=9, tool="fresh")
        assert len(rows) == 1, f"expected one bucket row, got {len(rows)}"
        assert rows[0]["calls"] == n


class TestSessionVersionRace:
    """UserRepo.bump_session_version — [ATOMIC-RMW].

    A genuine lost-update with security consequences: the old shape was UPDATE, COMMIT, then a
    SEPARATE SELECT to read the new value, with the lock as the only thing stopping another
    bumper from committing in between and making this caller return the OTHER caller's version.
    That returned value is written into a freshly-issued session token.
    """

    async def test_concurrent_bumps_return_distinct_versions_and_lose_no_increments(self, db):
        users = UserRepo(db)
        user = await users.create(username="racer", role="admin", password_hash="x")

        n = 25
        results = await _run_barriered(n, lambda i: users.bump_session_version(user.id))
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent bump raised: {errors!r}"

        # Every caller must have received the value ITS OWN statement wrote — so the returned
        # values are exactly 1..N with no duplicates. A duplicate means two callers were handed
        # the same session_version, i.e. one of them read the other's write.
        assert sorted(results) == list(range(1, n + 1)), (
            f"bumps returned non-distinct or non-sequential versions: {sorted(results)}"
        )

        refreshed = await users.get_by_id(user.id)
        assert refreshed.session_version == n


class TestUserCreateRace:
    """UserRepo.create — [TRANSACTION + UNIQUE-violation catch].

    Notably, the pre-cutover code ALREADY documented a race the lock did not close (two
    simultaneous OIDC JIT provisions for the same new `sub`), and already handled it by catching
    the UNIQUE violation. This test covers both the username and oidc_subject constraints.
    """

    async def test_concurrent_same_username_yields_one_user_and_typed_conflicts(self, db):
        users = UserRepo(db)

        results = await _run_barriered(
            8, lambda i: users.create(username="dupe", role="viewer", password_hash=f"h{i}")
        )

        created = [r for r in results if not isinstance(r, BaseException)]
        conflicts = [r for r in results if isinstance(r, UsernameConflictError)]
        other = [
            r for r in results
            if isinstance(r, BaseException) and not isinstance(r, UsernameConflictError)
        ]

        assert other == [], f"race produced unexpected exceptions: {other!r}"
        assert len(created) == 1
        assert len(conflicts) == 7
        assert len(await users.list()) == 1

    async def test_concurrent_oidc_jit_provisioning_converges_on_one_user(self, db):
        """Two simultaneous "Sign in with SSO" for the same brand-new subject. Both pass the
        `existing is None` check; the oidc_subject UNIQUE constraint is the real backstop, and
        get_or_create_from_oidc's retry loop must converge both callers on the SAME user rather
        than creating two or raising."""
        users = UserRepo(db)

        results = await _run_barriered(
            6,
            lambda i: users.get_or_create_from_oidc(
                subject="sub-abc-123", email="person@example.test", default_role="viewer"
            ),
        )
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent JIT provisioning raised: {errors!r}"

        ids = {r.id for r in results}
        assert len(ids) == 1, f"JIT provisioning created {len(ids)} users for one subject"

        all_users = await users.list()
        subjects = [u.oidc_subject for u in all_users if u.oidc_subject == "sub-abc-123"]
        assert len(subjects) == 1


class TestProjectCreateRace:
    """ProjectRepo.create — [TRANSACTION + UNIQUE-violation catch]. Same shape as server create."""

    async def test_concurrent_same_slug_yields_one_project_and_typed_conflicts(self, db):
        projects = ProjectRepo(db)

        results = await _run_barriered(
            6, lambda i: projects.create(slug="shared-proj", name=f"p{i}")
        )

        created = [r for r in results if not isinstance(r, BaseException)]
        conflicts = [r for r in results if isinstance(r, ProjectSlugConflictError)]
        other = [
            r for r in results
            if isinstance(r, BaseException) and not isinstance(r, ProjectSlugConflictError)
        ]

        assert other == [], f"race produced unexpected exceptions: {other!r}"
        assert len(created) == 1
        assert len(conflicts) == 5


class TestMembershipRace:
    """ProjectMemberRepo.upsert / remove — [UPSERT] / [SINGLE-STATEMENT].

    Membership changes are an authorization surface: a torn write here means a user with the
    wrong project role, or a duplicate membership row that makes "what is this user's role"
    ambiguous.
    """

    async def test_concurrent_role_writes_leave_exactly_one_membership_row(self, db):
        users = UserRepo(db)
        projects = ProjectRepo(db)
        members = ProjectMemberRepo(db)

        user = await users.create(username="member", role="viewer", password_hash="x")
        project = await projects.create(slug="team-a", name="Team A")

        roles = ["viewer", "poweruser", "admin"]
        results = await _run_barriered(
            9,
            lambda i: members.upsert(
                user_id=user.id, project_id=project.id, role=roles[i % len(roles)]
            ),
        )
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent membership upsert raised: {errors!r}"

        rows = await members.list_for_project(project.id)
        assert len(rows) == 1, f"expected one membership row, got {len(rows)}"
        # Last writer wins, and the surviving role must be one that was actually written —
        # never a torn/absent value.
        assert rows[0].role in roles

    async def test_concurrent_add_and_remove_never_leaves_a_duplicate(self, db):
        users = UserRepo(db)
        projects = ProjectRepo(db)
        members = ProjectMemberRepo(db)

        user = await users.create(username="churn", role="viewer", password_hash="x")
        project = await projects.create(slug="team-b", name="Team B")

        async def churn(i: int):
            if i % 2 == 0:
                return await members.upsert(
                    user_id=user.id, project_id=project.id, role="viewer"
                )
            return await members.remove(user_id=user.id, project_id=project.id)

        results = await _run_barriered(10, churn)
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent add/remove raised: {errors!r}"

        rows = await members.list_for_project(project.id)
        assert len(rows) <= 1, f"membership duplicated under churn: {rows!r}"


class TestSettingsAtomicity:
    """SettingsRepo.set_many — [TRANSACTION]; SettingsRepo.set — [UPSERT].

    set_many exists SPECIFICALLY for cross-key atomicity: the setup wizard writes
    admin_password_hash + session_secret + auth_mode as one unit, and a reader must never catch
    a state where the password is set but the session secret isn't.
    """

    async def test_reader_never_observes_a_partial_set_many(self, db):
        settings = SettingsRepo(db)
        keys = [f"k{i}" for i in range(12)]

        stop = asyncio.Event()
        partials: list[int] = []

        async def writer():
            for gen in range(20):
                await settings.set_many({k: f"gen-{gen}" for k in keys})
            stop.set()

        async def reader():
            while not stop.is_set():
                snapshot = await settings.get_all()
                present = [snapshot[k] for k in keys if k in snapshot]
                if present:
                    # Every key present must carry the SAME generation — a mixture means the
                    # reader caught a half-applied batch.
                    partials.append(len(set(present)))
                await asyncio.sleep(0)

        await asyncio.gather(writer(), reader())

        assert partials, "reader never sampled — test proved nothing"
        assert set(partials) == {1}, (
            "reader observed a set_many batch half-applied (keys from two generations at once)"
        )

    async def test_concurrent_set_on_same_key_never_errors_and_lands_a_real_value(self, db):
        settings = SettingsRepo(db)

        results = await _run_barriered(20, lambda i: settings.set("contended_key", f"v{i}"))
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent settings.set raised: {errors!r}"

        value = await settings.get("contended_key")
        assert value in {f"v{i}" for i in range(20)}


class TestApiKeyWriteRaces:
    """ApiKeyRepo.create / set_enabled / set_quota / delete / touch_last_used.

    create is [TRANSACTION]; the rest are [SINGLE-STATEMENT]. Grouped because they share a table
    and the interesting failure is cross-method (e.g. a delete racing a quota write).
    """

    async def test_concurrent_key_creates_all_succeed_with_distinct_ids(self, db):
        keys = ApiKeyRepo(db)

        results = await _run_barriered(
            12,
            lambda i: keys.create(
                name=f"key-{i}", key_hash=f"hash-{i}", key_prefix=f"pfx{i}"
            ),
        )
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent key create raised: {errors!r}"

        ids = {r.id for r in results}
        assert len(ids) == 12, "RETURNING id handed two creates the same row id"
        assert len(await keys.list()) == 12

    async def test_duplicate_key_hash_is_rejected_by_the_unique_constraint(self, db):
        """key_hash UNIQUE is a security control — two keys sharing a hash would make
        get_by_hash ambiguous. The lock never enforced this; the constraint always did."""
        keys = ApiKeyRepo(db)

        results = await _run_barriered(
            5,
            lambda i: keys.create(
                name=f"dup-{i}", key_hash="identical-hash", key_prefix="pfx"
            ),
        )
        created = [r for r in results if not isinstance(r, BaseException)]
        assert len(created) == 1, f"expected one winner, got {len(created)}"
        assert len(await keys.list()) == 1

    async def test_concurrent_enable_disable_and_quota_writes_stay_consistent(self, db):
        keys = ApiKeyRepo(db)
        key = await keys.create(name="k", key_hash="h", key_prefix="p")

        async def churn(i: int):
            if i % 3 == 0:
                return await keys.set_enabled(key.id, i % 2 == 0)
            if i % 3 == 1:
                return await keys.set_quota(key.id, quota_calls=i, quota_period="day")
            return await keys.touch_last_used(key.id)

        results = await _run_barriered(15, churn)
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent key writes raised: {errors!r}"

        # quota_calls/quota_period are written together and must never end up half-set.
        refreshed = await keys.get_by_id(key.id)
        assert (refreshed.quota_calls is None) == (refreshed.quota_period is None), (
            f"half-written quota state: calls={refreshed.quota_calls} "
            f"period={refreshed.quota_period}"
        )


class TestServerUpdateAndHealthRaces:
    """ServerRepo.update / set_project / delete — [SINGLE-STATEMENT];
    ServerRepo.set_health — [ATOMIC-RMW] (COALESCE reads the stored value in-statement)."""

    async def test_concurrent_health_writes_never_lose_coalesced_columns(self, db):
        repo = ServerRepo(db)
        server = await repo.create(slug="hp", name="hp", upstream_url="http://u.test")

        # Seed the COALESCE'd columns, then hammer with probes that pass None for them — the
        # COALESCE must preserve the stored value on every one, never null it out.
        await repo.set_health("hp", "healthy", upstream_protocol="2025-06-18",
                              discover_json='{"seeded": true}')

        async def probe(i: int):
            return await repo.set_health(
                "hp", "healthy" if i % 2 == 0 else "unhealthy", health_reason=f"r{i}"
            )

        results = await _run_barriered(12, probe)
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent set_health raised: {errors!r}"

        final = await repo.get("hp")
        assert final.upstream_protocol == "2025-06-18", (
            "COALESCE'd column was nulled by a concurrent probe passing None"
        )
        assert final.discover_json == '{"seeded": true}'
        assert final.health_status in {"healthy", "unhealthy"}

    async def test_concurrent_field_updates_do_not_clobber_each_other(self, db):
        """update() builds a dynamic SET list from only the fields the caller supplied. Two
        callers updating DIFFERENT fields must both survive — a naive read-modify-write
        (read the row, write every field back) would silently drop one."""
        repo = ServerRepo(db)
        await repo.create(slug="upd", name="orig", upstream_url="http://orig.test")

        async def go(i: int):
            if i % 2 == 0:
                return await repo.update("upd", name=f"name-{i}")
            return await repo.update("upd", in_aggregate=False)

        results = await _run_barriered(8, go)
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent update raised: {errors!r}"

        final = await repo.get("upd")
        assert final.name.startswith("name-")
        assert final.in_aggregate is False, (
            "a name-only update clobbered a concurrent in_aggregate update"
        )
        # The field NEITHER caller touched must be untouched.
        assert final.upstream_url == "http://orig.test"

    async def test_concurrent_delete_and_update_never_raises_unexpectedly(self, db):
        repo = ServerRepo(db)
        await repo.create(slug="doomed", name="d", upstream_url="http://u.test")

        async def go(i: int):
            if i == 0:
                return await repo.delete("doomed")
            return await repo.update("doomed", name=f"n{i}")

        results = await _run_barriered(5, go)
        # A racing update against a just-deleted server legitimately raises ServerNotFoundError
        # (the row is gone). Anything else — a driver error, an FK violation from the cascade —
        # would be a real bug.
        from db.repo import ServerNotFoundError

        unexpected = [
            r for r in results
            if isinstance(r, BaseException) and not isinstance(r, ServerNotFoundError)
        ]
        assert unexpected == [], f"delete/update race raised unexpectedly: {unexpected!r}"
        assert await repo.list() == []


class TestAdminEventRace:
    """AdminEventRepo.insert — [SINGLE-STATEMENT] with RETURNING id.

    lastrowid (the pre-cutover mechanism) read a CONNECTION-WIDE "last inserted rowid", not the
    statement's own — it was only ever correct because the lock serialized writers. RETURNING is
    per-statement by definition, so this test guards the exact thing lastrowid could get wrong.
    """

    async def test_concurrent_inserts_return_distinct_ids_and_persist_every_row(self, db):
        events = AdminEventRepo(db)

        n = 20
        results = await _run_barriered(
            n,
            lambda i: events.insert(
                action="server.create", summary=f"created {i}", target_id=f"s{i}"
            ),
        )
        errors = [r for r in results if isinstance(r, BaseException)]
        assert errors == [], f"concurrent admin-event insert raised: {errors!r}"

        assert len(set(results)) == n, (
            f"two concurrent inserts returned the same id: {sorted(results)}. "
            "This is exactly the failure mode lastrowid had without the write lock."
        )
        stored = await events.query(limit=500)
        assert len(stored) == n, "an admin event was lost under concurrent insert"


class TestToolsCacheRace:
    """ToolsCache._store / invalidate (argus/toolslist.py) — [TRANSACTION] / [SINGLE-STATEMENT].

    Same DELETE-then-N-INSERT shape as set_policy: a reader catching the gap sees a server with
    NO tools, which surfaces to a client as an empty tools/list.
    """

    async def test_concurrent_reader_never_sees_an_empty_tool_list(self, db):
        from argus.toolslist import ToolsCache

        repo = ServerRepo(db)
        server = await repo.create(slug="tc", name="tc", upstream_url="http://u.test")
        cache = ToolsCache(db, bridge=None)  # bridge unused: _store is called directly

        tools = [{"name": f"tool-{i}", "description": "d"} for i in range(30)]
        await cache._store(server.id, tools, ttl_ms=60_000, cache_scope=None)

        stop = asyncio.Event()
        observations: list[int] = []

        async def writer():
            for _ in range(20):
                await cache._store(server.id, tools, ttl_ms=60_000, cache_scope=None)
            stop.set()

        async def reader():
            while not stop.is_set():
                rows = await cache._cached_rows(server.id)
                observations.append(len(rows))
                await asyncio.sleep(0)

        await asyncio.gather(writer(), reader())

        assert observations, "reader never sampled — test proved nothing"
        assert set(observations) == {30}, (
            f"reader observed a partially-rebuilt tools cache: {sorted(set(observations))}. "
            "0 would surface to a client as a server with no tools at all."
        )

    async def test_duplicate_tool_names_in_one_response_do_not_abort_the_refresh(self, db):
        """The ON CONFLICT DO UPDATE added during the port: an upstream advertising the same tool
        name twice used to abort the whole transaction on a primary-key violation, leaving the
        cache EMPTY rather than merely imperfect."""
        from argus.toolslist import ToolsCache

        repo = ServerRepo(db)
        server = await repo.create(slug="dup", name="dup", upstream_url="http://u.test")
        cache = ToolsCache(db, bridge=None)

        tools = [
            {"name": "same", "description": "first"},
            {"name": "same", "description": "second"},
            {"name": "other", "description": "d"},
        ]
        await cache._store(server.id, tools, ttl_ms=None, cache_scope=None)

        rows = await cache._cached_rows(server.id)
        names = sorted(r["tool_name"] for r in rows)
        assert names == ["other", "same"], f"refresh lost rows on duplicate name: {names}"
