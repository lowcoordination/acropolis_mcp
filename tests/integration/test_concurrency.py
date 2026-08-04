"""
Concurrency regression tests for the 2026-08-04 external security review's Plan 2 findings
(F2, F7).

The review's own top-level critique of the existing suite: every prior test is strictly
sequential (e.g. rate-limit tests fire N requests in a `for` loop), so races in the policy
engine and the repo layer were invisible by construction. These tests exist specifically to
close that gap — they interleave real concurrent operations via asyncio.gather rather than
awaiting each one in turn.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from db.database import Database
from db.models import ServerPolicy
from db.repo import ApiKeyRepo, ServerRepo


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


# ---------------------------------------------------------------------------
# F7 — no transaction isolation on the shared SQLite connection
# ---------------------------------------------------------------------------

class TestF7TransactionIsolation:
    async def test_set_policy_never_observes_a_transiently_empty_denylist(self, db):
        """The exact failure mode from the review: set_policy does DELETE-then-reinsert across
        tool_policies. If a concurrent writer's commit() could land mid-way (the pre-fix
        behaviour, since every repo method shared one connection with no lock/transaction),
        a reader hitting get_policy() in that window would see an empty denylist — the gateway
        transiently passes through everything it was configured to block.

        This test doesn't just check the FINAL state is correct (that would pass even with the
        race, since both writes eventually complete) — it polls get_policy() concurrently with
        the write and asserts the denylist is NEVER observed empty once it has been set at
        least once.
        """
        server_repo = ServerRepo(db)
        server = await server_repo.create(slug="test-server", name="Test", upstream_url="http://x/mcp")

        # Establish a real, non-empty denylist first.
        await server_repo.set_policy(
            server.id,
            ServerPolicy(mode="denylist", denied=["shell_run", "write_file", "delete_all"]),
        )

        observed_empty = False
        stop = asyncio.Event()

        async def reader_loop():
            nonlocal observed_empty
            while not stop.is_set():
                policy = await server_repo.get_policy(server.id)
                if policy.mode == "denylist" and len(policy.denied) == 0:
                    observed_empty = True
                    return
                await asyncio.sleep(0)

        async def repeated_writer():
            # Re-save the same denylist repeatedly — each save internally does
            # DELETE FROM tool_policies then re-INSERTs. A concurrent reader must never
            # observe the gap between those two steps.
            for _ in range(50):
                await server_repo.set_policy(
                    server.id,
                    ServerPolicy(mode="denylist", denied=["shell_run", "write_file", "delete_all"]),
                )

        reader_task = asyncio.create_task(reader_loop())
        await repeated_writer()
        stop.set()
        await reader_task

        assert not observed_empty, (
            "get_policy() observed a transiently empty denylist during a concurrent "
            "set_policy() write — the gateway would fail open during a policy save"
        )

    async def test_concurrent_set_policy_calls_do_not_corrupt_final_state(self, db):
        """Fire many concurrent set_policy calls (interleaved via gather, not sequential awaits)
        against the same server and confirm the final state is exactly one of the written
        policies, not a merge/corruption of several."""
        server_repo = ServerRepo(db)
        server = await server_repo.create(slug="test-server", name="Test", upstream_url="http://x/mcp")

        policies = [
            ServerPolicy(mode="denylist", denied=[f"tool_{i}"]) for i in range(10)
        ]

        await asyncio.gather(*(server_repo.set_policy(server.id, p) for p in policies))

        final = await server_repo.get_policy(server.id)
        assert final.mode == "denylist"
        # Exactly one of the ten policies' single denied tool should be present — not a
        # concatenation of several (which the old DELETE-then-N-INSERT race, run concurrently
        # without a lock, could produce) and not empty.
        assert len(final.denied) == 1
        assert final.denied[0].startswith("tool_")

    async def test_create_and_touch_last_used_do_not_deadlock_or_corrupt(self, db):
        """touch_last_used no longer commits on every call (debounced), but it still shares
        gateway.db with the write-locked create()/set_policy() paths. Confirm high-concurrency
        mixed traffic completes without deadlocking or leaving a corrupted row."""
        server_repo = ServerRepo(db)
        key_repo = ApiKeyRepo(db)
        key = await key_repo.create(name="test-key", key_hash="x" * 64, key_prefix="acropolis_x")

        async def make_server(i: int):
            await server_repo.create(slug=f"srv-{i}", name=f"Server {i}", upstream_url="http://x/mcp")

        async def touch():
            for _ in range(20):
                await key_repo.touch_last_used(key.id)

        await asyncio.wait_for(
            asyncio.gather(*(make_server(i) for i in range(10)), touch(), touch()),
            timeout=10.0,
        )

        servers = await server_repo.list()
        assert len(servers) == 10
        assert {s.slug for s in servers} == {f"srv-{i}" for i in range(10)}


# ---------------------------------------------------------------------------
# F2 — policy engine fails open under concurrency
# ---------------------------------------------------------------------------
#
# NOTE: F2's own regression test (concurrent ReDoS floods vs. an unrelated must-block request)
# requires driving argus.policy._match_with_timeout's real forkserver-based subprocess pool
# under load, which needs to run as a real module (not inline) and is exercised directly in
# tests/unit/test_policy.py once the F2 fix lands. See 02-enforcement-and-internet-facing.md
# for why: the tri-state undetermined/block-on-timeout rewrite changes what "no test covers
# this" means, and the concurrency probe belongs next to the rest of the policy timeout tests
# rather than duplicated here.
