"""Unit tests for db/repo.py's UserRepo — focused on the self-review fix for a concurrent
oidc_subject collision in get_or_create_from_oidc (see that method's own comment)."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from db.database import Database
from db.repo import UsernameConflictError, UserRepo


@pytest.fixture
async def user_repo(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    yield UserRepo(db)
    await db.close()


async def test_create_rejects_duplicate_username(user_repo):
    await user_repo.create(username="dup", role="viewer", password_hash="h")
    with pytest.raises(UsernameConflictError):
        await user_repo.create(username="dup", role="viewer", password_hash="h2")


async def test_create_rejects_duplicate_oidc_subject_even_with_different_username(user_repo):
    """Self-review fix: the pre-flight check in create() only looks at username, but the
    oidc_subject UNIQUE constraint is a second, independent uniqueness rule. Before the fix,
    violating it raised an unhandled aiosqlite.IntegrityError instead of the same
    UsernameConflictError every other conflict path raises."""
    await user_repo.create(
        username="alice", role="viewer", auth_source="oidc", oidc_subject="same-subject",
    )
    with pytest.raises(UsernameConflictError):
        await user_repo.create(
            username="alice-different-name", role="viewer",
            auth_source="oidc", oidc_subject="same-subject",
        )


async def test_concurrent_jit_provisioning_for_same_subject_resolves_to_one_user(user_repo):
    """Simulates two simultaneous OIDC callbacks for the same brand-new `sub` (a double-clicked
    SSO button, or two tabs) racing through get_or_create_from_oidc's `existing is None` check
    before either has committed. Both calls must succeed and resolve to the SAME user id — not
    error out, and not silently create two rows for one subject."""
    results = await asyncio.gather(
        user_repo.get_or_create_from_oidc(
            subject="racing-subject", email="racer@example.com", default_role="viewer",
            preferred_username="racer",
        ),
        user_repo.get_or_create_from_oidc(
            subject="racing-subject", email="racer@example.com", default_role="viewer",
            preferred_username="racer",
        ),
    )
    assert results[0].id == results[1].id

    all_users = await user_repo.list()
    matching = [u for u in all_users if u.oidc_subject == "racing-subject"]
    assert len(matching) == 1, f"expected exactly one user for the racing subject, got {len(matching)}"
