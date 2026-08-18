"""Unit tests for db/repo.py's unified policy assembly (#113).

get_policy is now a thin delegation to get_policies_for([id])[id] — one implementation of
ServerPolicy assembly instead of two copies that could drift on enforcement data (allowed/
denied lists and block_patterns are enforcement structures; two independent builders would
be a security-relevant duplication). These tests pin the parity contract across policy
shapes: no policy row, a saved-but-empty policy, and a fully-populated policy (allow/deny
lists, rate limit, param rules with block_patterns, DLP detectors + custom patterns).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from db.database import Database
from db.models import DlpCustomPattern, ParamRule, ServerPolicy
from db.repo import ServerRepo


@pytest.fixture
async def server_repo(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    yield ServerRepo(db)
    await db.close()


async def _assert_parity(server_repo: ServerRepo, server_id: int) -> None:
    single = await server_repo.get_policy(server_id)
    batched = (await server_repo.get_policies_for([server_id]))[server_id]
    assert single == batched


async def test_parity_with_no_policy_row(server_repo):
    """A server that has never had a policy saved: both paths return the same
    passthrough/no-rate-limit default, not raise."""
    server = await server_repo.create(slug="bare", name="bare", upstream_url="http://upstream:1")
    await _assert_parity(server_repo, server.id)
    policy = await server_repo.get_policy(server.id)
    assert policy.mode == "passthrough"
    assert policy.rate_limit is None
    assert policy.allowed == [] and policy.denied == []
    assert policy.param_rules == {}
    assert policy.dlp_detectors == {} and policy.dlp_custom_patterns == []


async def test_parity_with_default_policy_row(server_repo):
    """A saved-but-empty policy: the row exists but every list is empty — the shape a
    freshly-created server gets from set_policy with defaults."""
    server = await server_repo.create(slug="empty", name="empty", upstream_url="http://upstream:2")
    await server_repo.set_policy(server.id, ServerPolicy())
    await _assert_parity(server_repo, server.id)


async def test_parity_with_full_policy(server_repo):
    """Every field populated — allow/deny lists, rate limit, param rules with block_patterns,
    DLP detectors and custom patterns. This is the shape that exercises every decode in the
    assembly (block_patterns json.loads, dlp_config decode)."""
    server = await server_repo.create(slug="full", name="full", upstream_url="http://upstream:3")
    policy = ServerPolicy(
        mode="allowlist",
        rate_limit="10/minute",
        allowed=["tool_a", "tool_b"],
        denied=["tool_c"],
        param_rules={
            "tool_a": {
                "query": ParamRule(max_length=50, block_patterns=["(a+)+$", r"\b\d{4}\b"]),
                "limit": ParamRule(min_value=0, max_value=100),
            },
            "tool_b": {"secret": ParamRule(denied=True)},
        },
        dlp_detectors={"credit_card": "block", "email": "redact"},
        dlp_custom_patterns=[
            DlpCustomPattern(name="aws-key", pattern=r"AKIA[0-9A-Z]{16}", action="redact"),
        ],
    )
    await server_repo.set_policy(server.id, policy)
    await _assert_parity(server_repo, server.id)

    # The round-trip must also agree with the original on the fields enforcement reads use.
    loaded = await server_repo.get_policy(server.id)
    assert loaded.mode == "allowlist"
    assert loaded.rate_limit == "10/minute"
    assert sorted(loaded.allowed) == ["tool_a", "tool_b"]
    assert loaded.denied == ["tool_c"]
    assert loaded.param_rules["tool_a"]["query"].block_patterns == ["(a+)+$", r"\b\d{4}\b"]
    assert loaded.param_rules["tool_a"]["limit"].max_value == 100
    assert loaded.param_rules["tool_b"]["secret"].denied is True
    assert loaded.dlp_detectors == {"credit_card": "block", "email": "redact"}
    assert [p.name for p in loaded.dlp_custom_patterns] == ["aws-key"]
