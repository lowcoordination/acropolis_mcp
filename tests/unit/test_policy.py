from __future__ import annotations

import pytest

from argus.policy import evaluate, tool_is_visible
from db.models import ParamRule, ServerPolicy


async def test_passthrough_always_allows():
    policy = ServerPolicy(mode="passthrough")
    decision = await evaluate("anything", {}, "srv", policy)
    assert not decision.blocked


@pytest.mark.parametrize(
    "tool_name,allowed,expected_blocked",
    [
        ("read_file", ["read_file", "list_directory"], False),
        ("write_file", ["read_file", "list_directory"], True),
        ("read_file", [], True),
    ],
)
async def test_allowlist_mode(tool_name, allowed, expected_blocked):
    policy = ServerPolicy(mode="allowlist", allowed=allowed)
    decision = await evaluate(tool_name, {}, "srv", policy)
    assert decision.blocked is expected_blocked
    if expected_blocked:
        assert decision.rule == "allowlist"


@pytest.mark.parametrize(
    "tool_name,denied,expected_blocked",
    [
        ("delete_file", ["delete_file", "move_file"], True),
        ("read_file", ["delete_file", "move_file"], False),
        ("read_file", [], False),
    ],
)
async def test_denylist_mode(tool_name, denied, expected_blocked):
    policy = ServerPolicy(mode="denylist", denied=denied)
    decision = await evaluate(tool_name, {}, "srv", policy)
    assert decision.blocked is expected_blocked
    if expected_blocked:
        assert decision.rule == "denylist"


async def test_param_max_length_violation():
    policy = ServerPolicy(
        mode="allowlist",
        allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(max_length=10)}},
    )
    decision = await evaluate("shell_run", {"command": "a" * 20}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "max_length"


async def test_param_block_pattern_violation():
    policy = ServerPolicy(
        mode="allowlist",
        allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(block_patterns=[r"rm\s+-rf"])}},
    )
    decision = await evaluate("shell_run", {"command": "rm -rf /"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "block_pattern"


async def test_param_block_pattern_case_insensitive():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"shell_run": {"command": ParamRule(block_patterns=[r"sudo"])}},
    )
    decision = await evaluate("shell_run", {"command": "SUDO rm foo"}, "srv", policy)
    assert decision.blocked


async def test_param_denied_entirely():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"search_jobs": {"proxies": ParamRule(denied=True)}},
    )
    decision = await evaluate("search_jobs", {"proxies": "http://evil"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "denied_param"


async def test_param_max_value_violation():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"search_jobs": {"results_wanted": ParamRule(max_value=50)}},
    )
    decision = await evaluate("search_jobs", {"results_wanted": 200}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "max_value"


async def test_param_max_value_non_numeric_ignored():
    # Non-numeric value can't violate a numeric bound — should not raise, should not block.
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"search_jobs": {"results_wanted": ParamRule(max_value=50)}},
    )
    decision = await evaluate("search_jobs", {"results_wanted": "not-a-number"}, "srv", policy)
    assert not decision.blocked


async def test_param_min_value_violation():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"count": ParamRule(min_value=1)}},
    )
    decision = await evaluate("tool", {"count": 0}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "min_value"


async def test_param_rule_applies_regardless_of_mode():
    # Param validation runs even when the tool itself is allowed.
    policy = ServerPolicy(
        mode="allowlist",
        allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(block_patterns=[r"sudo"])}},
    )
    decision = await evaluate("shell_run", {"command": "sudo ls"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "block_pattern"


async def test_missing_param_not_checked():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"required_param": ParamRule(denied=True)}},
    )
    decision = await evaluate("tool", {"other_param": "x"}, "srv", policy)
    assert not decision.blocked


async def test_args_summary_truncates_long_values():
    policy = ServerPolicy(mode="passthrough")
    decision = await evaluate("tool", {"secret": "x" * 200}, "srv", policy)
    assert decision.args_summary["secret"].endswith("[truncated]")
    assert len(decision.args_summary["secret"]) < 200


async def test_args_summary_short_values_untouched():
    policy = ServerPolicy(mode="passthrough")
    decision = await evaluate("tool", {"key": "short"}, "srv", policy)
    assert decision.args_summary["key"] == "short"


@pytest.mark.parametrize(
    "mode,allowed,denied,tool_name,expected_visible",
    [
        ("passthrough", [], [], "any_tool", True),
        ("allowlist", ["read_file"], [], "read_file", True),
        ("allowlist", ["read_file"], [], "write_file", False),
        ("denylist", [], ["delete_file"], "delete_file", False),
        ("denylist", [], ["delete_file"], "read_file", True),
    ],
)
def test_tool_is_visible(mode, allowed, denied, tool_name, expected_visible):
    policy = ServerPolicy(mode=mode, allowed=allowed, denied=denied)
    assert tool_is_visible(tool_name, policy) is expected_visible


def test_param_rule_rejects_oversized_regex():
    with pytest.raises(ValueError):
        ParamRule(block_patterns=["a" * 201])


def test_param_rule_rejects_invalid_regex():
    with pytest.raises(ValueError):
        ParamRule(block_patterns=["["])


async def test_catastrophic_backtracking_pattern_times_out_instead_of_hanging():
    """The security-critical case: a pattern vulnerable to catastrophic backtracking must
    not be able to hang policy evaluation indefinitely. Confirmed manually before this fix
    that "(a+)+$" against 31 chars of crafted input hangs Python's `re` for >5s uninterrupted
    — well past what any request should wait. This test proves the fix bounds it.

    F2 fix (2026-08-04 review): a timed-out match is now UNDETERMINED, and _check_param treats
    UNDETERMINED on an operator-authored block_pattern rule as a match — i.e. BLOCKED, not
    allowed. The original fail-open design here was found to be silently defeatable under
    concurrent load (see test_policy_engine_blocks_under_concurrent_redos_flood below); failing
    closed on a rule the operator explicitly wrote is the corrected, documented trade-off."""
    import time

    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"(a+)+$"])}},
    )
    evil_input = "a" * 30 + "!"

    start = time.monotonic()
    decision = await evaluate("tool", {"value": evil_input}, "srv", policy)
    elapsed = time.monotonic() - start

    # Must return well before the pattern would naturally finish (which is many seconds/
    # unbounded) — the _REGEX_MATCH_TIMEOUT_SECONDS cap plus overhead, generously bounded.
    assert elapsed < 2.0
    assert decision.blocked
    assert decision.rule == "block_pattern_undetermined"


async def test_concurrent_backtracking_patterns_do_not_serialize():
    """Regression test for the shared-executor finding: block_pattern's wait must run on its
    own dedicated thread pool, not asyncio's process-wide default executor. If it shared the
    default pool, several concurrent pathological matches would serialize behind each other
    (and could stall unrelated run_in_executor(None, ...) work elsewhere in the process). Firing
    several at once and bounding total wall time proves they run concurrently instead.

    F2 fix: all should time out -> UNDETERMINED -> blocked (see the fail-open->fail-closed note
    on test_catastrophic_backtracking_pattern_times_out_instead_of_hanging above)."""
    import asyncio
    import time

    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"(a+)+$"])}},
    )
    evil_input = "a" * 30 + "!"

    start = time.monotonic()
    decisions = await asyncio.gather(
        *(evaluate("tool", {"value": evil_input}, "srv", policy) for _ in range(8))
    )
    elapsed = time.monotonic() - start

    # If these serialized on a starved shared pool, 8 * ~0.7s would blow well past this.
    # Running concurrently, total time should stay close to a single timeout's worth.
    assert elapsed < 2.5
    assert all(d.blocked for d in decisions)


async def test_policy_engine_does_not_fail_open_under_concurrent_redos_flood():
    """F2 regression test — reproduces the reviewer's exact probe. Pre-fix: asyncio.wait_for's
    timeout clock started at SUBMISSION to the 16-worker wait_executor, not at the point a
    match actually began waiting. With more than 16 concurrent pathological matches in flight,
    the 17th+ would sit queued in the executor's own backlog, burn its whole deadline before
    ever starting, and get treated identically to "the regex genuinely took too long" — i.e.
    silently allowed. The reviewer measured this directly: 40 concurrent ReDoS requests against
    one server let a completely UNRELATED server's must-block rule pass 10/10 requests that
    should have been blocked, logged as ALLOWED.

    This test fires well over _MAX_CONCURRENT_REGEX_CHECKS (16) pathological matches against a
    "flood" server concurrently with must-block requests against a separate "victim" server, and
    asserts every victim request is still blocked — proving the semaphore-before-process.start()
    fix actually closes the window, not just that a single match times out correctly."""
    import asyncio

    flood_policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"(a+)+$"])}},
    )
    victim_policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"^BLOCK_ME$"])}},
    )
    evil_input = "a" * 30 + "!"

    async def flood_request():
        return await evaluate("tool", {"value": evil_input}, "flood-server", flood_policy)

    async def victim_request():
        return await evaluate("tool", {"value": "BLOCK_ME"}, "victim-server", victim_policy)

    # 40 flood requests (well over the 16-worker pool) racing 10 victim requests, all fired
    # concurrently via gather — not sequentially, which is what let this bug hide in every
    # prior test in this suite.
    flood_tasks = [flood_request() for _ in range(40)]
    victim_tasks = [victim_request() for _ in range(10)]
    results = await asyncio.gather(*flood_tasks, *victim_tasks)
    victim_decisions = results[40:]

    assert all(d.blocked for d in victim_decisions), (
        f"expected 10/10 victim requests blocked, got "
        f"{sum(1 for d in victim_decisions if d.blocked)}/10 — policy engine failed open "
        f"under concurrent ReDoS load"
    )
