from __future__ import annotations

import pytest

from argus.policy import evaluate, tool_is_visible
from db.models import ParamRule, ServerPolicy


def test_passthrough_always_allows():
    policy = ServerPolicy(mode="passthrough")
    decision = evaluate("anything", {}, "srv", policy)
    assert not decision.blocked


@pytest.mark.parametrize(
    "tool_name,allowed,expected_blocked",
    [
        ("read_file", ["read_file", "list_directory"], False),
        ("write_file", ["read_file", "list_directory"], True),
        ("read_file", [], True),
    ],
)
def test_allowlist_mode(tool_name, allowed, expected_blocked):
    policy = ServerPolicy(mode="allowlist", allowed=allowed)
    decision = evaluate(tool_name, {}, "srv", policy)
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
def test_denylist_mode(tool_name, denied, expected_blocked):
    policy = ServerPolicy(mode="denylist", denied=denied)
    decision = evaluate(tool_name, {}, "srv", policy)
    assert decision.blocked is expected_blocked
    if expected_blocked:
        assert decision.rule == "denylist"


def test_param_max_length_violation():
    policy = ServerPolicy(
        mode="allowlist",
        allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(max_length=10)}},
    )
    decision = evaluate("shell_run", {"command": "a" * 20}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "max_length"


def test_param_block_pattern_violation():
    policy = ServerPolicy(
        mode="allowlist",
        allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(block_patterns=[r"rm\s+-rf"])}},
    )
    decision = evaluate("shell_run", {"command": "rm -rf /"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "block_pattern"


def test_param_block_pattern_case_insensitive():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"shell_run": {"command": ParamRule(block_patterns=[r"sudo"])}},
    )
    decision = evaluate("shell_run", {"command": "SUDO rm foo"}, "srv", policy)
    assert decision.blocked


def test_param_denied_entirely():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"search_jobs": {"proxies": ParamRule(denied=True)}},
    )
    decision = evaluate("search_jobs", {"proxies": "http://evil"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "denied_param"


def test_param_max_value_violation():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"search_jobs": {"results_wanted": ParamRule(max_value=50)}},
    )
    decision = evaluate("search_jobs", {"results_wanted": 200}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "max_value"


def test_param_max_value_non_numeric_ignored():
    # Non-numeric value can't violate a numeric bound — should not raise, should not block.
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"search_jobs": {"results_wanted": ParamRule(max_value=50)}},
    )
    decision = evaluate("search_jobs", {"results_wanted": "not-a-number"}, "srv", policy)
    assert not decision.blocked


def test_param_min_value_violation():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"count": ParamRule(min_value=1)}},
    )
    decision = evaluate("tool", {"count": 0}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "min_value"


def test_param_rule_applies_regardless_of_mode():
    # Param validation runs even when the tool itself is allowed.
    policy = ServerPolicy(
        mode="allowlist",
        allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(block_patterns=[r"sudo"])}},
    )
    decision = evaluate("shell_run", {"command": "sudo ls"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "block_pattern"


def test_missing_param_not_checked():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"required_param": ParamRule(denied=True)}},
    )
    decision = evaluate("tool", {"other_param": "x"}, "srv", policy)
    assert not decision.blocked


def test_args_summary_truncates_long_values():
    policy = ServerPolicy(mode="passthrough")
    decision = evaluate("tool", {"secret": "x" * 200}, "srv", policy)
    assert decision.args_summary["secret"].endswith("[truncated]")
    assert len(decision.args_summary["secret"]) < 200


def test_args_summary_short_values_untouched():
    policy = ServerPolicy(mode="passthrough")
    decision = evaluate("tool", {"key": "short"}, "srv", policy)
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
