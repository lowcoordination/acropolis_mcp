from __future__ import annotations

import pytest

from argus.policy import (
    MatchOutcome,
    _finditer_spans_with_timeout,
    evaluate,
    summarize_args,
    tool_is_visible,
)
from db.models import DlpCustomPattern, ParamRule, ServerPolicy


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
    decision = await evaluate("tool", {"path": "x" * 200}, "srv", policy)
    assert decision.args_summary["path"].endswith("[truncated]")
    assert len(decision.args_summary["path"]) < 200


async def test_args_summary_short_values_untouched():
    policy = ServerPolicy(mode="passthrough")
    decision = await evaluate("tool", {"path": "short"}, "srv", policy)
    assert decision.args_summary["path"] == "short"


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

    The pattern here is deliberately re2-INCOMPATIBLE (a backreference, `\1`): with the #112
    re2 fast path, any pattern re2 accepts (including the classic "(a+)+$") is matched inline
    in linear time and needs no timeout at all. The process/timeout path still exists for the
    patterns re2 rejects, and this is the test that exercises it — the backreference keeps the
    pattern on that path while still being able to hang Python's `re`.

    F2 fix (2026-08-04 review): a timed-out match is now UNDETERMINED, and _check_param treats
    UNDETERMINED on an operator-authored block_pattern rule as a match — i.e. BLOCKED, not
    allowed. The original fail-open design here was found to be silently defeatable under
    concurrent load (see test_policy_engine_blocks_under_concurrent_redos_flood below); failing
    closed on a rule the operator explicitly wrote is the corrected, documented trade-off."""
    import time

    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"^(a*)*\1$"])}},
    )
    evil_input = "a" * 30 + "b"

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
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"^(a*)*\1$"])}},
    )
    evil_input = "a" * 30 + "b"

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
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"^(a*)*\1$"])}},
    )
    victim_policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": ParamRule(block_patterns=[r"^BLOCK_ME$"])}},
    )
    evil_input = "a" * 30 + "b"

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


# ---------------------------------------------------------------------------
# §26 — summarize_args redacts by key name, not just length (review 2026-08-04)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "key", ["password", "api_key", "apiKey", "token", "access_token", "Authorization", "secret"]
)
def test_summarize_args_redacts_sensitive_keys_regardless_of_length(key):
    """Regression: the old implementation only truncated by LENGTH ('value[:120]'), so a short
    secret (an 8-character API key, a PIN) sailed straight into the audit log untouched. A
    sensitive key name must be redacted outright, not merely left short enough to survive
    truncation."""
    summary = summarize_args({key: "shortsecret"})
    assert summary[key] == "[redacted]"


def test_summarize_args_still_truncates_long_non_sensitive_values():
    long_value = "x" * 200
    summary = summarize_args({"path": long_value})
    assert summary["path"] == "x" * 120 + " [truncated]"


def test_summarize_args_passes_through_short_non_sensitive_values():
    summary = summarize_args({"path": "/tmp/file.txt"})
    assert summary["path"] == "/tmp/file.txt"


# ---------------------------------------------------------------------------
# Enterprise #10 — DLP integration into evaluate()
# ---------------------------------------------------------------------------

async def test_no_dlp_config_is_byte_identical_to_pre_dlp_behavior():
    """Hard regression-test requirement from the plan: a server with NO dlp_detectors/
    dlp_custom_patterns configured must behave exactly as before this feature existed — no
    dlp_* fields populated on the Decision, even when the arguments contain something that
    WOULD match a detector if one were configured."""
    policy = ServerPolicy(mode="passthrough")
    decision = await evaluate(
        "tool", {"message": "my card is 4111111111111111, email nick@example.com"}, "srv", policy
    )
    assert not decision.blocked
    assert decision.dlp_detector is None
    assert decision.dlp_action is None
    assert decision.dlp_match_count == 0
    assert decision.dlp_redacted_arguments is None


async def test_dlp_allow_action_does_not_block_or_redact():
    policy = ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "allow"})
    decision = await evaluate("tool", {"message": "card 4111111111111111"}, "srv", policy)
    assert not decision.blocked
    assert decision.dlp_action is None


async def test_dlp_redact_allows_call_and_sets_redacted_arguments():
    policy = ServerPolicy(mode="passthrough", dlp_detectors={"email": "redact"})
    decision = await evaluate(
        "tool", {"message": "reach me at nick@example.com for details"}, "srv", policy
    )
    assert not decision.blocked
    assert decision.dlp_action == "redact"
    assert decision.dlp_detector == "email"
    assert decision.dlp_match_count == 1
    assert "nick@example.com" not in decision.dlp_redacted_arguments["message"]
    assert "[REDACTED:email]" in decision.dlp_redacted_arguments["message"]


async def test_dlp_block_blocks_the_call():
    policy = ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "block"})
    decision = await evaluate("tool", {"message": "card 4111111111111111"}, "srv", policy)
    assert decision.blocked
    assert decision.rule == "dlp"
    assert decision.dlp_detector == "credit_card"
    assert decision.dlp_action == "block"


async def test_dlp_block_decision_never_carries_matched_value():
    """The audit-safety invariant: the matched/redacted value must never appear anywhere a
    Decision surfaces it. `reason` is a fixed template naming the detector, not the value;
    `matched` (the field other rule types use to carry the offending text) stays None for DLP
    so nothing downstream (audit, webhook) can accidentally forward the secret through it."""
    policy = ServerPolicy(mode="passthrough", dlp_detectors={"credit_card": "block"})
    decision = await evaluate("tool", {"message": "card 4111111111111111"}, "srv", policy)
    assert decision.matched is None
    assert "4111111111111111" not in (decision.reason or "")


async def test_dlp_runs_after_allow_deny_not_before():
    """Ordering: a call already blocked by allowlist/denylist must not even attempt a DLP
    scan — asserted indirectly via decision.rule being 'denylist', not 'dlp', even though the
    argument would also match the configured DLP block detector."""
    policy = ServerPolicy(
        mode="denylist", denied=["dangerous_tool"], dlp_detectors={"credit_card": "block"}
    )
    decision = await evaluate(
        "dangerous_tool", {"message": "card 4111111111111111"}, "srv", policy
    )
    assert decision.blocked
    assert decision.rule == "denylist"
    assert decision.dlp_detector is None  # never reached the DLP scan


async def test_dlp_runs_after_param_rules_not_before():
    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"other": ParamRule(denied=True)}},
        dlp_detectors={"credit_card": "block"},
    )
    decision = await evaluate(
        "tool", {"other": "x", "message": "card 4111111111111111"}, "srv", policy
    )
    assert decision.blocked
    assert decision.rule == "denied_param"
    assert decision.dlp_detector is None


async def test_dlp_custom_pattern_wired_through_evaluate():
    policy = ServerPolicy(
        mode="passthrough",
        dlp_custom_patterns=[DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="block")],
    )
    decision = await evaluate("tool", {"note": "assigned EMP-123456"}, "srv", policy)
    assert decision.blocked
    assert decision.dlp_detector == "employee_id"


async def test_finditer_spans_with_timeout_recovers_real_match_spans():
    """The DLP custom-pattern span-recovery primitive (argus/dlp.py's
    _scan_value_with_custom_pattern) — a well-behaved pattern returns every match's
    (start, end) span, not just a matched/not-matched bool."""
    import re

    compiled = re.compile(r"\d+")
    spans = await _finditer_spans_with_timeout(compiled, "a1 b22 c333")
    assert spans == [(1, 2), (4, 6), (8, 11)]


async def test_finditer_spans_with_timeout_fails_closed_on_pathological_pattern():
    """Security-critical: the ENTIRE finditer() call (not just a single search()) must be
    bounded. A pattern that resolves its FIRST match quickly is not guaranteed to resolve
    later matches equally quickly — finditer restarts matching from each match's end, which is
    exactly the kind of position-dependent backtracking a ReDoS pattern exploits. This is the
    gap a naive 'search() once, then trust finditer()' design would leave open; this test
    proves the fix bounds finditer itself, returning None (UNDETERMINED) rather than hanging."""
    import re
    import time

    evil = re.compile(r"(a+)+$")
    evil_input = "a" * 30 + "!"

    start = time.monotonic()
    spans = await _finditer_spans_with_timeout(evil, evil_input)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0
    assert spans is None


async def test_dlp_custom_pattern_redos_fails_closed_through_evaluate():
    """End-to-end confirmation that a pathological custom DLP pattern set through ServerPolicy
    and reaching evaluate() still fails closed within a bounded time, exactly matching F2's
    block_pattern precedent."""
    import time

    policy = ServerPolicy(
        mode="passthrough",
        dlp_custom_patterns=[DlpCustomPattern(name="evil", pattern=r"^(a*)*\1$", action="block")],
    )
    evil_input = "a" * 30 + "b"

    start = time.monotonic()
    decision = await evaluate("tool", {"value": evil_input}, "srv", policy)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0
    assert decision.blocked
    assert decision.dlp_detector == "evil"


# ---------------------------------------------------------------------------
# #112 — re2 fast path: patterns re2 accepts are matched inline on the event loop with
# no timeout process (linear-time guarantee), so the ~85-109ms forkserver overhead measured
# in r5-redos-2026-08-10.md disappears for the common operator-pattern case. Only patterns
# re2 rejects (backreferences, lookarounds) keep the process path above.
# ---------------------------------------------------------------------------

async def test_re2_fast_path_engages_for_patterns_re_would_hang_on():
    """The classic catastrophic-backtracking shape "(a+)+$" is ACCEPTED by re2 — RE2 just
    matches it in linear time. So through the model (compile_pattern), it must compile to the
    re2 engine and evaluate inline in microseconds, where Python's `re` would take >5s on the
    same adversarial input. Proves engine selection works and the fast path actually fires."""
    import time

    from db.models import is_re2_pattern

    rule = ParamRule(block_patterns=[r"(a+)+$"])
    compiled = rule.compiled_patterns()[0]
    assert is_re2_pattern(compiled), "block_pattern compiled to re, expected re2 fast path"

    policy = ServerPolicy(
        mode="passthrough",
        param_rules={"tool": {"value": rule}},
    )
    evil_input = "a" * 30 + "!"

    start = time.monotonic()
    decision = await evaluate("tool", {"value": evil_input}, "srv", policy)
    elapsed = time.monotonic() - start

    # "(a+)+$" does not match input ending in '!', so the decision is allow — the assertion
    # that matters is the elapsed time. Sub-millisecond inline; 50ms is a huge margin over
    # inline while staying far below the ~85ms process-spawn floor the old path paid.
    assert not decision.blocked
    assert elapsed < 0.05, f"re2 fast path took {elapsed:.3f}s — engine selection may be broken"


async def test_re2_fast_path_recovers_finditer_spans():
    """The DLP span-recovery primitive on an re2-compiled pattern must return spans inline,
    with no process involvement — same contract as the process path's well-behaved case."""
    from db.models import compile_pattern, is_re2_pattern

    compiled = compile_pattern(r"\d+")
    assert is_re2_pattern(compiled)
    spans = await _finditer_spans_with_timeout(compiled, "a1 b22 c333")
    assert spans == [(1, 2), (4, 6), (8, 11)]


# ---------------------------------------------------------------------------
# Issue #106 — the match deadline must measure only pattern.search(), never
# forkserver spawn/bootstrap/IPC overhead. See tests/bench/results/r5-redos-2026-08-10.md
# and the issue for the full measurement; these are the regression tests that would have
# caught the original bug (a benign pattern spuriously timing out because the deadline
# clock started at process.start() rather than once the worker confirmed it was running).
# ---------------------------------------------------------------------------

async def test_benign_match_leaves_most_of_the_timeout_budget_unused():
    """The test that would have caught the original bug. Pre-fix, the deadline covered
    fork + child bootstrap + IPC + the match, so a benign match on a slow/loaded host could
    consume the (near-)entire _REGEX_MATCH_TIMEOUT_SECONDS budget on spawn overhead alone —
    that's the whole issue #106 report. Post-fix, the deadline starts only once the worker
    confirms it is running, so a benign, non-backtracking match should complete in a small
    fraction of the budget on any reasonable host, regardless of how slow forkserver spawn is
    on that host. Asserting a generous fraction (not a tight absolute bound) keeps this
    portable across CI hardware while still failing if spawn overhead leaks back into the
    deadline."""
    import re
    import time

    from argus.policy import _REGEX_MATCH_TIMEOUT_SECONDS, _match_with_timeout

    compiled = re.compile(r"rm\s+-rf", re.IGNORECASE)

    # Warm the forkserver first so this measures steady-state, not the one-time cold-start
    # helper spawn (covered separately by the cold-start measurements in the issue).
    await _match_with_timeout(compiled, "warmup")

    start = time.monotonic()
    outcome = await _match_with_timeout(compiled, "after 0.1.1 upgrade")
    elapsed = time.monotonic() - start

    assert outcome is MatchOutcome.NOT_MATCHED
    # Generous: half the budget is still >100x more than the match itself needs, but tight
    # enough to fail if the fix regresses and spawn overhead leaks back into the deadline.
    assert elapsed < (_REGEX_MATCH_TIMEOUT_SECONDS / 2), (
        f"benign match took {elapsed:.3f}s, more than half the "
        f"{_REGEX_MATCH_TIMEOUT_SECONDS}s match budget — spawn overhead may be leaking into "
        f"the match deadline again (issue #106)"
    )


async def test_worker_never_ready_is_undetermined_and_attributed_to_infra_not_pattern():
    """A worker that never confirms it's running (simulated here by a readiness timeout of
    effectively zero, forcing the ready-wait to fail even though the worker WOULD have
    matched instantly) must still fail closed to UNDETERMINED — but the caller-visible
    behavior (block) must not depend on which of the two timeouts fired. This is the
    'not_ready' path from _run_worker_with_timeout, which issue #106 reports as the actual
    real-world failure mode (a benign pattern blocked because the HOST was slow, not because
    the pattern was bad)."""
    import re

    from argus.policy import _run_worker_with_timeout, _regex_worker

    compiled = re.compile(r"rm\s+-rf", re.IGNORECASE)

    # A near-zero ready budget forces the readiness wait to fail even for a trivially fast
    # worker — simulating a host too slow/loaded to fork+bootstrap a worker in time, without
    # needing genuinely slow hardware in CI.
    import argus.policy as policy_module

    original_ready_timeout = policy_module._WORKER_READY_TIMEOUT_SECONDS
    policy_module._WORKER_READY_TIMEOUT_SECONDS = 0.0
    try:
        result, log_reason = await _run_worker_with_timeout(
            _regex_worker, compiled, "after 0.1.1 upgrade", "block_pattern match"
        )
    finally:
        policy_module._WORKER_READY_TIMEOUT_SECONDS = original_ready_timeout

    assert result is None
    assert log_reason == "not_ready"


async def test_genuine_redos_is_undetermined_and_attributed_to_match_not_infra():
    """The case the naive same-queue-sentinel prototype got wrong: a worker that DOES become
    ready and then hangs in a genuinely pathological match must be attributed to the match
    timing out, not misreported as 'never became ready'. (An earlier prototype signaled
    readiness by put()ing a token on the same result queue used for the match outcome —
    mp.Queue.put() hands off to a background feeder THREAD in the child, which a
    GIL-hogging pattern.search() immediately starves, so the sentinel never flushed and a
    real ReDoS was misreported as an infra failure. The Event-based fix in _regex_worker
    does not have this problem because Event.set() is synchronous and OS-level.)"""
    import re

    from argus.policy import _run_worker_with_timeout, _regex_worker

    evil_pattern = re.compile(r"(a+)+$")
    evil_input = "a" * 30 + "!"

    result, log_reason = await _run_worker_with_timeout(
        _regex_worker, evil_pattern, evil_input, "block_pattern match"
    )

    assert result is None
    assert log_reason == "match_timeout"


async def test_regex_match_timeout_and_worker_ready_timeout_are_configurable_via_settings():
    """Issue #106 suggestion #2: an operator on slower hardware must be able to raise these
    budgets without patching argus/policy.py. Confirms both fields exist on Settings with the
    module's current defaults, so the module-level constants and Settings stay in sync."""
    from archon.settings import Settings

    settings = Settings()
    assert settings.regex_match_timeout_seconds == 0.5
    assert settings.worker_ready_timeout_seconds == 5.0
