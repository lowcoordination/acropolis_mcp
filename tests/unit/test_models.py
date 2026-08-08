from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from db.models import DlpCustomPattern, ParamRule, ServerPolicy


# ---------------------------------------------------------------------------
# §26 — ServerPolicy.mode / rate_limit validation (review 2026-08-04)
# ---------------------------------------------------------------------------

def test_valid_modes_are_accepted():
    for mode in ("passthrough", "allowlist", "denylist"):
        assert ServerPolicy(mode=mode).mode == mode


def test_invalid_mode_is_rejected_at_construction():
    with pytest.raises(ValidationError, match="mode must be one of"):
        ServerPolicy(mode="allowlust")


@pytest.mark.parametrize("spec", ["5/minute", "1/second", "1000/hour"])
def test_valid_rate_limit_specs_are_accepted(spec):
    assert ServerPolicy(rate_limit=spec).rate_limit == spec


@pytest.mark.parametrize(
    "bad_spec",
    ["not-a-spec", "5/fortnight", "abc/minute", "5", "5/minute/extra", "0/minute", "-5/minute"],
)
def test_invalid_rate_limit_specs_are_rejected_at_construction(bad_spec):
    """The regression this guards against: an unparseable rate_limit used to save successfully
    and then raise ValueError out of argus.rate_limiter.parse_spec on the very next tools/call
    against that server — every call, not just the first, since the spec is re-parsed per
    request (see Pipeline._check_rate_limits). Rejecting at construction/save time turns that
    into an immediate 400, before it ever reaches the database."""
    with pytest.raises(ValidationError):
        ServerPolicy(rate_limit=bad_spec)


def test_none_rate_limit_is_still_allowed():
    assert ServerPolicy(rate_limit=None).rate_limit is None


# ---------------------------------------------------------------------------
# §26 — ParamRule.compiled_patterns() caching (review 2026-08-04)
# ---------------------------------------------------------------------------

def test_compiled_patterns_returns_equivalent_patterns():
    rule = ParamRule(block_patterns=["/etc/.*", "secret"])
    compiled = rule.compiled_patterns()
    assert [c.pattern for c in compiled] == ["/etc/.*", "secret"]
    assert all(isinstance(c, re.Pattern) for c in compiled)


def test_compiled_patterns_is_cached_not_recompiled_each_call():
    rule = ParamRule(block_patterns=["/etc/.*"])
    first = rule.compiled_patterns()
    second = rule.compiled_patterns()
    assert first is second, "compiled_patterns() should return the same cached list object"
    assert first[0] is second[0], "individual compiled Pattern objects should be reused, not rebuilt"


# ---------------------------------------------------------------------------
# Enterprise #10 — ServerPolicy.dlp_detectors / dlp_custom_patterns validation
# ---------------------------------------------------------------------------

def test_dlp_detectors_default_to_empty_dict():
    """A server with no DLP config configured must default to zero detectors — the hard
    regression-test requirement, not just a design preference (see argus/policy.py's evaluate,
    which skips the DLP scan entirely when this is empty)."""
    policy = ServerPolicy()
    assert policy.dlp_detectors == {}
    assert policy.dlp_custom_patterns == []


@pytest.mark.parametrize("action", ["allow", "redact", "block"])
def test_valid_dlp_detector_actions_accepted(action):
    policy = ServerPolicy(dlp_detectors={"credit_card": action})
    assert policy.dlp_detectors["credit_card"] == action


def test_invalid_dlp_detector_action_rejected():
    with pytest.raises(ValidationError, match="action must be one of"):
        ServerPolicy(dlp_detectors={"credit_card": "quarantine"})


def test_unknown_dlp_detector_name_rejected():
    with pytest.raises(ValidationError, match="unknown dlp detector"):
        ServerPolicy(dlp_detectors={"totally_made_up": "block"})


def test_dlp_custom_pattern_valid_regex_accepted():
    pattern = DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="redact")
    assert pattern.action == "redact"


def test_dlp_custom_pattern_invalid_regex_rejected():
    with pytest.raises(ValidationError, match="invalid regex"):
        DlpCustomPattern(name="broken", pattern="[", action="block")


def test_dlp_custom_pattern_oversized_regex_rejected():
    with pytest.raises(ValidationError, match="too long"):
        DlpCustomPattern(name="huge", pattern="a" * 201, action="block")


def test_dlp_custom_pattern_invalid_action_rejected():
    with pytest.raises(ValidationError, match="action must be one of"):
        DlpCustomPattern(name="x", pattern="abc", action="quarantine")


def test_dlp_custom_pattern_default_action_is_block():
    pattern = DlpCustomPattern(name="x", pattern="abc")
    assert pattern.action == "block"


def test_server_policy_with_dlp_custom_patterns_round_trips_via_model_dump():
    policy = ServerPolicy(
        dlp_custom_patterns=[DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="redact")]
    )
    dumped = policy.model_dump()
    rebuilt = ServerPolicy(**dumped)
    assert rebuilt == policy
