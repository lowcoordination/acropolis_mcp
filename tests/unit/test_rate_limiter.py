from __future__ import annotations

import pytest

from argus.rate_limiter import RateLimiterRegistry, parse_spec, server_key, tool_key


def test_parse_spec_variants():
    assert parse_spec("5/minute").calls == 5
    assert parse_spec("30/hour").period == 3600.0
    assert parse_spec("100/second").period == 1.0


def test_parse_spec_invalid_format():
    with pytest.raises(ValueError):
        parse_spec("garbage")


def test_parse_spec_unknown_unit():
    with pytest.raises(ValueError):
        parse_spec("5/fortnight")


async def test_bucket_allows_up_to_limit_then_blocks():
    registry = RateLimiterRegistry()
    registry.register("k", "3/hour")
    results = [await registry.check("k") for _ in range(4)]
    assert results == [True, True, True, False]


async def test_unregistered_key_is_unlimited():
    registry = RateLimiterRegistry()
    for _ in range(50):
        assert await registry.check("unregistered") is True


async def test_check_all_short_circuits_on_first_exhausted_bucket():
    registry = RateLimiterRegistry()
    registry.register("a", "1/hour")
    registry.register("b", "100/hour")
    assert await registry.check_all(["a", "b"]) is True
    # 'a' is now exhausted — check_all must return False
    assert await registry.check_all(["a", "b"]) is False


def test_key_helpers_are_distinct_and_stable():
    assert server_key("shell") == "srv:shell"
    assert tool_key("shell", "shell_run") == "srv:shell:tool:shell_run"
    assert server_key("shell") != tool_key("shell", "shell_run")


async def test_ensure_current_preserves_state_when_spec_unchanged():
    """F8 regression: ensure_current must be a no-op (preserving consumed-token state) when
    called repeatedly with the SAME spec — the naive fix of "just always call register()" would
    reset every caller to a fresh full bucket on every request and defeat rate limiting."""
    registry = RateLimiterRegistry()
    registry.register("k", "2/hour")
    assert await registry.check("k") is True  # consume 1 of 2
    registry.ensure_current("k", "2/hour")  # same spec — must NOT reset
    assert await registry.check("k") is True  # consume the 2nd
    registry.ensure_current("k", "2/hour")
    assert await registry.check("k") is False  # exhausted — proves state was preserved


async def test_ensure_current_rebuilds_bucket_when_spec_changes():
    """F8: this is the actual fix — an operator raising a limit must take effect immediately,
    not require a restart."""
    registry = RateLimiterRegistry()
    registry.register("k", "1/hour")
    assert await registry.check("k") is True
    assert await registry.check("k") is False  # exhausted at limit 1

    registry.ensure_current("k", "5/hour")  # operator raises the limit
    assert await registry.check("k") is True  # a fresh bucket at the new, higher limit


async def test_unregister_removes_tracked_spec_too():
    """F8: unregister must clear BOTH the bucket and the spec RateLimiterRegistry uses to
    decide whether ensure_current needs to rebuild — otherwise a key that's unregistered then
    re-registered with the SAME spec string would be treated as unchanged and keep whatever
    stale bucket state (if any) happened to still be there."""
    registry = RateLimiterRegistry()
    registry.register("k", "1/hour")
    registry.unregister("k")
    assert registry.is_registered("k") is False
    registry.ensure_current("k", "1/hour")
    assert registry.is_registered("k") is True
    assert await registry.check("k") is True  # fresh bucket, not exhausted from before
