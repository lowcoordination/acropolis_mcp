from __future__ import annotations

import pytest

from argus.rate_limiter import RateLimiterRegistry, api_key_key, parse_spec, server_key, tool_key


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
    assert api_key_key(7) == "key:7"
    assert server_key("shell") != tool_key("shell", "shell_run")
