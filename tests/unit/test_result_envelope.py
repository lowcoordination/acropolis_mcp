"""Unit tests for argus.result_envelope: the 2026-07-28 result fields (#172)."""
from __future__ import annotations

from argus.result_envelope import CACHEABLE_METHODS, envelope_2026_result


def test_plain_method_gets_only_result_type():
    result = envelope_2026_result("tools/call", {"content": [{"type": "text", "text": "x"}]})
    assert result == {"content": [{"type": "text", "text": "x"}], "resultType": "complete"}


def test_cacheable_method_gets_conservative_cache_directives():
    result = envelope_2026_result("tools/list", {"tools": []})
    assert result == {"tools": [], "resultType": "complete", "ttlMs": 0, "cacheScope": "private"}


def test_every_cacheable_method_is_covered():
    # The set the 2026-07-28 schema marks cacheable. Dropping one reintroduces #172 for it.
    assert CACHEABLE_METHODS == {
        "tools/list", "prompts/list", "resources/list", "resources/read",
        "resources/templates/list", "server/discover",
    }


def test_existing_fields_are_never_overwritten():
    # A 2026 upstream, or a non-complete result such as input_required, keeps its own values.
    result = envelope_2026_result(
        "tools/list",
        {"tools": [], "resultType": "input_required", "ttlMs": 5000, "cacheScope": "public"},
    )
    assert result["resultType"] == "input_required"
    assert result["ttlMs"] == 5000
    assert result["cacheScope"] == "public"


def test_explicit_null_is_filled_like_a_missing_field():
    result = envelope_2026_result("tools/list", {"tools": [], "resultType": None, "ttlMs": None})
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == 0
    assert result["cacheScope"] == "private"


def test_input_is_not_mutated():
    original = {"tools": []}
    envelope_2026_result("tools/list", original)
    assert original == {"tools": []}


def test_non_dict_result_is_returned_unchanged():
    assert envelope_2026_result("tools/call", None) is None
    assert envelope_2026_result("tools/call", [1]) == [1]
