"""The audit origin vocabulary (#123) — argus/origin.py.

The trust boundary is the point of these tests: the derived key name must always lead, and a
caller assertion must never be able to forge structure. Charset rejection itself is enforced at
the API boundary (PolicyEvaluateRequest) and tested in tests/integration/test_policy_evaluate.py;
what is tested here is that the COMPOSITION keeps the derived half first and unambiguous.
"""
from __future__ import annotations

from argus.origin import (
    CLASS_GATEWAY,
    CLASS_LOCAL,
    CLASS_TEST,
    ORIGIN_CLASSES,
    TEST_ORIGIN,
    local_origin,
    origin_class,
)


class TestLocalOrigin:
    def test_derived_only_when_no_assertion(self):
        assert local_origin("guard") == "local:guard"

    def test_assertion_is_appended_after_the_derived_name(self):
        origin = local_origin("guard", "pi", "laptop-01")
        assert origin == "local:guard/pi@laptop-01"
        # The derived half leads: everything before the first '/' in the detail is the gateway's
        # own record, so a reader can always find it without trusting the caller.
        assert origin.split(":", 1)[1].split("/", 1)[0] == "guard"

    def test_half_an_assertion_is_ignored_entirely(self):
        """Harness without host (or vice versa) would produce a detail string that cannot be
        parsed back apart — drop it rather than emit something ambiguous."""
        assert local_origin("guard", "pi", None) == "local:guard"
        assert local_origin("guard", None, "laptop") == "local:guard"
        assert local_origin("guard", "", "") == "local:guard"

    def test_every_built_value_classes_as_local(self):
        for origin in (local_origin("guard"), local_origin("guard", "pi", "host")):
            assert origin_class(origin) == CLASS_LOCAL


class TestOriginClass:
    def test_null_is_gateway(self):
        """NULL is the storage form of real traffic; "gateway" is how it is named in a query
        param or a metrics label, where a literal null is awkward."""
        assert origin_class(None) == CLASS_GATEWAY

    def test_bare_test_token_is_its_own_class(self):
        """origin='test' predates the class:detail scheme and has no colon — it must keep
        classing correctly, since those rows are already on disk."""
        assert origin_class(TEST_ORIGIN) == CLASS_TEST
        assert origin_class("test") == CLASS_TEST

    def test_class_is_the_leading_segment(self):
        assert origin_class("local:guard/pi@laptop") == CLASS_LOCAL
        assert origin_class("local:guard") == CLASS_LOCAL

    def test_unknown_class_degrades_to_its_leading_segment(self):
        """A class added later must still aggregate sensibly rather than vanishing from a
        breakdown or crashing a scrape."""
        assert origin_class("future:something") == "future"

    def test_known_classes_are_the_documented_three(self):
        assert set(ORIGIN_CLASSES) == {"gateway", "local", "test"}


class TestAssertionCannotForgeStructure:
    """Composition-level proof of the trust boundary. The API layer rejects these characters
    outright (422); this asserts that even if a value carrying them reached the builder, the
    DERIVED prefix still leads and still classes as local — defence in depth, not a substitute
    for the boundary validation."""

    def test_colon_in_assertion_cannot_change_the_class(self):
        assert origin_class(local_origin("guard", "pi:evil", "host")) == CLASS_LOCAL

    def test_derived_name_still_leads_with_a_hostile_assertion(self):
        origin = local_origin("guard", "pi", "host/../../admin")
        assert origin.startswith("local:guard/")
