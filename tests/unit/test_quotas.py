"""Unit tests for argus/quotas.py's period-boundary math (enterprise #11)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from argus.quotas import period_start


class TestPeriodStartDay:
    def test_mid_day_truncates_to_midnight_utc(self):
        now = datetime(2026, 8, 9, 14, 37, 22, tzinfo=timezone.utc)
        assert period_start("day", now) == datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)

    def test_exactly_at_midnight_is_unchanged(self):
        now = datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)
        assert period_start("day", now) == now

    def test_one_second_before_midnight_stays_in_previous_day(self):
        now = datetime(2026, 8, 9, 23, 59, 59, tzinfo=timezone.utc)
        assert period_start("day", now) == datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)

    def test_naive_datetime_is_treated_as_utc(self):
        now = datetime(2026, 8, 9, 14, 0, 0)  # no tzinfo
        result = period_start("day", now)
        assert result.tzinfo is not None
        assert result == datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)

    def test_non_utc_input_is_converted_before_truncating(self):
        from datetime import timedelta

        # 23:30 in UTC+2 is 21:30 UTC — same calendar day either way, but this exercises the
        # conversion path (not just a same-day case where a bug would go unnoticed).
        plus_two = timezone(timedelta(hours=2))
        now = datetime(2026, 8, 9, 23, 30, 0, tzinfo=plus_two)
        assert period_start("day", now) == datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)

    def test_a_timezone_where_local_date_differs_from_utc_date(self):
        from datetime import timedelta

        # 01:00 in UTC+3 is 22:00 UTC on the PREVIOUS calendar day — this is the case that
        # actually distinguishes "truncate after converting to UTC" from "truncate the local
        # wall-clock date," which would give the wrong bucket.
        plus_three = timezone(timedelta(hours=3))
        now = datetime(2026, 8, 10, 1, 0, 0, tzinfo=plus_three)
        assert period_start("day", now) == datetime(2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc)


class TestPeriodStartMonth:
    def test_mid_month_truncates_to_first_of_month(self):
        now = datetime(2026, 8, 9, 14, 37, 22, tzinfo=timezone.utc)
        assert period_start("month", now) == datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_last_day_of_month_stays_in_that_month(self):
        now = datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc)
        assert period_start("month", now) == datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_first_instant_of_month_is_unchanged(self):
        now = datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert period_start("month", now) == now


class TestPeriodStartValidation:
    def test_unknown_period_kind_raises(self):
        with pytest.raises(ValueError, match="unknown quota_period"):
            period_start("week")

    def test_default_now_is_close_to_real_utc_now(self):
        # Not pinned to a specific instant (that's what the `now=` parameter is for above) —
        # just proves the no-argument path actually calls datetime.now(UTC) rather than, say,
        # silently defaulting to the epoch.
        before = datetime.now(timezone.utc)
        result = period_start("day")
        after = datetime.now(timezone.utc)
        assert before.replace(hour=0, minute=0, second=0, microsecond=0) <= result <= after
