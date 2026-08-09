"""Enterprise #11: quota period-boundary math.

Kept as a standalone module (mirrors argus/rate_limiter.py's shape) rather than inline in
Pipeline — the boundary computation is pure, easily unit-testable in isolation, and this is
exactly the kind of "two lines of logic that are trivial to get off-by-one wrong" code that
benefits from having its own focused tests (see tests/unit/test_quotas.py's period-boundary
cases) independent of the full pipeline/HTTP machinery.

Scope reminder (docs/quotas.md has the full statement): this is CALL-COUNT quotas. Acropolis
proxies JSON-RPC tool calls; it has no visibility into model token usage or inference cost, so
nothing here — or anywhere else in this feature — computes or implies a dollar or token figure.
"""
from __future__ import annotations

from datetime import datetime, timezone

VALID_QUOTA_PERIODS = ("day", "month")


def period_start(period_kind: str, now: datetime | None = None) -> datetime:
    """Returns the UTC instant the CURRENT quota period began, for `period_kind` ('day' |
    'month'), evaluated at `now` (defaults to the real current UTC time — a parameter purely so
    tests can pin an exact instant rather than depending on wall-clock timing).

    Periods are UTC-aligned, always — never the operator's local timezone, never a rolling
    24h/30d window. A rolling window would mean two calls a millisecond apart could straddle
    "the boundary" depending on exactly when each landed, which makes the quota's remaining
    budget effectively unpredictable from the outside. A fixed UTC calendar boundary means
    "how much is left this period" has one unambiguous answer at any given instant, and
    matches the same UTC-everywhere convention this codebase already uses for retention cutoffs
    (stoa/retention.py) and audit timestamps (db/database.py's utcnow()).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    if period_kind == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period_kind == "month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"unknown quota_period {period_kind!r}, expected one of {VALID_QUOTA_PERIODS}")
