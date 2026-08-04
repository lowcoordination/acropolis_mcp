from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Simple async token bucket for rate limiting."""

    def __init__(self, calls: int, period_seconds: float):
        self.calls = calls
        self.period = period_seconds
        self._tokens = float(calls)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self.calls),
                self._tokens + (elapsed / self.period) * self.calls,
            )
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


def parse_spec(spec: str) -> TokenBucket:
    """Parse '5/minute' | '30/hour' | '100/second' into a TokenBucket."""
    parts = spec.strip().split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid rate limit spec: {spec!r}. Use 'N/minute'.")
    count = int(parts[0])
    unit = parts[1].strip().lower()
    period = {"second": 1.0, "minute": 60.0, "hour": 3600.0}.get(unit)
    if period is None:
        raise ValueError(f"Unknown period {unit!r}. Use second/minute/hour.")
    return TokenBucket(count, period)


def server_key(slug: str) -> str:
    return f"srv:{slug}"


def tool_key(slug: str, tool_name: str) -> str:
    """F9 (review 2026-08-04, tracked gap, not this sprint's scope): tool_key is constructed
    and checked on every tools/call (see Pipeline._check_rate_limits), but nothing anywhere
    ever calls register() for a tool_key — ServerPolicy has no per-tool rate_limit field
    surfaced from tool_policies.rate_limit (the DB column exists; the model doesn't expose it).
    check_all() treats an unregistered key as unlimited, so this lookup always passes. Matches
    the real fleet's guard-config.yml, which only ever configured server-level limits — kept as
    a documented gap rather than removed, since the DB column and this key builder are the
    natural landing point when per-tool limits are implemented."""
    return f"srv:{slug}:tool:{tool_name}"


class RateLimiterRegistry:
    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        # F8: tracks the spec string each key was last registered with, so ensure_current can
        # tell "the policy hasn't changed, leave the bucket's consumed-token state alone" apart
        # from "the operator changed the limit, rebuild the bucket" without unregistering (and
        # thus resetting) on every single request.
        self._specs: dict[str, str] = {}

    def register(self, key: str, spec: str) -> None:
        """Builds a FRESH bucket, resetting any consumed-token state for `key`. Call this when
        the spec has genuinely changed (see ensure_current for the common "is it still the same
        limit" case) or when a bucket is being registered for the first time."""
        self._buckets[key] = parse_spec(spec)
        self._specs[key] = spec

    def ensure_current(self, key: str, spec: str) -> None:
        """(Re)registers `key` only if `spec` differs from what it was last registered with, or
        if it isn't registered at all. A no-op — and critically, does NOT touch the existing
        bucket's consumed-token state — when the policy hasn't changed since the last call.
        This is what makes it safe to call on every request without defeating the limit by
        resetting every caller to a fresh full bucket each time."""
        if self._specs.get(key) != spec:
            self.register(key, spec)

    def unregister(self, key: str) -> None:
        self._buckets.pop(key, None)
        self._specs.pop(key, None)

    def is_registered(self, key: str) -> bool:
        return key in self._buckets

    async def check(self, key: str) -> bool:
        """Returns True if the call is allowed, False if rate-limited.
        A key with no registered bucket is treated as unlimited."""
        bucket = self._buckets.get(key)
        if bucket is None:
            return True
        return await bucket.consume()

    async def check_all(self, keys: list[str]) -> bool:
        """All-or-nothing check across several buckets (e.g. server + tool + api key)."""
        for key in keys:
            if not await self.check(key):
                return False
        return True
