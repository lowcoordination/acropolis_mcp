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
    return f"srv:{slug}:tool:{tool_name}"


def api_key_key(key_id: int) -> str:
    return f"key:{key_id}"


class RateLimiterRegistry:
    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}

    def register(self, key: str, spec: str) -> None:
        self._buckets[key] = parse_spec(spec)

    def unregister(self, key: str) -> None:
        self._buckets.pop(key, None)

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
