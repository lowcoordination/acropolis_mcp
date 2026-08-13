from __future__ import annotations

import asyncio
import time
from typing import Protocol, runtime_checkable


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


@runtime_checkable
class RateLimitBackend(Protocol):
    """Storage/enforcement seam for rate limiting (issue #31, step 1 of the distributed
    rate-limiting fix).

    Every method here is what argus/pipeline.py, archon/setup.py, and archon/api.py actually
    call today against `RateLimiterRegistry` — this Protocol exists to let a future
    Redis/Valkey-backed implementation (issue #31's later steps) stand in for
    `InMemoryBackend` without touching any caller. `InMemoryBackend` below is that seam's only
    implementation for now; the storage is process-local, so — like the class it replaces —
    each replica still enforces its own independent copy of every limit. See deploy/k8s's
    replica-count comment and issue #31 for the multi-replica gap this interface exists to
    eventually close, and issue #28 for why replicas stay capped at 1 until it does.

    A distributed implementation is NOT required to keep the exact `TokenBucket` refill
    algorithm — only the check-then-consume ATOMICITY guarantee that `check`/`check_all`
    depend on (see `TokenBucket.consume`'s `asyncio.Lock`; a Redis backend would need an
    equivalent, e.g. a single atomic Lua script, not a separate read then write).
    """

    def register(self, key: str, spec: str) -> None:
        """Builds a FRESH bucket, resetting any consumed-token state for `key`."""
        ...

    def ensure_current(self, key: str, spec: str) -> None:
        """(Re)registers `key` only if `spec` differs from what it was last registered with,
        or if it isn't registered at all. Must NOT touch existing consumed-token state when
        the spec is unchanged — see RateLimiterRegistry's docstring history (issue F8) for why
        that distinction is load-bearing, not incidental."""
        ...

    def unregister(self, key: str) -> None:
        ...

    def is_registered(self, key: str) -> bool:
        ...

    async def check(self, key: str) -> bool:
        """Returns True if the call is allowed, False if rate-limited. A key with no
        registered bucket is treated as unlimited."""
        ...

    async def check_all(self, keys: list[str]) -> bool:
        """All-or-nothing check across several buckets (e.g. server + tool + api key)."""
        ...


class InMemoryBackend:
    """Process-local `RateLimitBackend`: a dict of TokenBuckets, exactly as
    `RateLimiterRegistry` behaved before the interface existed (issue #31).

    This is the ONLY implementation of RateLimitBackend today. Its limitation is the entire
    reason issue #31 exists: state lives in this process's memory, so N replicas each enforce
    the full configured limit independently, multiplying the effective limit by N. Safe and
    correct for the single-replica deployment this app currently requires (see deploy/k8s's
    `replicas: 1` and issue #28); not safe to scale past that until a shared-state backend
    (issue #31's later steps) replaces or supplements this one.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        # F8: tracks the spec string each key was last registered with, so ensure_current can
        # tell "the policy hasn't changed, leave the bucket's consumed-token state alone" apart
        # from "the operator changed the limit, rebuild the bucket" without unregistering (and
        # thus resetting) on every single request.
        self._specs: dict[str, str] = {}

    def register(self, key: str, spec: str) -> None:
        self._buckets[key] = parse_spec(spec)
        self._specs[key] = spec

    def ensure_current(self, key: str, spec: str) -> None:
        if self._specs.get(key) != spec:
            self.register(key, spec)

    def unregister(self, key: str) -> None:
        self._buckets.pop(key, None)
        self._specs.pop(key, None)

    def is_registered(self, key: str) -> bool:
        return key in self._buckets

    async def check(self, key: str) -> bool:
        bucket = self._buckets.get(key)
        if bucket is None:
            return True
        return await bucket.consume()

    async def check_all(self, keys: list[str]) -> bool:
        for key in keys:
            if not await self.check(key):
                return False
        return True


# Every existing caller (argus/app.py, argus/pipeline.py, archon/setup.py, archon/api.py) and
# every existing test constructs/type-hints `RateLimiterRegistry` by name. Aliasing rather than
# replacing it keeps all of that working unchanged — "in-memory remains default and
# behaviourally unchanged" (issue #31's acceptance criteria) with the least motion. Revisit this
# once a second backend exists and callers need to choose between them; a selection mechanism
# ahead of having anything to select is speculative.
RateLimiterRegistry = InMemoryBackend
