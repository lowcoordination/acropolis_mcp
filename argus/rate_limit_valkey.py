"""Shared-state rate-limit backend over Valkey/Redis (issue #31).

Separate module from argus/rate_limiter.py on purpose: `redis` is an OPTIONAL dependency
(`pip install acropolis[distributed]`), and rate_limiter.py is imported unconditionally by the
data plane. Keeping the optional import here means a single-replica deployment that never
installs the client still imports the rate limiter fine.

Why this exists: InMemoryBackend holds token buckets in process memory, so N replicas enforce N
independent copies of every limit (issue #31, and see deploy/k8s's `replicas: 1` comment plus
issue #28). This backend puts the bucket in one place all replicas share.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from argus.rate_limiter import RateLimitBackendUnavailable, parse_spec_parts

logger = logging.getLogger("argus.rate_limit_valkey")

# Key prefix for every bucket this backend owns, so a Valkey instance shared with other
# workloads (a cache, a job queue) can't collide with rate-limit state and vice versa.
_KEY_PREFIX = "acropolis:ratelimit:"

# Refill-and-consume as ONE server-side operation.
#
# This is the whole reason a Lua script is used rather than a GET/compute/SET sequence from the
# client: the in-memory backend gets its atomicity from TokenBucket's asyncio.Lock, and the
# RateLimitBackend contract requires an equivalent guarantee. A read-then-write from N replicas
# has a check-then-act race between the read and the write — exactly the burst-shaped failure a
# rate limiter exists to prevent, so inheriting it here would defeat the point of the backend.
# Valkey/Redis execute a script atomically against the keyspace, which gives that for free.
#
# The algorithm mirrors TokenBucket.consume exactly (continuous refill, cap at `calls`, consume
# one token if >= 1.0) so behaviour doesn't change when an operator switches backends. It
# deliberately does NOT use Redis's own rate-limiting helpers or an approximate fixed-window
# counter — an operator's "5/minute" must mean the same thing in both backends.
#
# Time comes from Valkey's own clock (redis.call('TIME')), not the client's: with N replicas
# there is no single client clock, and using per-replica wall time would make refill rate depend
# on which replica happened to serve the request, plus skew between them.
_CONSUME_SCRIPT = """
local key = KEYS[1]
local calls = tonumber(ARGV[1])
local period = tonumber(ARGV[2])

local t = redis.call('TIME')
local now = tonumber(t[1]) + (tonumber(t[2]) / 1000000)

local state = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(state[1])
local last_refill = tonumber(state[2])

if tokens == nil or last_refill == nil then
  -- First call for this key: a full bucket, same as a freshly constructed TokenBucket.
  tokens = calls
  last_refill = now
end

local elapsed = now - last_refill
if elapsed < 0 then
  -- Clock moved backwards (NTP correction). Refill nothing rather than compute a negative
  -- refill, which would silently DEDUCT tokens and over-throttle.
  elapsed = 0
end

tokens = math.min(calls, tokens + (elapsed / period) * calls)

local allowed = 0
if tokens >= 1.0 then
  tokens = tokens - 1.0
  allowed = 1
end

redis.call('HSET', key, 'tokens', tokens, 'last_refill', now)
-- Expire idle buckets so a gateway with churning server slugs doesn't leak keys forever. Two
-- full periods is comfortably longer than it takes a bucket to refill completely, so a TTL can
-- never discard state that still had consumed tokens worth remembering.
redis.call('EXPIRE', key, math.ceil(period * 2))

return allowed
"""


class ValkeyBackend:
    """A `RateLimitBackend` whose token buckets live in Valkey/Redis, shared across replicas.

    Fails CLOSED: every method that talks to the server converts a connection/timeout failure
    into `RateLimitBackendUnavailable`, which `Pipeline._check_rate_limits` turns into a 429.
    See that exception's docstring in argus/rate_limiter.py for why that is the right posture
    for a rate limiter specifically (short version: an adversary trying to evade a rate limit
    already controls the load needed to make a shared backend unavailable, so failing open
    hands them the bypass).

    Spec storage: `register`/`ensure_current` keep the spec string in a local dict, NOT in
    Valkey. The spec comes from the server's policy row in Postgres, which every replica reads
    independently and identically — replicating it into Valkey would add a second source of
    truth for the same value with no benefit. What must be shared is the CONSUMED-TOKEN state,
    which is what the Lua script maintains.
    """

    def __init__(self, client: Any, key_prefix: str = _KEY_PREFIX) -> None:
        """`client` is a redis.asyncio.Redis (or any object with the same `eval` coroutine).
        Injected rather than constructed here so tests and app.py control connection settings,
        matching how the rest of this codebase takes its httpx/asyncpg clients."""
        self._client = client
        self._prefix = key_prefix
        self._specs: dict[str, str] = {}

    def _redis_key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def register(self, key: str, spec: str) -> None:
        # Validate eagerly: a malformed spec must raise here (where an operator is saving a
        # policy) rather than on the next tools/call, matching parse_spec's behaviour in the
        # in-memory backend.
        parse_spec_parts(spec)
        self._specs[key] = spec

    def ensure_current(self, key: str, spec: str) -> None:
        if self._specs.get(key) != spec:
            self.register(key, spec)

    def unregister(self, key: str) -> None:
        self._specs.pop(key, None)

    def is_registered(self, key: str) -> bool:
        return key in self._specs

    async def check(self, key: str) -> bool:
        spec = self._specs.get(key)
        if spec is None:
            # Same contract as InMemoryBackend: an unregistered key is unlimited. Note this
            # path does NOT touch Valkey, so an unregistered key cannot fail closed — there is
            # no limit to enforce and nothing to ask the server about.
            return True

        calls, period = parse_spec_parts(spec)
        try:
            allowed = await self._client.eval(
                _CONSUME_SCRIPT, 1, self._redis_key(key), calls, period,
            )
        except Exception as e:
            # Deliberately broad: redis-py raises ConnectionError/TimeoutError/RedisError plus
            # OS-level errors, and the posture is identical for all of them — we could not
            # determine whether this call is within the limit, so we must not claim it is.
            # Narrowing this risks a new client exception type silently becoming fail-open,
            # which is the one outcome this design must never produce.
            raise RateLimitBackendUnavailable(
                f"valkey rate-limit backend unreachable: {e}"
            ) from e
        return bool(allowed)

    async def check_all(self, keys: list[str]) -> bool:
        for key in keys:
            if not await self.check(key):
                return False
        return True


def build_valkey_backend(url: str, **client_kwargs: Any) -> ValkeyBackend:
    """Construct a ValkeyBackend from a connection URL, importing the optional client here.

    Raises a clear, actionable error when `acropolis[distributed]` isn't installed — a bare
    ModuleNotFoundError at this point would read as a bug rather than a missing extra.
    """
    try:
        from redis.asyncio import Redis
    except ModuleNotFoundError as e:  # pragma: no cover - depends on install extras
        raise RuntimeError(
            "the Valkey/Redis rate-limit backend requires the 'distributed' extra: "
            "pip install 'acropolis[distributed]'"
        ) from e

    # Short timeouts on purpose. This client sits on the request hot path, and the fail-closed
    # posture means a hung connection would stall every request rather than erroring promptly —
    # a slow backend must degrade to a fast 429, not to a hang. Same reasoning as the shared
    # httpx client's connect/pool budgets in argus/app.py.
    #
    # max_connections is set explicitly (issue #97): redis-py 8.x's async ConnectionPool
    # defaults to 100 (older redis-py effectively had no cap, 2**31). Past that many concurrent
    # rate-limited requests in one process, the pool raises immediately rather than queueing —
    # measured by bench_rate_limit.py Part 4c as a fast (~13ms) fail-closed 429
    # (rule=rate_limit_backend_unavailable) that reads, from the audit log, indistinguishable
    # from a real Valkey outage. 256 is roughly 2.5x the measured ceiling; the pool only opens
    # connections on demand, so the headroom costs nothing until a process actually needs it.
    defaults: dict[str, Any] = {
        "socket_connect_timeout": 2.0,
        "socket_timeout": 2.0,
        "health_check_interval": 30,
        "max_connections": 256,
    }
    defaults.update(client_kwargs)
    return ValkeyBackend(Redis.from_url(url, **defaults))
