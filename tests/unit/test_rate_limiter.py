from __future__ import annotations

import pytest

from argus.rate_limiter import (
    InMemoryBackend,
    RateLimitBackend,
    RateLimitBackendUnavailable,
    RateLimiterRegistry,
    parse_spec,
    server_key,
    tool_key,
)


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


# --- Issue #31 step 1: RateLimitBackend interface -------------------------------------------


def test_rate_limiter_registry_is_the_in_memory_backend():
    """RateLimiterRegistry must stay the SAME object as InMemoryBackend, not a subclass or a
    wrapper — every existing caller (argus/pipeline.py, archon/setup.py, archon/api.py,
    argus/app.py) and every existing test in this file constructs/type-hints it by that name.
    An alias satisfies "in-memory remains default and behaviourally unchanged" with zero
    caller churn; anything else would be a needless second class doing the same thing."""
    assert RateLimiterRegistry is InMemoryBackend


def test_in_memory_backend_satisfies_the_protocol():
    assert isinstance(InMemoryBackend(), RateLimitBackend)


class _FakeBackend:
    """A deliberately minimal second RateLimitBackend implementation — NOT shipped, exists only
    to prove the interface is something a real caller can actually be pointed at, not just a
    Protocol that happens to describe one class. Everything here is trivial and
    process-local — a real distributed backend (issue #31's later steps) would talk to
    Redis/Valkey instead, but the SHAPE a caller depends on is exactly this."""

    def __init__(self) -> None:
        self.checked: list[str] = []
        self._registered: set[str] = set()

    def register(self, key: str, spec: str) -> None:
        self._registered.add(key)

    def ensure_current(self, key: str, spec: str) -> None:
        self._registered.add(key)

    def unregister(self, key: str) -> None:
        self._registered.discard(key)

    def is_registered(self, key: str) -> bool:
        return key in self._registered

    async def check(self, key: str) -> bool:
        self.checked.append(key)
        return True  # never blocks — the point here is call-shape compatibility, not policy

    async def check_all(self, keys: list[str]) -> bool:
        for key in keys:
            if not await self.check(key):
                return False
        return True


async def test_a_real_caller_can_be_pointed_at_a_different_backend():
    """The load-bearing proof for this issue: Pipeline._check_rate_limits (the actual,
    unmodified production code) is exercised against _FakeBackend instead of
    RateLimiterRegistry, through the SAME rate_limiter constructor argument every real
    deployment uses. If this didn't work, the interface would be decorative — something that
    merely describes RateLimiterRegistry's shape rather than something a caller can actually
    substitute."""
    from db.models import ServerPolicy, ServerRecord

    from argus.rate_limiter import server_key, tool_key

    fake = _FakeBackend()
    server = ServerRecord(
        id=1, slug="demo", name="Demo", upstream_url="http://example.test",
        enabled=True, in_aggregate=True, created_at="2026-01-01", updated_at="2026-01-01",
    )
    policy = ServerPolicy(rate_limit="5/minute")

    from argus.pipeline import Pipeline

    pipeline = Pipeline.__new__(Pipeline)  # bypass the full constructor; only need _rate_limiter
    pipeline._rate_limiter = fake
    pipeline._audit = None

    blocked = await pipeline._check_rate_limits(
        server, policy, "echo", api_key_id=None, rpc_id=1, start=0.0, client_ip=None,
    )
    assert blocked is None  # _FakeBackend.check() never blocks
    assert server_key("demo") in fake.checked or tool_key("demo", "echo") in fake.checked


class _FakeAuditLogger:
    """Minimal stand-in for AuditLogger — records the (decision, rule) pairs _refuse logs,
    without touching a real Database."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def log(self, **kwargs) -> None:
        self.rows.append(kwargs)


class _UnavailableBackend:
    """A RateLimitBackend whose storage cannot be reached — the shape a Redis/Valkey backend
    takes when its connection drops. check_all must raise RateLimitBackendUnavailable, per the
    Protocol's contract, never return a bool."""

    def register(self, key: str, spec: str) -> None:
        pass

    def ensure_current(self, key: str, spec: str) -> None:
        pass

    def unregister(self, key: str) -> None:
        pass

    def is_registered(self, key: str) -> bool:
        return False

    async def check(self, key: str) -> bool:
        raise RateLimitBackendUnavailable("simulated backend outage")

    async def check_all(self, keys: list[str]) -> bool:
        raise RateLimitBackendUnavailable("simulated backend outage")


async def test_rate_limiter_fails_closed_when_backend_is_unavailable():
    """Issue #31's fail-open-vs-fail-closed decision, proven through the real code path.

    A backend that cannot be reached must produce a BLOCKED response (429), not let the call
    through — see RateLimitBackendUnavailable's docstring for why this is the correct trade for
    a control whose entire job is resisting an adversary who controls the load."""
    from db.models import ServerPolicy, ServerRecord

    from argus.pipeline import Pipeline

    server = ServerRecord(
        id=1, slug="demo", name="Demo", upstream_url="http://example.test",
        enabled=True, in_aggregate=True, created_at="2026-01-01", updated_at="2026-01-01",
    )
    policy = ServerPolicy(rate_limit="5/minute")

    pipeline = Pipeline.__new__(Pipeline)
    pipeline._rate_limiter = _UnavailableBackend()
    audit = _FakeAuditLogger()
    pipeline._audit = audit

    response = await pipeline._check_rate_limits(
        server, policy, "echo", api_key_id=None, rpc_id=1, start=0.0, client_ip=None,
    )

    assert response is not None, "backend-unavailable must block the call, not let it through"
    assert response.status_code == 429

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["decision"] == "BLOCKED"
    # Own rule value, distinguishable from a genuine over-limit block ("rate_limit") — an
    # operator seeing this in the audit trail needs a different response (check the backend)
    # than seeing a real rate_limit block (the configured limit is doing its job).
    assert row["rule"] == "rate_limit_backend_unavailable"


# --- Issue #31: backend selection in create_app ---------------------------------------------


def test_default_backend_is_in_memory():
    """The default must stay in-memory: a single-replica deployment (what deploy/k8s enforces)
    should never be made to run a Valkey server it doesn't need."""
    from archon.settings import Settings

    from argus.app import _build_rate_limiter

    assert isinstance(_build_rate_limiter(Settings(data_dir="/tmp/argus-test")), InMemoryBackend)


def test_valkey_backend_requires_a_url():
    """Boot-time failure, not request-time. With the fail-closed posture a misconfigured valkey
    backend 429s every request, so an operator must find out at startup."""
    from archon.settings import Settings

    from argus.app import _build_rate_limiter

    settings = Settings(data_dir="/tmp/argus-test", rate_limit_backend="valkey")
    with pytest.raises(ValueError, match="requires rate_limit_backend_url"):
        _build_rate_limiter(settings)


def test_unknown_backend_name_fails_at_boot():
    from archon.settings import Settings

    from argus.app import _build_rate_limiter

    settings = Settings(data_dir="/tmp/argus-test", rate_limit_backend="nope")
    with pytest.raises(ValueError, match="unknown rate_limit_backend"):
        _build_rate_limiter(settings)
