"""Valkey-backed rate limiting (issue #31).

Runs against a REAL Valkey server, not a mock — the whole value of this backend is the
atomicity Valkey provides for the refill-and-consume Lua script, and a mock would assert the
code calls `eval` rather than that concurrent callers actually get a correct answer. Same
reasoning as tests/conftest.py's real-Postgres fixture.

Container lifecycle mirrors conftest.py's Postgres fixture: reuse ACROPOLIS_TEST_VALKEY_URL if
set (CI service container, or a developer's own instance), otherwise start one via `docker run`
and tear it down at session end.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time

import pytest

from argus.rate_limiter import RateLimitBackendUnavailable

pytest.importorskip("redis", reason="the 'distributed' extra is not installed")

from argus.rate_limit_valkey import ValkeyBackend, build_valkey_backend  # noqa: E402

_VALKEY_IMAGE = "valkey/valkey:8-alpine"
_VALKEY_PORT = 63801
_CONTAINER_NAME = "acropolis-test-valkey"


def _docker_available() -> bool:
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _start_container() -> str:
    subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True)
    proc = subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", _CONTAINER_NAME,
            "-p", f"{_VALKEY_PORT}:6379", _VALKEY_IMAGE,
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to start test Valkey container: {proc.stderr}")
    return f"redis://127.0.0.1:{_VALKEY_PORT}/0"


def _wait_ready(url: str, timeout: float = 30.0) -> None:
    from redis.asyncio import Redis

    async def _probe() -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            client = Redis.from_url(url, socket_connect_timeout=1.0)
            try:
                await client.ping()
                await client.aclose()
                return
            except Exception as e:  # noqa: BLE001 — any failure means "not ready yet"
                last = e
                await client.aclose()
                await asyncio.sleep(0.2)
        raise RuntimeError(f"test Valkey never became ready within {timeout}s: {last}")

    asyncio.run(_probe())


@pytest.fixture(scope="session")
def valkey_url():
    """A live Valkey. Same sourcing order as conftest.py's Postgres fixture.

    In CI these tests MUST run, not skip: the atomicity guarantee this backend exists to
    provide is exactly the kind of claim a silent skip would let rot. So when CI is detected
    and no server can be obtained, fail loudly instead — matching conftest.py's own stated
    principle that "a green run that silently tested nothing would be the single worst
    outcome." Locally, skipping is the right courtesy for a developer without docker.
    """
    preset = os.environ.get("ACROPOLIS_TEST_VALKEY_URL")
    if preset:
        _wait_ready(preset)
        yield preset
        return

    if not _docker_available():
        message = (
            "no Valkey available: docker is unusable and ACROPOLIS_TEST_VALKEY_URL is unset"
        )
        if os.environ.get("CI"):
            raise RuntimeError(
                f"{message}. These tests must not skip in CI — add a valkey service container "
                "or set ACROPOLIS_TEST_VALKEY_URL."
            )
        pytest.skip(message)

    url = _start_container()
    try:
        _wait_ready(url)
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True)


@pytest.fixture
async def backend(valkey_url):
    b = build_valkey_backend(valkey_url)
    await b._client.flushall()  # isolate each test from the last
    yield b
    await b._client.aclose()


async def test_limit_is_enforced_like_the_in_memory_backend(backend):
    """The operator-facing contract: '3/hour' means 3, in this backend exactly as in
    InMemoryBackend. A backend switch must not silently change what a spec means."""
    backend.register("k", "3/hour")
    results = [await backend.check("k") for _ in range(5)]
    assert results == [True, True, True, False, False]


async def test_unregistered_key_is_unlimited(backend):
    for _ in range(20):
        assert await backend.check("unregistered") is True


async def test_concurrent_consumers_cannot_exceed_the_limit(backend):
    """The reason this backend uses a Lua script rather than GET/compute/SET.

    50 concurrent checks against a limit of 10 must let through EXACTLY 10. A read-then-write
    sequence from concurrent callers would race between the read and the write and let more
    through — the precise burst-shaped failure a rate limiter exists to prevent, so a
    distributed backend that inherited it would defeat its own purpose."""
    backend.register("burst", "10/hour")
    results = await asyncio.gather(*[backend.check("burst") for _ in range(50)])
    assert sum(results) == 10


async def test_two_backend_instances_share_one_limit(valkey_url):
    """The actual multi-replica requirement (issue #31's acceptance criteria): a shared limit
    holds across separate backend instances, which is what two replicas of the gateway are.

    With InMemoryBackend this test would let 8 through (4 per instance), not 4 — that
    doubling is the bug this whole issue exists to fix."""
    a = build_valkey_backend(valkey_url)
    b = build_valkey_backend(valkey_url)
    await a._client.flushall()
    try:
        a.register("shared", "4/hour")
        b.register("shared", "4/hour")

        results = []
        for i in range(6):
            results.append(await (a if i % 2 == 0 else b).check("shared"))

        assert results == [True, True, True, True, False, False]
        assert sum(results) == 4, "the limit must be 4 across both instances, not 4 each"
    finally:
        await a._client.aclose()
        await b._client.aclose()


async def test_check_all_is_all_or_nothing(backend):
    backend.register("a", "1/hour")
    backend.register("b", "100/hour")
    assert await backend.check_all(["a", "b"]) is True
    assert await backend.check_all(["a", "b"]) is False  # 'a' exhausted


async def test_ensure_current_preserves_state_when_spec_unchanged(backend):
    """Same F8 guarantee InMemoryBackend makes — ensure_current on an unchanged spec must not
    reset consumed tokens, or calling it per-request (which Pipeline does) defeats the limit."""
    backend.register("k", "2/hour")
    assert await backend.check("k") is True
    backend.ensure_current("k", "2/hour")
    assert await backend.check("k") is True
    backend.ensure_current("k", "2/hour")
    assert await backend.check("k") is False


async def test_register_rejects_a_malformed_spec(backend):
    """Eagerly, where an operator is saving a policy — not on the next tools/call."""
    with pytest.raises(ValueError):
        backend.register("k", "not-a-spec")


async def test_unavailable_backend_fails_closed():
    """Issue #31's fail-closed decision, against a genuinely dead server (nothing listening).

    Must raise RateLimitBackendUnavailable — never return True. Returning True here would mean
    an adversary can bypass every configured limit by making the backend unreachable, which is
    strictly easier than defeating the limiter itself."""
    dead = build_valkey_backend("redis://127.0.0.1:6399/0")
    dead.register("k", "5/minute")
    try:
        with pytest.raises(RateLimitBackendUnavailable):
            await dead.check("k")
        with pytest.raises(RateLimitBackendUnavailable):
            await dead.check_all(["k"])
    finally:
        await dead._client.aclose()


async def test_unregistered_key_does_not_touch_an_unavailable_backend():
    """An unregistered key is unlimited by contract, so it must not consult the server at all —
    and therefore must not fail closed even when the server is down. Otherwise a Valkey outage
    would 429 every request to every server that has no rate limit configured."""
    dead = build_valkey_backend("redis://127.0.0.1:6399/0")
    try:
        assert await dead.check("never-registered") is True
    finally:
        await dead._client.aclose()


async def test_backend_satisfies_the_protocol(backend):
    from argus.rate_limiter import RateLimitBackend

    assert isinstance(backend, RateLimitBackend)


async def test_idle_buckets_expire(backend):
    """Buckets get a TTL so a gateway with churning server slugs doesn't leak keys forever."""
    backend.register("ttl", "5/second")
    await backend.check("ttl")
    ttl = await backend._client.ttl(f"{backend._prefix}ttl")
    assert 0 < ttl <= 10, f"expected a bounded TTL, got {ttl}"
