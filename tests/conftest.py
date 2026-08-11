"""Test-suite Postgres provisioning (enterprise #7, issue #8).

Before the cutover, every test built its own store by handing `Database` a pytest `tmp_path` —
isolation came free, because each test got its own directory and therefore its own SQLite files.
Postgres has no equivalent of "a fresh file per test", so that isolation has to be manufactured.

Strategy: ONE Postgres server for the whole session (a real one — the suite never mocks the
database, per the plan's "the service container is a normal postgres: image, not a mock"), and
one freshly-created, separately-named DATABASE per test that needs a store. A brand-new database
per test is slower than truncating tables between tests, but it is the only option that also
exercises the migration runner from empty on every single test — which, for a change whose whole
risk surface is "did the schema port faithfully", is worth the seconds it costs. It also means no
test can ever be polluted by a predecessor's rows, matching the pre-cutover guarantee exactly.

Where the server comes from:
  - ACROPOLIS_TEST_DATABASE_URL, if set, points at an already-running Postgres (this is what CI
    uses — the workflow's `postgres:` service container — and what a developer with a local
    instance uses).
  - Otherwise the suite starts one via `docker run postgres:17-alpine` and tears it down at the
    end of the session.
  - If neither is possible, collection fails loudly with an actionable message rather than
    skipping. There is no SQLite path left to silently fall back to, and a green run that
    silently tested nothing would be the single worst outcome of this cutover.

`Database` no longer takes a path, but ~50 existing test modules call `Database(tmp_path)`. Rather
than edit every one of them to thread a URL through, `Database.__init__` is left URL-only and this
module provides an autouse fixture that makes the legacy call shape work: see `_patch_database`
below for exactly what it does and why that indirection is preferable to a 50-file mechanical diff
inside an already-large change.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import subprocess
import time
import uuid

import asyncpg
import pytest

import db.database as db_database


def _run_sync(coro_factory, timeout: float = 120.0):
    """Run an async helper from SYNCHRONOUS fixture code.

    pytest-asyncio runs in `asyncio_mode = "auto"` (see pyproject.toml), so by the time a fixture
    body executes there is often already a running event loop on this thread — and
    `asyncio.run()` refuses to nest inside one. These provisioning helpers (CREATE DATABASE /
    DROP DATABASE / readiness probe) are administrative, must complete before the test's own loop
    does anything, and must not join the test's loop (a connection opened on it would outlive the
    fixture). Running each on its own thread with its own fresh loop keeps them completely
    independent of whatever loop the test is using.

    The explicit timeout matters: `ThreadPoolExecutor.__exit__` joins its worker, so a helper that
    blocks forever (e.g. a DROP DATABASE waiting behind a connection that hasn't finished closing)
    would hang the whole suite in fixture teardown with no traceback pointing at the cause. Better
    to raise and let the caller decide — cleanup callers swallow it, provisioning callers don't.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro_factory())).result(timeout=timeout)

_CONTAINER_NAME = "acropolis-pytest-pg"
_PG_IMAGE = "postgres:17-alpine"
_PG_PORT = 55433
_PG_USER = "acropolis"
_PG_PASSWORD = "acropolis-test"
_ADMIN_DB = "postgres"


def _admin_dsn(base: str, dbname: str = _ADMIN_DB) -> str:
    """Rewrite a DSN's database name, keeping credentials/host/port."""
    head, _, _tail = base.rpartition("/")
    return f"{head}/{dbname}"


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
            "docker", "run", "-d", "--name", _CONTAINER_NAME,
            "-e", f"POSTGRES_USER={_PG_USER}",
            "-e", f"POSTGRES_PASSWORD={_PG_PASSWORD}",
            "-e", f"POSTGRES_DB={_ADMIN_DB}",
            "-p", f"{_PG_PORT}:5432",
            # Test-only tuning: these trade crash durability for speed. Safe here precisely
            # because a test database is disposable — never put these in a real deployment.
            _PG_IMAGE, "-c", "fsync=off", "-c", "synchronous_commit=off",
            "-c", "full_page_writes=off", "-c", "max_connections=300",
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to start test Postgres container: {proc.stderr}")
    return f"postgresql://{_PG_USER}:{_PG_PASSWORD}@127.0.0.1:{_PG_PORT}/{_ADMIN_DB}"


def _wait_ready(dsn: str, timeout: float = 60.0) -> None:
    async def _probe() -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                conn = await asyncpg.connect(dsn)
                await conn.close()
                return
            except Exception as e:  # noqa: BLE001 — any connect failure is "not ready yet"
                last = e
                await asyncio.sleep(0.3)
        raise RuntimeError(f"test Postgres never became ready within {timeout}s: {last}")

    _run_sync(_probe)


@pytest.fixture(scope="session")
def postgres_admin_dsn():
    """A DSN pointing at a live Postgres server's maintenance database.

    Session-scoped: the server is started at most once per run, and torn down at the end only if
    this fixture is what started it (an operator-provided ACROPOLIS_TEST_DATABASE_URL instance is
    never touched).
    """
    external = os.environ.get("ACROPOLIS_TEST_DATABASE_URL")
    if external:
        _wait_ready(external)
        try:
            yield external
        finally:
            _drop_leftover_databases(external)
        return

    if not _docker_available():
        raise RuntimeError(
            "This suite requires a real Postgres. Set ACROPOLIS_TEST_DATABASE_URL to a running "
            "instance, or make `docker` available so one can be started automatically. There is "
            "no SQLite fallback as of enterprise #7 (issue #8)."
        )

    dsn = _start_container()
    try:
        _wait_ready(dsn)
        yield dsn
    finally:
        _drop_leftover_databases(dsn)
        subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True)


def _create_database(admin_dsn: str) -> str:
    """Create a uniquely-named empty database and return its DSN."""
    name = f"acropolis_test_{uuid.uuid4().hex[:16]}"

    async def _go() -> None:
        conn = await asyncpg.connect(_admin_dsn(admin_dsn))
        try:
            # CREATE DATABASE cannot run inside a transaction block; asyncpg's execute() runs it
            # in autocommit here because no explicit transaction is open.
            await conn.execute(f'CREATE DATABASE "{name}"')
        finally:
            await conn.close()

    _run_sync(_go)
    return _admin_dsn(admin_dsn, name)


def _drop_database(admin_dsn: str, dsn: str) -> None:
    """Drop one test database, best-effort and time-bounded.

    `WITH (FORCE)` terminates any connection the test left open, so a pool that wasn't explicitly
    closed can't wedge the drop. Even so this is wrapped in a short timeout and a bare except:
    per-test cleanup must NEVER be able to fail or hang a test that already passed. Anything that
    survives lands in _LEAKED and gets one more attempt at session end (see
    _drop_leftover_databases), and failing even that only leaves a stray database in a
    throwaway test server.

    Why this is defensive rather than paranoid: a test's app pools are closed by the test's own
    fixture teardown, which runs on the test's event loop, while this runs on a different thread
    with its own loop. Those two are not ordered with respect to each other, so this call can
    legitimately arrive while connections are still going away.
    """
    name = dsn.rpartition("/")[2]

    async def _go() -> None:
        conn = await asyncpg.connect(_admin_dsn(admin_dsn), timeout=10)
        try:
            await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            await conn.close()

    try:
        _run_sync(_go, timeout=20.0)
    except Exception:  # noqa: BLE001 — cleanup must never fail or hang a passing test
        _LEAKED.append(dsn)


# Databases whose per-test drop didn't succeed in time; retried once at session end.
_LEAKED: list[str] = []


def _drop_leftover_databases(admin_dsn: str) -> None:
    for dsn in list(_LEAKED):
        name = dsn.rpartition("/")[2]

        async def _go(n=name) -> None:
            conn = await asyncpg.connect(_admin_dsn(admin_dsn), timeout=10)
            try:
                await conn.execute(f'DROP DATABASE IF EXISTS "{n}" WITH (FORCE)')
            finally:
                await conn.close()

        try:
            _run_sync(_go, timeout=20.0)
        except Exception:  # noqa: BLE001
            pass
    _LEAKED.clear()


@pytest.fixture(autouse=True)
def _patch_database(request, postgres_admin_dsn, monkeypatch):
    """Make the legacy `Database(tmp_path)` call shape resolve to a per-test Postgres database.

    ~50 existing test modules construct their store as `Database(tmp_path)` — the pre-cutover
    signature, where the argument was a data directory. Post-cutover `Database` takes a Postgres
    DSN and nothing else. Rather than mechanically rewrite 50 files (and every fixture that
    threads `tmp_path` through helper functions) inside a change that is already very large, this
    autouse fixture wraps the constructor: a `Path` argument — or any falsy/`tmp_path`-shaped
    value — is translated to a freshly-created, uniquely-named Postgres database for this test.

    This is a TEST-ONLY affordance and is deliberately narrow: it only rewrites arguments that
    are NOT already a Postgres DSN string, so a test that wants to pass a real URL (the
    two-instance concurrency test, which must point two Databases at the SAME database) does so
    and is passed through untouched.

    Databases are created lazily — a test that never constructs a Database pays nothing — and
    dropped after the test regardless of outcome.

    Bug fix (found running the full suite against real Postgres, post-cutover): the pre-cutover
    semantic of `Database(tmp_path)` was "one on-disk directory, therefore one logical
    database" — a test whose fixtures independently construct multiple `Database(tmp_path)`
    objects against the SAME tmp_path (e.g. one fixture for a bare `db` handle, another for the
    `api_client` app's own store — several files in this suite do exactly this) got them all
    pointed at the same SQLite file for free, because the path itself was the identity. The
    original version of this patch created a FRESH, DIFFERENT Postgres database on every call
    regardless of the `dsn` argument's identity, silently breaking that assumption: two
    `Database(tmp_path)` calls in the same test ended up on two disconnected databases, so a
    write through one fixture's app was invisible to a read through the other fixture's direct
    handle — not a Postgres consistency issue, a fixture-identity issue. Caching by the
    argument's `id()` (works for both `tmp_path` and its stringified form, since a test always
    passes the SAME Path/str object it received from the `tmp_path` fixture, not a copy)
    restores the original one-argument-one-database semantic exactly.
    """
    created: list[str] = []
    by_arg_identity: dict[int, str] = {}
    real_init = db_database.Database.__init__

    def patched_init(self, dsn=None, **kwargs):
        if not isinstance(dsn, str) or not dsn.startswith("postgres"):
            key = id(dsn)
            if key not in by_arg_identity:
                by_arg_identity[key] = _create_database(postgres_admin_dsn)
                created.append(by_arg_identity[key])
            dsn = by_arg_identity[key]
        return real_init(self, dsn, **kwargs)

    monkeypatch.setattr(db_database.Database, "__init__", patched_init)
    try:
        yield
    finally:
        for dsn in created:
            _drop_database(postgres_admin_dsn, dsn)


@pytest.fixture
def pg_dsn(postgres_admin_dsn):
    """An empty, uniquely-named Postgres database, for tests that need the URL directly.

    Used by the two-instance concurrency test (two `Database` objects, ONE database) and by the
    raw-bytes canary tests, which connect with a bare asyncpg connection to inspect stored bytes
    outside the repo layer.
    """
    dsn = _create_database(postgres_admin_dsn)
    try:
        yield dsn
    finally:
        _drop_database(postgres_admin_dsn, dsn)

import httpx
from dataclasses import dataclass
from fastapi import FastAPI
from archon.settings import Settings
from argus.app import create_app
from db.database import Database
import pytest

@dataclass
class AppEnv:
    app: FastAPI
    transport: httpx.ASGITransport
    db: Database
    settings: Settings

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, base_url="http://argus.test")

@pytest.fixture
async def app_env(tmp_path, request):
    overrides = getattr(request, "param", {})
    probe_on_create = overrides.pop("probe_on_create", True)
    settings = Settings(
        data_dir=str(tmp_path),
        auth_mode=overrides.pop("auth_mode", "open"),
        health_poll_enabled=overrides.pop("health_poll_enabled", False),
        audit_retention_enabled=overrides.pop("audit_retention_enabled", False),
        **overrides,
    )
    db = Database(tmp_path)
    await db.connect()
    try:
        app = create_app(settings, db, enable_health_probing=probe_on_create)
        transport = httpx.ASGITransport(app=app)
        async with app.router.lifespan_context(app):
            yield AppEnv(app=app, transport=transport, db=db, settings=settings)
    finally:
        await db.close()

@pytest.fixture
async def api_client(app_env):
    async with app_env.client() as client:
        yield client

@pytest.fixture
async def admin_client(app_env):
    async with app_env.client() as client:
        resp = await client.post(
            "/api/v1/setup", json={"admin_password": "test-admin-password-1"}
        )
        assert resp.status_code == 200, f"setup failed in admin_client fixture: {resp.text}"
        yield client

async def login_as(app_env: AppEnv, username: str, password: str) -> httpx.AsyncClient:
    client = app_env.client()
    resp = await client.post(
        "/api/v1/login", json={"username": username, "admin_password": password}
    )
    if resp.status_code != 200:
        await client.aclose()
        raise AssertionError(f"login failed for {username!r}: {resp.status_code} {resp.text}")
    return client
