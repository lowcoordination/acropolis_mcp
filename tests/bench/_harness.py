"""Shared machinery for tests/bench/*.py measurement tools.

House style: benches are standalone `python -m tests.bench.bench_*` scripts (never pytest),
each isolating one subsystem, each feeding a named go/no-go decision, results checked into
tests/bench/results/ with machine + repro command + git SHA. This module holds the machinery
the benches share so a sixth copy of `_percentile` never gets written: statistics, timing,
the canonical representative argument shapes, quiet logging, the --smoke convention, the
results writer, and Postgres/Valkey provisioning (generalized from tests/conftest.py and
tests/integration/test_rate_limit_valkey.py).

Scope note: this module is deliberately pure machinery. Bench-specific policy objects,
argument shapes that only one bench uses, and the question/decision/scope narrative stay in
each bench's own module — the story stays local, only the math moves (see the epic's harness
issue for that decision).
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import os
import platform
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "tests" / "bench" / "results"


# ---------------------------------------------------------------------------
# --smoke convention
# ---------------------------------------------------------------------------
# `python -m tests.bench.bench_<name> --smoke` floors every iteration count so the bench
# completes in seconds. Smoke asserts NO numbers: its only job is proving the bench still
# runs (CI wires it as a runnability gate — see the epic's CI issue). A bench author
# expresses every iteration constant as `iters(NORMAL, SMOKE_FLOOR)`.

SMOKE = "--smoke" in sys.argv


def iters(normal: int, smoke: int) -> int:
    """Return `normal` normally, `smoke` under --smoke."""
    return smoke if SMOKE else normal


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------


def percentile(samples: list[float], pct: float) -> float:
    """Percentile of measured ms samples.

    The >=100-sample guard is load-bearing, not cosmetic: statistics.quantiles(n=100)
    requires at least 100 samples to produce a p99, and smoke mode deliberately runs with
    far fewer samples than that.
    """
    if len(samples) >= 100:
        return statistics.quantiles(samples, n=100)[int(pct) - 1]
    return max(samples)


# ---------------------------------------------------------------------------
# representative arguments
# ---------------------------------------------------------------------------


def representative_arguments(size_label: str) -> dict:
    """The canonical small/medium/large argument shapes shared by every bench.

    Cross-bench comparability depends on these staying byte-identical — bench_otel's
    docstring states its numbers are comparable to bench_dlp's *because* the shapes match.
    Change them only with that contract in mind.
    """
    filler = (
        "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet, consectetur "
        "adipiscing elit. "
    )
    if size_label == "small":
        return {"query": "find all TODO comments in the repo", "limit": 20}
    if size_label == "medium":
        return {"message": filler * 10, "channel": "general"}
    if size_label == "large":
        return {"content": filler * 200, "path": "/tmp/report.txt"}
    raise ValueError(size_label)


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------


def quiet_logging() -> None:
    """Suppress every logger below WARNING — benches drive thousands of real requests
    (audit logging, httpx request logging, FastMCP's own request logging all fire per call)
    and the resulting console noise makes the actual results hard to find. Mirrors the
    house "print exactly the table, nothing else load-bearing" output discipline."""
    logging.basicConfig(level=logging.WARNING)
    for name in ("argus", "archon", "stoa", "httpx", "httpcore", "mcp", "uvicorn"):
        logging.getLogger(name).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# timing
# ---------------------------------------------------------------------------


async def time_call(fn, iterations: int) -> list[float]:
    """Time `iterations` awaited calls of `fn` (a zero-arg callable returning an awaitable),
    returning per-call ms samples via time.perf_counter.

    Warmup is the caller's job — every bench warms up explicitly (the forkserver's first
    spawn is meaningfully slower than steady state, see argus/policy.py).
    """
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        await fn()
        samples.append((time.perf_counter() - start) * 1000)  # ms
    return samples


def print_latency_table(label: str, results: list[dict]) -> None:
    """Print an on/off added-latency table (the bench_dlp / bench_otel shape).

    `results` entries need: size_label, arg_bytes, off_p50, off_p99, on_p50, on_p99.
    """
    print(f"\n--- {label} ---")
    print(f"{'size':<8} {'arg bytes':>10} {'off p50':>9} {'off p99':>9} {'on p50':>9} {'on p99':>9} {'added p50':>10} {'added p99':>10}")
    for r in results:
        added_p50 = r["on_p50"] - r["off_p50"]
        added_p99 = r["on_p99"] - r["off_p99"]
        print(
            f"{r['size_label']:<8} {r['arg_bytes']:>10} {r['off_p50']:>8.3f}ms {r['off_p99']:>8.3f}ms "
            f"{r['on_p50']:>8.3f}ms {r['on_p99']:>8.3f}ms {added_p50:>9.3f}ms {added_p99:>9.3f}ms"
        )


# ---------------------------------------------------------------------------
# results writer
# ---------------------------------------------------------------------------


def markdown_table(headers: list[str], rows: list[list]) -> str:
    """Render headers/rows as a GitHub-flavored markdown pipe table (for the results
    files write_results produces). Cells are str()'d; the console print path uses the same
    rendering so what the bench prints and what lands in the results file never drift."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n"


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def write_results(slug: str, tables_markdown: str, module: str | None = None) -> Path:
    """Write tests/bench/results/<slug>-<YYYY-MM-DD>.md and return its path.

    Stamps date, machine, Python version, the git SHA the numbers were measured against, and
    the repro command; embeds the bench's tables; leaves a hand-written `## Verdict`
    placeholder. The verdict is the point of the exercise (house style: numbers feed a named
    go/no-go decision) and is deliberately NOT generated — a measurement tool must not write
    its own conclusion.

    `module` is the bench's module name for the repro command (defaults to `slug`, which is
    right for the common `bench_<slug>.py` naming; pass it explicitly otherwise, e.g.
    slug="pipeline-baseline" with module="bench_pipeline").

    Raises FileExistsError if a results file for this slug+date already exists — a results
    file is a historical record, and silently overwriting one would destroy the evidence a
    decision was made on.
    """
    if module is None:
        module = slug
    today = datetime.date.today().isoformat()
    machine = platform.uname()
    header = (
        f"# {slug} — benchmark results\n\n"
        f"Measured {today} with `python -m tests.bench.{module}` "
        f"(harness commit `{_git_sha()}`). Machine: {machine.node} ({machine.system}, "
        f"{machine.machine}), Python {platform.python_version()}.\n\n"
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"{slug}-{today}.md"
    if path.exists():
        raise FileExistsError(
            f"{path} already exists — results files are historical records. Choose a "
            "distinct slug (e.g. add a variant label) rather than overwriting it."
        )
    path.write_text(header + tables_markdown + "\n## Verdict\n\n(TBD — hand-written go/no-go per house style)\n")
    return path


# ---------------------------------------------------------------------------
# Postgres / Valkey provisioning
# ---------------------------------------------------------------------------
# Generalized from tests/conftest.py (Postgres) and tests/integration/test_rate_limit_valkey.py
# (Valkey): same sourcing order (operator env var -> docker run -> loud failure, never a
# silent skip — a green run that silently measured nothing is the failure mode), same
# disposable-server tuning. Container names and ports are deliberately DISTINCT from the
# pytest suite's (acropolis-pytest-pg:55433, acropolis-test-valkey:63801) so a bench and a
# test run can coexist on one machine.

_PG_IMAGE = "postgres:17-alpine"
_PG_CONTAINER = "acropolis-bench-pg"
_PG_PORT = 55434
_PG_USER = "acropolis"
_PG_PASSWORD = "acropolis-bench"
_ADMIN_DB = "postgres"

_VALKEY_IMAGE = "valkey/valkey:8-alpine"
_VALKEY_CONTAINER = "acropolis-bench-valkey"
_VALKEY_PORT = 63802

_started_containers: list[str] = []
_created_databases: list[str] = []


def _docker_available() -> bool:
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _fail_loudly(what: str, env_var: str) -> None:
    message = (
        f"no {what} available for this bench: set {env_var} to a running instance, "
        "or make `docker` usable so one can be started automatically. A bench never "
        "silently skips — that would be a green run that measured nothing."
    )
    if os.environ.get("CI"):
        raise RuntimeError(f"{message} (CI requires the {env_var} service container or docker.)")
    raise RuntimeError(message)


def _admin_dsn(base: str, dbname: str = _ADMIN_DB) -> str:
    """Rewrite a DSN's database name, keeping credentials/host/port."""
    head, _, _tail = base.rpartition("/")
    return f"{head}/{dbname}"


def _start_pg_container() -> str:
    """docker run a disposable Postgres (test-only tuning, mirroring conftest.py) and return
    the admin DSN. Readiness is the caller's job (await _wait_pg_ready) — starting is sync,
    waiting must happen inside the bench's own event loop."""
    subprocess.run(["docker", "rm", "-f", _PG_CONTAINER], capture_output=True)
    proc = subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", _PG_CONTAINER,
            "-e", f"POSTGRES_USER={_PG_USER}",
            "-e", f"POSTGRES_PASSWORD={_PG_PASSWORD}",
            "-e", f"POSTGRES_DB={_ADMIN_DB}",
            "-p", f"{_PG_PORT}:5432",
            _PG_IMAGE, "-c", "fsync=off", "-c", "synchronous_commit=off",
            "-c", "full_page_writes=off", "-c", "max_connections=300",
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to start bench Postgres container: {proc.stderr}")
    _started_containers.append(_PG_CONTAINER)
    return f"postgresql://{_PG_USER}:{_PG_PASSWORD}@127.0.0.1:{_PG_PORT}/{_ADMIN_DB}"


async def _wait_pg_ready(dsn: str, timeout: float = 60.0) -> None:
    """Await the server accepting connections, as an INLINE loop — benches call this from
    inside their own running event loop, so asyncio.run() is unavailable by design."""
    import asyncpg  # local import: keeps this module importable without the app's deps

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
    raise RuntimeError(f"bench Postgres never became ready within {timeout}s: {last}")


def _start_valkey_container() -> str:
    """docker run a disposable Valkey and return the URL. Readiness is the caller's job
    (await _wait_valkey_ready)."""
    subprocess.run(["docker", "rm", "-f", _VALKEY_CONTAINER], capture_output=True)
    proc = subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", _VALKEY_CONTAINER,
            "-p", f"{_VALKEY_PORT}:6379", _VALKEY_IMAGE,
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to start bench Valkey container: {proc.stderr}")
    _started_containers.append(_VALKEY_CONTAINER)
    return f"redis://127.0.0.1:{_VALKEY_PORT}/0"


async def _wait_valkey_ready(url: str, timeout: float = 30.0) -> None:
    """Await the server answering PING, as an inline loop (see _wait_pg_ready)."""
    from redis.asyncio import Redis

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
    raise RuntimeError(f"bench Valkey never became ready within {timeout}s: {last}")


async def postgres_url() -> str:
    """A DSN to a freshly-created, uniquely-named Postgres database on a live server.

    Sourcing (same order as conftest.py): ACROPOLIS_TEST_DATABASE_URL if set (used as the
    admin DSN — the operator-provided server is never touched beyond creating the bench's
    own database), otherwise a disposable `docker run postgres:17-alpine`. Fails loudly,
    never skips — see _fail_loudly.

    Every call returns a fresh database (mirroring conftest's per-test isolation), so a
    bench that wants several isolated stores just calls it again. `stop_infra()` drops every
    database and removes every container this process created.
    """
    external = os.environ.get("ACROPOLIS_TEST_DATABASE_URL")
    if external is None and not _docker_available():
        _fail_loudly("Postgres", "ACROPOLIS_TEST_DATABASE_URL")
    admin_dsn = external if external is not None else _start_pg_container()
    await _wait_pg_ready(admin_dsn)

    name = f"acropolis_bench_{uuid.uuid4().hex[:12]}"

    async def _create() -> None:
        import asyncpg  # local import: keeps this module importable without the app's deps

        conn = await asyncpg.connect(_admin_dsn(admin_dsn))
        try:
            # CREATE DATABASE cannot run inside a transaction block; asyncpg's execute() runs
            # it in autocommit here because no explicit transaction is open.
            await conn.execute(f'CREATE DATABASE "{name}"')
        finally:
            await conn.close()

    await _create()
    _created_databases.append(name)
    return _admin_dsn(admin_dsn, name)


async def valkey_url() -> str:
    """A URL to a live Valkey server.

    Sourcing (same order as test_rate_limit_valkey.py): ACROPOLIS_TEST_VALKEY_URL if set,
    otherwise a disposable `docker run valkey/valkey:8-alpine`. Fails loudly, never skips.
    `stop_infra()` removes any container this process started. The operator-provided server
    is not flushed or otherwise touched by provisioning — the bench decides what to flush.
    """
    preset = os.environ.get("ACROPOLIS_TEST_VALKEY_URL")
    if preset is not None:
        return preset
    if not _docker_available():
        _fail_loudly("Valkey", "ACROPOLIS_TEST_VALKEY_URL")
    url = _start_valkey_container()
    await _wait_valkey_ready(url)
    return url


def valkey_container_name() -> str | None:
    """Name of the Valkey container THIS process started, or None when the bench is running
    against an operator-provided server (ACROPOLIS_TEST_VALKEY_URL).

    Lets a bench do container-level things (e.g. `docker pause` for a degraded-mode
    measurement) only to infrastructure it owns — never to a server the operator supplied.
    """
    if _VALKEY_CONTAINER in _started_containers:
        return _VALKEY_CONTAINER
    return None


async def stop_infra() -> None:
    """Drop every database and remove every container this process created — call in a
    finally after provisioning. Best-effort on drops (mirroring conftest's cleanup-must-never-
    fail discipline); container removal is unconditional."""
    if _created_databases:
        import asyncpg  # local import: keeps this module importable without the app's deps

        # Admin DSN for whatever server each database lives on — currently always the same
        # one, but track it per-database so this stays honest if sourcing ever fans out.
        admin_dsn = os.environ.get("ACROPOLIS_TEST_DATABASE_URL")
        if admin_dsn is None:
            admin_dsn = f"postgresql://{_PG_USER}:{_PG_PASSWORD}@127.0.0.1:{_PG_PORT}/{_ADMIN_DB}"

        async def _drop(name: str) -> None:
            conn = await asyncpg.connect(_admin_dsn(admin_dsn), timeout=10)
            try:
                await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            finally:
                await conn.close()

        for name in _created_databases:
            try:
                await _drop(name)
            except Exception:  # noqa: BLE001 — cleanup must never fail the bench's verdict
                pass
        _created_databases.clear()

    for container in _started_containers:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    _started_containers.clear()
