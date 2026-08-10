"""Enterprise #9 (OTel tracing) — proves the app genuinely runs correctly when the `otel`
optional dependency group is NOT installed at all, both with tracing off (the common case: base
install, nothing OTel-related present) and with ACROPOLIS_OTEL_ENABLED=true set anyway (the
"operator flipped the gate on a base install" case, which must degrade to a logged warning, not
a crash).

A genuine proof, not a code-review claim: builds a REAL, throwaway virtualenv containing only
this project's base + `dev` dependencies (deliberately excluding the `otel` extra), then runs a
small script inside THAT venv's own interpreter via subprocess — the only way to actually prove
"opentelemetry is not importable" rather than asserting it via a mocked ImportError in-process
(which tests the code path but not the real-world claim). tests/unit/test_tracing.py's
import-guard tests are the fast in-process companion to this slower, but more honest, one.

Session-scoped venv build (~5-10s, one-time per test run) — this is a "measurement tool" style
test in spirit (see tests/bench/bench_dlp.py's similar "not a fast unit test" framing), so it's
acceptable for it to be slower than the rest of the suite; it is still a real, always-run pytest
test, not a separately-invoked script, so CI catches a regression here automatically.

INCIDENT (review 2026-08-10): a `pip install` inside a fresh venv is a real PyPI round-trip,
which is fast and cache-warm locally but not on a CI runner rebuilding from scratch mid-suite.
Under degraded runner network conditions, `subprocess.run(timeout=...)`'s own timeout didn't
fire cleanly here — a build-backend grandchild pip spawns can outlive the direct child's kill
and keep the output pipe open, so `subprocess.run` blocks in `communicate()` past the stated
deadline. See `_run_with_hard_timeout` below (process-group kill via `start_new_session=True`
+ `os.killpg`) for the fix, and `.github/workflows/ci.yml`'s `Run pytest` step timeout for the
outer backstop in case a future failure mode isn't one this specific fix covers.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_with_hard_timeout(args: list[str], *, timeout: float, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run(..., timeout=...) wrapper that actually enforces the deadline (incident,
    review 2026-08-10 — see CI's own `Run pytest` step timeout comment in
    .github/workflows/ci.yml for the failure this fixes).

    Plain `subprocess.run(timeout=N)` only kills the DIRECT child on timeout. `pip install`
    routinely spawns grandchildren (a build backend subprocess for a wheel/sdist build, a
    resolver worker) that are NOT in that kill's blast radius — if one of those is still alive
    and holding the child's stdout/stderr pipe open (e.g. blocked on its own I/O under degraded
    runner network conditions), `Popen.kill()` on the direct child returns immediately but the
    subsequent `communicate()`/`wait()` used internally by `subprocess.run` can still block
    forever reading from that pipe. This is exactly what happened in CI: the 180s timeout never
    fired, and with no job-level timeout either, the run sat for 12+ minutes with zero output
    before being manually cancelled.

    Fix: `start_new_session=True` puts the child in its own process GROUP, and on timeout we
    kill the whole group (`os.killpg`) rather than just the one process `subprocess.run` would
    reach — every descendant dies together, so nothing is left holding the pipe open.

    Takes the same `capture_output=True, text=True` call shape as subprocess.run for a
    drop-in swap at each call site, but Popen itself doesn't accept `capture_output` (it's a
    subprocess.run-only convenience that expands to stdout=PIPE, stderr=PIPE) — translated here
    so callers don't need to know that."""
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    proc = subprocess.Popen(args, start_new_session=True, **kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # already exited between the timeout firing and us getting here
        stdout, stderr = proc.communicate()  # drain what's left; process group is dead now
        raise subprocess.TimeoutExpired(args, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)


@pytest.fixture(scope="session")
def no_otel_venv(tmp_path_factory):
    """A real venv with acropolis[dev] installed but NOT acropolis[otel] — proving the base
    install (what CI's non-otel job and every real user who never opts in actually gets) is
    genuinely free of the opentelemetry package tree, not just "we didn't add it to
    dependencies and hope nothing transitively pulls it in"."""
    venv_dir = tmp_path_factory.mktemp("no_otel_venv")
    venv.EnvBuilder(with_pip=True, symlinks=True).create(venv_dir)
    python = venv_dir / "bin" / "python"

    result = _run_with_hard_timeout(
        [str(python), "-m", "pip", "install", "-q", "-e", f"{REPO_ROOT}[dev]"],
        capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, (
        f"failed to build the no-otel venv:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return python


def _run_script(python: Path, script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return _run_with_hard_timeout(
        [str(python), "-c", textwrap.dedent(script)],
        capture_output=True, text=True, timeout=60, env=full_env, cwd=str(REPO_ROOT),
    )


class TestOtelGenuinelyAbsent:
    def test_opentelemetry_is_not_importable_in_this_venv(self, no_otel_venv):
        """Sanity check on the fixture itself — if this fails, the venv build didn't actually
        exclude the otel extra and every other test in this file is proving nothing."""
        result = _run_script(no_otel_venv, """
            import sys
            try:
                import opentelemetry  # noqa: F401
                sys.exit(1)  # FAIL: it's installed
            except ImportError:
                sys.exit(0)  # correct: genuinely absent
        """)
        assert result.returncode == 0, (
            f"opentelemetry IS importable in the 'no otel' venv — fixture is broken.\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )

    def test_app_boots_and_serves_with_tracing_disabled(self, no_otel_venv, pg_dsn):
        """The default, overwhelmingly common case: no ACROPOLIS_OTEL_ENABLED at all, no otel
        installed. The app must start, run its lifespan, and handle a request — completely
        unaffected by this feature's existence.

        Postgres cutover (enterprise #7): `Database` is URL-only. This script runs in a
        SEPARATE subprocess/venv (the whole point of this test file), so it is outside
        conftest.py's autouse `_patch_database` fixture, which only wraps the constructor inside
        THIS pytest process — the subprocess needs a real DSN passed in explicitly. `pg_dsn`
        gives a fresh, uniquely-named database exactly like every other test that needs one
        directly."""
        result = _run_script(no_otel_venv, f"""
            import asyncio
            import httpx
            from archon.settings import Settings
            from argus.app import create_app
            from db.database import Database

            async def main():
                settings = Settings(
                    database_url={pg_dsn!r}, auth_mode="open",
                    health_poll_enabled=False, audit_retention_enabled=False,
                )
                db = Database({pg_dsn!r})
                await db.connect()
                app = create_app(settings, db)
                async with app.router.lifespan_context(app):
                    assert app.state.tracing.active is False
                    assert app.state.tracing.enabled is False
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                        resp = await client.get("/api/v1/health")
                        assert resp.status_code == 200, resp.text
                await db.close()
                print("SUBPROCESS_OK")

            asyncio.run(main())
        """, env={"ACROPOLIS_OTEL_ENABLED": ""})
        assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
        assert "SUBPROCESS_OK" in result.stdout

    def test_app_boots_with_otel_enabled_env_var_but_package_absent(self, no_otel_venv, pg_dsn):
        """The genuinely interesting case: an operator sets ACROPOLIS_OTEL_ENABLED=true on a
        base install that never got `pip install acropolis[otel]`. Must degrade to a logged
        warning and an inactive (but harmless) TracingManager — never crash startup, never
        break request handling.

        Postgres cutover (enterprise #7): see the DSN note on the test above — same reasoning,
        this subprocess also needs a real `pg_dsn` passed in explicitly."""
        result = _run_script(no_otel_venv, f"""
            import asyncio
            import logging
            import httpx
            from archon.settings import Settings
            from argus.app import create_app
            from db.database import Database

            async def main():
                settings = Settings(
                    database_url={pg_dsn!r}, auth_mode="open",
                    health_poll_enabled=False, audit_retention_enabled=False,
                )
                db = Database({pg_dsn!r})
                await db.connect()
                app = create_app(settings, db)
                async with app.router.lifespan_context(app):
                    # enabled reflects the OPERATOR'S request (the env var was true); active
                    # reflects REALITY (the SDK genuinely could not be imported) — these must
                    # be allowed to disagree, and the app must still work regardless.
                    assert app.state.tracing.enabled is True
                    assert app.state.tracing.active is False
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                        resp = await client.post(
                            "/mcp/does-not-exist/mcp",
                            json={{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {{}}}},
                        )
                        # 404 (unknown server) is fine — the point is the process didn't crash
                        # building the request pipeline around a half-initialized tracer.
                        assert resp.status_code == 404, resp.text
                await db.close()
                print("SUBPROCESS_OK")

            asyncio.run(main())
        """, env={"ACROPOLIS_OTEL_ENABLED": "true"})
        assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
        assert "SUBPROCESS_OK" in result.stdout
        # The warning must have actually been logged, not silently swallowed.
        assert "otel" in result.stderr.lower() or "otel" in result.stdout.lower()
