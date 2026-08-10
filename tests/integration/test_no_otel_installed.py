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
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def no_otel_venv(tmp_path_factory):
    """A real venv with acropolis[dev] installed but NOT acropolis[otel] — proving the base
    install (what CI's non-otel job and every real user who never opts in actually gets) is
    genuinely free of the opentelemetry package tree, not just "we didn't add it to
    dependencies and hope nothing transitively pulls it in"."""
    venv_dir = tmp_path_factory.mktemp("no_otel_venv")
    venv.EnvBuilder(with_pip=True, symlinks=True).create(venv_dir)
    python = venv_dir / "bin" / "python"

    result = subprocess.run(
        [str(python), "-m", "pip", "install", "-q", "-e", f"{REPO_ROOT}[dev]"],
        capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, (
        f"failed to build the no-otel venv:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return python


def _run_script(python: Path, script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    import os

    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
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
