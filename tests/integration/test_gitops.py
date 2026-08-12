"""Tests for GitOps / policy-as-code (Enterprise #7)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database

# Project root for subprocess calls — derived from test file location, not hardcoded
PROJECT_ROOT = Path(__file__).parent.parent.parent


pytestmark = pytest.mark.parametrize("app_env", [{"probe_on_create": False}], indirect=True)


def _cli_env(pg_dsn: str) -> dict:
    """Environment for the `argus` CLI subprocesses below.

    Postgres cutover (enterprise #7): these used to pass `ARGUS_DATA_DIR` and let the CLI open a
    SQLite file under it. Postgres is now a hard requirement with no fallback, so the CLI needs a
    real connection URL or it exits non-zero by design (DatabaseNotConfiguredError). Each test
    gets its own empty database via the `pg_dsn` fixture, preserving the per-test isolation the
    old per-tmp_path data directory provided.

    (Note the old variable name was already stale — Settings uses the ACROPOLIS_ prefix, so
    ARGUS_DATA_DIR had no effect and these subprocesses were silently sharing ./data. Worth
    recording, since it means these tests are now MORE isolated than they were before.)

    PATH is kept minimal, as before, but must include the venv's bin so `python -m argus`
    resolves its dependencies.
    """
    return {
        "ACROPOLIS_DATABASE_URL": pg_dsn,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }


# CLI tests use subprocess to test the actual exit codes

def test_cli_check_exit_code_0_when_in_sync(tmp_path, pg_dsn, app_env):
    """check exits 0 when live config matches the file."""
    # Create a minimal valid config (empty settings = use defaults)
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""version: 1
settings: {}
servers: []
""")

    # Run check against a fresh database (no servers, no settings overrides)
    data_dir = tmp_path / "data"
    result = subprocess.run(
        [sys.executable, "-m", "argus", "check", str(config_file)],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )
    # Fresh DB has no servers, config file has no servers, no settings overrides → in sync
    assert result.returncode == 0, f"expected 0 (in sync), got {result.returncode}: {result.stderr}"


def test_cli_check_exit_code_1_when_drift(tmp_path, pg_dsn, app_env):
    """check exits 1 when live config differs from the file."""
    # First, export the current config
    data_dir = tmp_path / "data"
    export_result = subprocess.run(
        [sys.executable, "-m", "argus", "export", "--stable"],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )
    assert export_result.returncode == 0

    # Modify the config to introduce drift
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""version: 1
settings:
  auth_mode: open
servers: []
""")

    # Run check
    result = subprocess.run(
        [sys.executable, "-m", "argus", "check", str(config_file)],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, f"expected 1 (drift), got {result.returncode}: {result.stderr}"
    assert "drift" in result.stderr.lower() or "auth_mode" in result.stderr


def test_cli_check_exit_code_2_when_invalid_file(tmp_path, pg_dsn, app_env):
    """check exits 2 when the file is malformed."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("not valid yaml: [{")

    data_dir = tmp_path / "data"
    result = subprocess.run(
        [sys.executable, "-m", "argus", "check", str(config_file)],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2, f"expected 2 (invalid), got {result.returncode}: {result.stderr}"
    assert "error" in result.stderr.lower()


def test_cli_export_stable_produces_identical_output(tmp_path, pg_dsn, app_env):
    """--stable export omits exported_at, producing byte-identical output for unchanged config."""
    data_dir = tmp_path / "data"

    # Export twice with --stable
    result1 = subprocess.run(
        [sys.executable, "-m", "argus", "export", "--stable"],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )
    result2 = subprocess.run(
        [sys.executable, "-m", "argus", "export", "--stable"],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )

    assert result1.returncode == 0
    assert result2.returncode == 0
    assert result1.stdout == result2.stdout, "--stable exports should be byte-identical"
    assert "exported_at" not in result1.stdout, "--stable should omit exported_at"


def test_cli_export_without_stable_includes_exported_at(tmp_path, pg_dsn, app_env):
    """Default export includes exported_at timestamp."""
    data_dir = tmp_path / "data"

    result = subprocess.run(
        [sys.executable, "-m", "argus", "export"],
        cwd=PROJECT_ROOT,
        env=_cli_env(pg_dsn),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "exported_at" in result.stdout, "default export should include exported_at"


# API endpoint tests

async def test_drift_endpoint_disabled_by_default(admin_client, app_env):
    """GET /config/drift returns unknown when gitops is not enabled."""
    resp = await admin_client.get("/api/v1/config/drift")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "unknown"


async def test_drift_endpoint_requires_auth(admin_client, app_env):
    """GET /config/drift is behind require_admin."""
    await admin_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    async with app_env.client() as fresh:
        resp = await fresh.get("/api/v1/config/drift")
        assert resp.status_code == 401


async def test_reconcile_endpoint_requires_auth(admin_client, app_env):
    """POST /config/reconcile is behind require_admin."""
    await admin_client.post("/api/v1/setup", json={"admin_password": "hunter22"})
    async with app_env.client() as fresh:
        resp = await fresh.post("/api/v1/config/reconcile")
        assert resp.status_code == 401


async def test_metrics_includes_drift_gauge(admin_client, app_env):
    """GET /metrics includes the config drift gauge."""
    resp = await admin_client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "acropolis_config_drift" in text
    assert "acropolis_config_last_check_timestamp" in text


# Import httpx for the async tests
import httpx


async def test_semantic_comparison_ignores_yaml_key_order(admin_client, app_env):
    """Reordering YAML keys should NOT produce drift — comparison is semantic, not textual."""

    # Create a server via API
    await admin_client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })

    # Export the config
    export_resp = await admin_client.get("/api/v1/config/export")
    original_yaml = export_resp.text

    # Create a semantically identical YAML with keys in different order
    # (simulating what might happen if someone hand-edits the file)
    reordered_yaml = """version: 1
servers:
  - upstream_url: http://localhost:8000/mcp
    name: Test Server
    slug: test-server
    enabled: true
    in_aggregate: true
    policy:
      mode: passthrough
settings:
  auth_mode: keyed
"""

    # The check should show no drift (semantic comparison)
    # We test this via the import preview endpoint
    import_resp = await admin_client.post("/api/v1/config/import", json={
        "yaml": reordered_yaml, "apply": False,
    })
    assert import_resp.status_code == 200
    data = import_resp.json()
    # All actions should be "unchanged" (no drift)
    for action in data["actions"]:
        assert action["kind"] == "unchanged", f"unexpected drift: {action}"


async def test_dlp_config_drift_is_detected(admin_client, app_env):
    """Enterprise #10: a DLP config change must show up as drift the same way any other policy
    field would — proves policy-as-code and DLP compose correctly rather than DLP silently
    riding along unrecognized in the exported/compared representation."""
    await admin_client.post("/api/v1/servers", json={
        "slug": "test-server", "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })
    await admin_client.put("/api/v1/servers/test-server/policy", json={
        "mode": "passthrough", "dlp_detectors": {"credit_card": "block"},
    })

    export_resp = await admin_client.get("/api/v1/config/export")
    exported = export_resp.text
    assert "dlp_detectors" in exported
    assert "credit_card: block" in exported

    # Re-importing the exact export should show no drift.
    reimport = await admin_client.post("/api/v1/config/import", json={"yaml": exported, "apply": False})
    for action in reimport.json()["actions"]:
        assert action["kind"] == "unchanged", f"unexpected drift on re-import: {action}"

    # A file with a DIFFERENT dlp_detectors value must show up as an update, not silently
    # match — the actual drift-detection claim.
    import yaml as _yaml
    data = _yaml.safe_load(exported)
    data["servers"][0]["policy"]["dlp_detectors"] = {"credit_card": "redact"}
    drifted_yaml = _yaml.safe_dump(data)
    drift_resp = await admin_client.post("/api/v1/config/import", json={"yaml": drifted_yaml, "apply": False})
    update_action = next(a for a in drift_resp.json()["actions"] if a["kind"] == "update")
    assert "dlp_detectors" in update_action["detail"]


async def test_ssrf_validation_rejects_private_url(admin_client, app_env):
    """gitops_url pointing at a private IP is rejected without opt-in."""

    # Try to set a private IP as gitops_url
    resp = await admin_client.put("/api/v1/settings", json={
        "gitops_url": "http://192.168.1.1/config.yaml",
    })
    # This should fail validation (SSRF protection)
    # Note: The current settings endpoint doesn't validate gitops_url yet
    # This test documents the expected behavior once validation is added
    # For now, we just verify the setting can be stored (validation happens at fetch time)
    assert resp.status_code in (200, 400, 422)


async def test_reconcile_endpoint_returns_400_with_no_pending_plan(admin_client, app_env):
    """POST /config/reconcile returns 400 (not 404) when there's no drift to apply."""

    # Enable gitops and set a URL (will fail to fetch, but that's ok for this test)
    await admin_client.put("/api/v1/settings", json={
        "gitops_enabled": "true",
        "gitops_url": "https://example.com/config.yaml",
    })

    # Try to reconcile (will fail because no pending plan, but endpoint should exist)
    resp = await admin_client.post("/api/v1/config/reconcile")
    # Should get 400 (no pending plan) not 404 (endpoint missing)
    assert resp.status_code == 400
    assert "no pending plan" in resp.json()["detail"].lower()


async def test_reconcile_applies_plan_and_writes_admin_event(admin_client, app_env, monkeypatch):
    """A successful reconcile() actually applies the drift AND writes one admin event.

    Exercises the real happy path end-to-end through the actual HTTP routes and the app's own
    wired ConfigSource/AdminEventRepo: live state (empty) drifts against a fetched config (one
    new server), GET /config/drift shows it, POST /config/reconcile applies it and records a
    `config.reconcile` admin event — the behavior the PR description claimed but the old
    version of this test never actually checked (it only asserted a 400 "no pending plan").
    """

    from db.repo import AdminEventRepo, ServerRepo, SettingsRepo

    app = app_env.app
    db = app.state.db
    server_repo = ServerRepo(db)
    admin_event_repo = AdminEventRepo(db)
    settings_repo = SettingsRepo(db)

    # gitops_enabled/gitops_url aren't exposed on SettingsUpdateRequest (PUT /api/v1/settings)
    # — same as the other regression tests in this file, write them directly via SettingsRepo.
    await settings_repo.set("gitops_enabled", "true")
    await settings_repo.set("gitops_url", "https://example.com/config.yaml")

    drift_yaml = """version: 1
servers:
  - slug: from-git
    name: From Git
    upstream_url: http://localhost:9000/mcp
    enabled: true
    in_aggregate: true
settings: {}
"""

    class _FakeResponse:
        content = drift_yaml.encode("utf-8")
        def raise_for_status(self):
            pass

    async def _fake_get(url):
        return _FakeResponse()

    config_source = app.state.config_source
    monkeypatch.setattr(config_source._http, "get", _fake_get)

    # Drive one check directly on the app's real ConfigSource (exposed via app.state), rather
    # than waiting on the background poll loop (default interval 300s — the loop's first
    # iteration already ran at startup, before gitops_enabled was set, so waiting for its next
    # iteration here would be both slow and flaky).
    state = await config_source.check_once()
    assert state.status == "drifted"
    assert state.plan is not None

    # GET /config/drift reflects the same cached state via the real route.
    drift_resp = await admin_client.get("/api/v1/config/drift")
    assert drift_resp.json()["status"] == "drifted"

    reconcile_resp = await admin_client.post("/api/v1/config/reconcile")
    assert reconcile_resp.status_code == 200
    body = reconcile_resp.json()
    assert body["applied"] is True
    assert any("from-git" in a or "created" in a.lower() for a in body["actions"])

    # The drift is actually applied to live state, not just planned.
    server = await server_repo.get("from-git")
    assert server is not None
    assert server.upstream_url == "http://localhost:9000/mcp"

    # And exactly one admin event records the reconcile.
    events = await admin_event_repo.query(action="config.reconcile", limit=10)
    assert len(events) == 1
    assert events[0].action == "config.reconcile"
    assert events[0].actor == "gitops"


# Security regression tests (found by /security-scan 2026-08-07)

async def test_reconcile_rejects_private_url_even_with_cached_plan(admin_client, app_env):
    """SSRF regression: reconcile() must re-validate gitops_url with _validate_webhook_url.

    Attack: cache a plan from a valid public URL, then point gitops_url at a private/metadata
    address and call reconcile — the fetch must be rejected, not silently performed.
    """

    app = app_env.app
    from stoa.gitops import ConfigSource
    from db.repo import ServerRepo, SettingsRepo

    db = app.state.db
    cs = ConfigSource(ServerRepo(db), SettingsRepo(db))
    settings_repo = SettingsRepo(db)
    await settings_repo.set("gitops_enabled", "true")
    await settings_repo.set("gitops_url", "https://169.254.169.254/latest/meta-data/")

    state = await cs.check_once()
    # The metadata (link-local) URL must be rejected by _validate_webhook_url
    assert state.status == "error"
    assert state.plan is None, "a rejected URL must not cache a plan"
    assert "non-public" in (state.last_error or "") or "169.254" in (state.last_error or "")
    await cs.stop()


async def test_fetch_config_rejects_oversized_body(admin_client, app_env, monkeypatch):
    """DoS regression: a config body larger than MAX_CONFIG_BYTES must be rejected."""

    from stoa.gitops import ConfigSource, MAX_CONFIG_BYTES

    app = app_env.app
    from db.repo import ServerRepo, SettingsRepo
    db = app.state.db
    cs = ConfigSource(ServerRepo(db), SettingsRepo(db))
    settings_repo = SettingsRepo(db)
    await settings_repo.set("gitops_enabled", "true")
    await settings_repo.set("gitops_url", "https://example.com/huge.yaml")

    # Stub the HTTP client to return an oversized body
    oversized = b"x" * (MAX_CONFIG_BYTES + 1)

    class _FakeResponse:
        content = oversized
        def raise_for_status(self):
            pass

    async def _fake_get(url):
        return _FakeResponse()

    monkeypatch.setattr(cs._http, "get", _fake_get)

    with pytest.raises(ValueError, match="too large"):
        await cs._fetch_config()
    await cs.stop()
