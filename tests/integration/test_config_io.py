"""Config export/import (new feature #2).

The security-critical assertions here deliberately check the SERIALIZED YAML string rather than
the parsed dict: a secret nested somewhere unexpected would still satisfy a dict-shaped
assertion like `"session_secret" not in data["settings"]`, but cannot hide from a substring
search of the bytes actually leaving the process.
"""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import yaml

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.models import DlpCustomPattern, ParamRule, ServerPolicy
from db.repo import ServerRepo, SettingsRepo


ADMIN_TOKEN = "test-admin-token"


@pytest.fixture
async def client(tmp_path: Path):
    # admin_token, and an Authorization header on the client below, because this fixture seeds a
    # real `admin_password_hash` (one of the secrets the export must never leak). That key is
    # also what require_admin uses to decide first-run setup is complete, so without a genuine
    # credential every request here would 401 — which is itself the correct behavior, and worth
    # exercising: these routes read and write the entire gateway config and must stay gated.
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False, admin_token=ADMIN_TOKEN,
    )
    db = Database(tmp_path)
    await db.connect()

    server_repo = ServerRepo(db)
    settings_repo = SettingsRepo(db)

    server = await server_repo.create(
        slug="shell", name="Shell", upstream_url="http://127.0.0.1:9001/mcp",
        upstream_auth_header="Bearer super-secret-upstream-token",
    )
    await server_repo.set_policy(server.id, ServerPolicy(
        mode="allowlist", rate_limit="5/minute", allowed=["shell_run"],
        param_rules={"shell_run": {"command": ParamRule(max_length=200, block_patterns=["sudo"])}},
    ))
    await server_repo.create(slug="fetch", name="Fetch", upstream_url="http://127.0.0.1:9002/mcp")

    dlp_server = await server_repo.create(
        slug="dlp-server", name="DLP Server", upstream_url="http://127.0.0.1:9003/mcp",
    )
    await server_repo.set_policy(dlp_server.id, ServerPolicy(
        mode="passthrough",
        dlp_detectors={"credit_card": "block", "email": "redact"},
        dlp_custom_patterns=[DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="redact")],
    ))

    # The three secrets that must never appear in an export.
    await settings_repo.set_many({
        "auth_mode": "keyed",
        "aggregate_enabled": "true",
        "admin_password_hash": "argon2-hash-of-the-admin-password",
        "session_secret": "deadbeefsessionsecret",
    })

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=transport, base_url="http://argus.test",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        ) as c:
            yield c
    await db.close()


# --------------------------------------------------------------------------- export

async def test_export_excludes_every_secret(client):
    resp = await client.get("/api/v1/config/export")
    assert resp.status_code == 200
    body = resp.text

    # Asserting on the raw serialized text, not the parsed structure — see module docstring.
    assert "admin_password_hash" not in body
    assert "argon2-hash-of-the-admin-password" not in body
    assert "session_secret" not in body
    assert "deadbeefsessionsecret" not in body
    assert "super-secret-upstream-token" not in body
    assert "key_hash" not in body


async def test_export_omits_credentials_by_default_but_names_the_servers(client):
    resp = await client.get("/api/v1/config/export")
    body = resp.text
    assert "upstream_auth_header" not in body

    # The operator must be told the file is incomplete, and which servers are affected —
    # otherwise they discover it when a reimported upstream starts 401ing.
    assert "shell" in resp.headers["X-Acropolis-Export-Warnings"]
    assert "were NOT exported" in resp.headers["X-Acropolis-Export-Warnings"]


async def test_export_include_credentials_opt_in_stamps_warning_into_the_file(client):
    resp = await client.get("/api/v1/config/export", params={"include_credentials": True})
    body = resp.text
    assert "super-secret-upstream-token" in body
    # The warning has to live in the FILE, not only the HTTP response — the file is what gets
    # committed to a repo by mistake three weeks later.
    assert "PLAINTEXT" in body
    # Still no admin/session secrets, even on the opt-in path.
    assert "admin_password_hash" not in body
    assert "session_secret" not in body


async def test_export_only_carries_allowlisted_settings(client):
    resp = await client.get("/api/v1/config/export")
    data = yaml.safe_load(resp.text)
    assert set(data["settings"]) <= {"auth_mode", "aggregate_enabled", "default_ttl_ms", "audit_retention_days"}
    assert data["settings"]["auth_mode"] == "keyed"


async def test_export_round_trips_policy_faithfully(client):
    resp = await client.get("/api/v1/config/export")
    data = yaml.safe_load(resp.text)
    shell = next(s for s in data["servers"] if s["slug"] == "shell")
    assert shell["policy"]["mode"] == "allowlist"
    assert shell["policy"]["rate_limit"] == "5/minute"
    assert shell["policy"]["allowed"] == ["shell_run"]
    assert shell["policy"]["param_rules"]["shell_run"]["command"]["max_length"] == 200
    assert shell["policy"]["param_rules"]["shell_run"]["command"]["block_patterns"] == ["sudo"]


async def test_export_round_trips_dlp_config_faithfully(client):
    """Enterprise #10: verifies the plan's claim that dlp_detectors/dlp_custom_patterns ride
    the existing policy serialization with no special-casing needed — export, don't assume."""
    resp = await client.get("/api/v1/config/export")
    data = yaml.safe_load(resp.text)
    dlp = next(s for s in data["servers"] if s["slug"] == "dlp-server")
    assert dlp["policy"]["dlp_detectors"] == {"credit_card": "block", "email": "redact"}
    assert dlp["policy"]["dlp_custom_patterns"] == [
        {"name": "employee_id", "pattern": r"EMP-\d{6}", "action": "redact"}
    ]


async def test_import_of_exported_dlp_config_reports_unchanged(client):
    """The full round-trip claim: export -> reimport must show the DLP-bearing server as
    unchanged, not as a spurious update — proves the on-disk (export_config/_parse) and
    in-DB (ServerRepo.get_policy/set_policy) representations of dlp_detectors/
    dlp_custom_patterns agree exactly."""
    exported = (await client.get("/api/v1/config/export")).text
    resp = await client.post("/api/v1/config/import", json={"yaml": exported})
    dlp_action = next(a for a in resp.json()["actions"] if a["target"] == "server 'dlp-server'")
    assert dlp_action["kind"] == "unchanged", dlp_action


# --------------------------------------------------------------------------- import

async def test_import_dry_run_writes_nothing(client):
    doc = yaml.safe_dump({
        "version": 1,
        "servers": [{"slug": "brand-new", "name": "New", "upstream_url": "http://127.0.0.1:9003/mcp",
                     "policy": {"mode": "passthrough"}}],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc})
    assert resp.status_code == 200
    body = resp.json()
    assert body["applied"] is False
    assert any("would create" in a["description"] for a in body["actions"])

    # The whole point of a dry run.
    assert (await client.get("/api/v1/servers/brand-new")).status_code == 404


async def test_import_apply_creates_the_server(client):
    doc = yaml.safe_dump({
        "version": 1,
        "servers": [{"slug": "brand-new", "name": "New", "upstream_url": "http://127.0.0.1:9003/mcp",
                     "policy": {"mode": "allowlist", "allowed": ["ping"]}}],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
    assert resp.json()["applied"] is True

    created = await client.get("/api/v1/servers/brand-new")
    assert created.status_code == 200
    policy = (await client.get("/api/v1/servers/brand-new/policy")).json()
    assert policy["mode"] == "allowlist"
    assert policy["allowed"] == ["ping"]


async def test_import_rejects_link_local_upstream(client):
    """F17's SSRF guard must apply to imported files too — the review specifically flagged that
    the API validated upstream URLs while the importer did not."""
    doc = yaml.safe_dump({
        "version": 1,
        "servers": [{"slug": "evil", "upstream_url": "http://169.254.169.254/mcp",
                     "policy": {"mode": "passthrough"}}],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
    body = resp.json()
    assert body["ok"] is False
    assert body["applied"] is False
    assert any("evil" in e for e in body["errors"])
    assert (await client.get("/api/v1/servers/evil")).status_code == 404


async def test_import_rejects_whole_file_when_any_entry_is_invalid(client):
    """No half-applied imports: one bad entry must not leave the operator with a partially
    migrated config and no clear way back."""
    doc = yaml.safe_dump({
        "version": 1,
        "servers": [
            {"slug": "good-one", "upstream_url": "http://127.0.0.1:9004/mcp", "policy": {"mode": "passthrough"}},
            {"slug": "bad-one", "upstream_url": "http://169.254.169.254/mcp", "policy": {"mode": "passthrough"}},
        ],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
    assert resp.json()["ok"] is False
    assert (await client.get("/api/v1/servers/good-one")).status_code == 404


async def test_import_refuses_to_write_non_allowlisted_settings(client):
    """An edited file must not be able to set admin_password_hash or session_secret."""
    doc = yaml.safe_dump({
        "version": 1,
        "settings": {"admin_password_hash": "attacker-controlled-hash"},
        "servers": [],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
    body = resp.json()
    assert body["ok"] is False
    assert any("admin_password_hash" in e for e in body["errors"])


async def test_import_rejects_unsupported_version(client):
    doc = yaml.safe_dump({"version": 99, "servers": []})
    resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
    body = resp.json()
    assert body["ok"] is False
    assert any("version" in e for e in body["errors"])


async def test_import_diff_shows_policy_field_deltas(client):
    """The plan asks for a real diff, not just 'would update X' — the operator should see what
    actually changes before applying."""
    doc = yaml.safe_dump({
        "version": 1,
        "servers": [{"slug": "shell", "name": "Shell", "upstream_url": "http://127.0.0.1:9001/mcp",
                     "policy": {"mode": "denylist", "denied": ["shell_run"]}}],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc})
    update = next(a for a in resp.json()["actions"] if a["kind"] == "update")
    assert "allowlist -> denylist" in update["detail"]


async def test_import_reports_unchanged_servers_as_unchanged(client):
    """Re-importing an untouched export should be a no-op, which is what makes the file safe to
    replay."""
    exported = (await client.get("/api/v1/config/export")).text
    resp = await client.post("/api/v1/config/import", json={"yaml": exported})
    kinds = {a["kind"] for a in resp.json()["actions"] if a["target"].startswith("server")}
    assert kinds == {"unchanged"}


async def test_import_never_deletes_servers_absent_from_the_file(client):
    doc = yaml.safe_dump({
        "version": 1,
        "servers": [{"slug": "shell", "name": "Shell", "upstream_url": "http://127.0.0.1:9001/mcp",
                     "policy": {"mode": "allowlist", "rate_limit": "5/minute", "allowed": ["shell_run"],
                                "param_rules": {"shell_run": {"command": {"max_length": 200,
                                                                          "block_patterns": ["sudo"]}}}}}],
    })
    resp = await client.post("/api/v1/config/import", json={"yaml": doc, "apply": True})
    assert resp.json()["ok"] is True
    # 'fetch' was not in the file and must survive untouched.
    assert (await client.get("/api/v1/servers/fetch")).status_code == 200
    assert any("fetch" in w for w in resp.json()["warnings"])


async def test_export_import_export_is_stable_modulo_timestamp(client):
    """Round-trip fidelity: exporting, importing, and re-exporting should produce the same
    document apart from the timestamp."""
    first = yaml.safe_load((await client.get("/api/v1/config/export")).text)
    await client.post("/api/v1/config/import",
                      json={"yaml": yaml.safe_dump(first), "apply": True})
    second = yaml.safe_load((await client.get("/api/v1/config/export")).text)

    first.pop("exported_at")
    second.pop("exported_at")
    assert first == second
