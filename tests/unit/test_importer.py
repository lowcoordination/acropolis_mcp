from __future__ import annotations

from pathlib import Path

import pytest

from archon.importer import apply_import, name_to_slug, parse_guard_config
from db.database import Database
from db.repo import ServerRepo

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample-guard-config.yml"


def test_name_to_slug_converts_underscores():
    assert name_to_slug("mn_land") == "mn-land"


def test_name_to_slug_already_valid():
    assert name_to_slug("shell") == "shell"


def test_name_to_slug_empty_raises():
    with pytest.raises(ValueError):
        name_to_slug("___")


def test_parse_real_guard_config_fixture():
    result = parse_guard_config(FIXTURE.read_text())
    slugs = {s.slug for s in result.servers}
    # 10 servers in the real fixture, including the underscore-renamed one.
    assert len(result.servers) == 10
    assert "mn-land" in slugs
    assert any("mn_land" in w for w in result.warnings)


def test_parse_preserves_allowlist_mode_and_param_rules():
    result = parse_guard_config(FIXTURE.read_text())
    shell = next(s for s in result.servers if s.slug == "shell")
    assert shell.policy.mode == "allowlist"
    assert shell.policy.allowed == ["shell_run"]
    assert "shell_run" in shell.policy.param_rules
    command_rule = shell.policy.param_rules["shell_run"]["command"]
    assert command_rule.max_length == 200
    assert r"rm\s+-rf" in command_rule.block_patterns


def test_parse_preserves_passthrough_mode():
    result = parse_guard_config(FIXTURE.read_text())
    search = next(s for s in result.servers if s.slug == "search")
    assert search.policy.mode == "passthrough"


def test_parse_preserves_denylist_mode():
    result = parse_guard_config(FIXTURE.read_text())
    github = next(s for s in result.servers if s.slug == "github")
    assert github.policy.mode == "denylist"
    assert "delete_file" in github.policy.denied


def test_parse_preserves_rate_limit():
    result = parse_guard_config(FIXTURE.read_text())
    shell = next(s for s in result.servers if s.slug == "shell")
    assert shell.rate_limit == "5/minute"


def test_parse_rejects_unknown_param_rule_keys():
    bad_yaml = """
servers:
  test:
    listen_port: 9010
    upstream: http://example.com:8010
    tools:
      mode: allowlist
      allowed: [foo]
      rules:
        foo:
          bar:
            unknown_key: true
"""
    with pytest.raises(ValueError, match="unknown rule keys"):
        parse_guard_config(bad_yaml)


def test_parse_rejects_invalid_upstream_url():
    bad_yaml = """
servers:
  test:
    listen_port: 9010
    upstream: not-a-url
    tools:
      mode: passthrough
"""
    with pytest.raises(ValueError, match="valid http/https URL"):
        parse_guard_config(bad_yaml)


async def test_apply_import_dry_run_writes_nothing(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    repo = ServerRepo(db)
    result = parse_guard_config(FIXTURE.read_text())

    actions = await apply_import(repo, result, dry_run=True)
    assert len(actions) == len(result.servers)
    assert all(a.startswith("would create") for a in actions)
    assert await repo.list() == []
    await db.close()


async def test_apply_import_creates_servers_and_policies(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    repo = ServerRepo(db)
    result = parse_guard_config(FIXTURE.read_text())

    await apply_import(repo, result, dry_run=False)

    servers = await repo.list()
    assert len(servers) == 10

    shell = await repo.get("shell")
    policy = await repo.get_policy(shell.id)
    assert policy.mode == "allowlist"
    assert policy.allowed == ["shell_run"]
    await db.close()


async def test_apply_import_idempotent_on_rerun(tmp_path: Path):
    db = Database(tmp_path)
    await db.connect()
    repo = ServerRepo(db)
    result = parse_guard_config(FIXTURE.read_text())

    await apply_import(repo, result, dry_run=False)
    # Re-running should update policy in place, not raise a conflict.
    actions = await apply_import(repo, result, dry_run=False)
    assert any("already exists" in a for a in actions)
    servers = await repo.list()
    assert len(servers) == 10  # no duplicates
    await db.close()
