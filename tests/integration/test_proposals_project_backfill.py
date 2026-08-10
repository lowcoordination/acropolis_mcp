"""Tests for db/migrations/0012_proposals_project_scope.sql (remediation, review 2026-08-10 —
see that migration's header for the finding it fixes: /proposals* was gated on GLOBAL admin
while the underlying policy change is project-owned).

Two scenarios, against the REAL migration runner (db.database._apply_migrations), same
discipline as test_users_migration.py:

1. A pre-existing 'server_policy' proposal is backfilled to its target server's CURRENT
   project_id.
2. A pre-existing 'config_import' proposal is left with project_id NULL — it's instance-wide
   by design, not an oversight to fix.
3. A 'server_policy' proposal whose target server has since been deleted backfills to NULL
   (falls back to global-admin-only, rather than erroring the migration).
"""
from __future__ import annotations

import json

import asyncpg
import pytest

from db.database import Database, _apply_migrations, _init_connection

# The exact migration list before this remediation's migration landed — simulates an existing
# instance upgrading from the full Epic 2 schema (through 0011) to this fix.
_PRE_SCOPE_MIGRATIONS = [
    "0001_init.sql", "0002_upstream_credential.sql", "0003_audit_api_key_index.sql",
    "0004_audit_origin.sql", "0005_admin_events.sql", "0006_users.sql", "0007_dlp.sql",
    "0008_server_health_reason.sql", "0009_usage_rollups.sql", "0010_projects.sql",
    "0011_proposals.sql",
]
_THROUGH_SCOPE_MIGRATIONS = _PRE_SCOPE_MIGRATIONS + ["0012_proposals_project_scope.sql"]


async def _raw_conn(dsn: str) -> asyncpg.Connection:
    conn = await asyncpg.connect(dsn)
    await _init_connection(conn)
    return conn


async def test_server_policy_proposal_backfills_to_target_servers_project(pg_dsn):
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_SCOPE_MIGRATIONS)

    project_id = await conn.fetchval(
        "INSERT INTO projects (slug, name, created_at) VALUES ('acme', 'Acme', $1) RETURNING id",
        "2026-01-01T00:00:00+00:00",
    )
    await conn.execute(
        """INSERT INTO servers (slug, name, upstream_url, enabled, in_aggregate, created_at,
               updated_at, project_id)
           VALUES ('acme-server', 'Acme Server', 'http://localhost:9000/mcp', true, true,
               $1, $1, $2)""",
        "2026-01-01T00:00:00+00:00", project_id,
    )
    payload = json.dumps({"request": {}, "baseline": {}})
    proposal_id = await conn.fetchval(
        """INSERT INTO proposals (target_type, target_id, payload, proposer, created_at)
           VALUES ('server_policy', 'acme-server', $1, 'admin', $2) RETURNING id""",
        payload, "2026-01-01T00:00:00+00:00",
    )

    # The actual upgrade: apply the remediation migration on top of an already-populated DB.
    await _apply_migrations(conn, _THROUGH_SCOPE_MIGRATIONS)

    backfilled = await conn.fetchval(
        "SELECT project_id FROM proposals WHERE id = $1", proposal_id
    )
    assert backfilled == project_id

    await conn.close()


async def test_config_import_proposal_stays_null_after_backfill(pg_dsn):
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_SCOPE_MIGRATIONS)

    payload = json.dumps({"request": {"yaml": "version: 1\nservers: []\n"}, "baseline": ""})
    proposal_id = await conn.fetchval(
        """INSERT INTO proposals (target_type, target_id, payload, proposer, created_at)
           VALUES ('config_import', 'config', $1, 'admin', $2) RETURNING id""",
        payload, "2026-01-01T00:00:00+00:00",
    )

    await _apply_migrations(conn, _THROUGH_SCOPE_MIGRATIONS)

    backfilled = await conn.fetchval(
        "SELECT project_id FROM proposals WHERE id = $1", proposal_id
    )
    assert backfilled is None, "config_import proposals must stay instance-wide (project_id NULL)"

    await conn.close()


async def test_orphaned_server_policy_proposal_backfills_to_null_not_error(pg_dsn):
    """A 'server_policy' proposal whose target_id no longer matches any server (the server was
    deleted between proposing and this migration running) must not fail the migration — it
    falls back to NULL, which the route layer then treats as global-admin-only, the safe
    default for a target that no longer resolves to anything."""
    conn = await _raw_conn(pg_dsn)
    await _apply_migrations(conn, _PRE_SCOPE_MIGRATIONS)

    payload = json.dumps({"request": {}, "baseline": {}})
    proposal_id = await conn.fetchval(
        """INSERT INTO proposals (target_type, target_id, payload, proposer, created_at)
           VALUES ('server_policy', 'long-deleted-server', $1, 'admin', $2) RETURNING id""",
        payload, "2026-01-01T00:00:00+00:00",
    )

    # Must not raise.
    await _apply_migrations(conn, _THROUGH_SCOPE_MIGRATIONS)

    backfilled = await conn.fetchval(
        "SELECT project_id FROM proposals WHERE id = $1", proposal_id
    )
    assert backfilled is None

    await conn.close()
