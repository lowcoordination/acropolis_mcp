"""Approval-workflow tests (enterprise #9, issue #10) — the plan's verification section.

Covers, in order: the disabled-by-default regression guard (byte-identical to pre-feature),
the 202-queues-instead-of-applies shape, the admin-only /proposals gate, four-eyes (self-
approval 403 with a distinct message, different-admin approval applies with BOTH identities
in the audit trail), the staleness/TOCTOU guard (the most important test in the file — approve
after an out-of-band change is refused and nothing applies), reject + expiry paths, config
import under approvals, and the approval_pending webhook's payload secrecy.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.models import ServerPolicy
from db.repo import ProjectMemberRepo, ProjectRepo, SettingsRepo
from tests.integration.test_webhooks import _WebhookReceiver


@pytest.fixture
async def app_client(tmp_path: Path):
    """App with a running lifespan + a setup-complete admin session, plus helper accessors."""
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open",
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as admin:
            resp = await admin.post(
                "/api/v1/setup", json={"admin_password": "hunter22", "auth_mode": "open"}
            )
            assert resp.status_code == 200
            yield app, transport, admin
    await db.close()


async def _login(transport: httpx.ASGITransport, username: str, password: str) -> httpx.AsyncClient:
    client = httpx.AsyncClient(transport=transport, base_url="http://argus.test")
    resp = await client.post(
        "/api/v1/login", json={"username": username, "admin_password": password}
    )
    if resp.status_code != 200:
        raise AssertionError(f"login failed for {username}: {resp.status_code} {resp.text}")
    return client


async def _create_user(
    app, admin: httpx.AsyncClient, username: str, role: str, password: str = "password-12345",
) -> None:
    resp = await admin.post(
        "/api/v1/users", json={"username": username, "password": password, "role": role}
    )
    assert resp.status_code == 201, resp.text
    # Grant the project role matching the user's global role in the 'default' project, so a
    # project poweruser can actually reach the policy route (same fixture logic as test_rbac).
    if role != "admin":
        project_repo = ProjectRepo(app.state.db)
        member_repo = ProjectMemberRepo(app.state.db)
        default_project = await project_repo.get("default")
        user_id = resp.json()["id"]
        await member_repo.upsert(
            user_id=user_id, project_id=default_project.id,
            role={"viewer": "viewer", "operator": "poweruser"}[role],
        )


async def _enable_approvals(admin: httpx.AsyncClient) -> None:
    resp = await admin.put("/api/v1/settings", json={"approvals_enabled": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["approvals_enabled"] is True


async def _create_server(admin: httpx.AsyncClient, slug: str = "test-server") -> None:
    resp = await admin.post("/api/v1/servers", json={
        "slug": slug, "name": "Test Server", "upstream_url": "http://localhost:8000/mcp",
    })
    assert resp.status_code == 201, resp.text


def _policy_body(mode: str = "allowlist") -> dict:
    return {"mode": mode, "rate_limit": None, "allowed": ["tools/list"], "denied": [],
            "param_rules": {}, "dlp_detectors": {}, "dlp_custom_patterns": []}


async def _admin_events(client: httpx.AsyncClient, action: str | None = None) -> list[dict]:
    params = {"action": action} if action else {}
    resp = await client.get("/api/v1/admin-events", params=params)
    assert resp.status_code == 200
    return resp.json()


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 1. Disabled by default = byte-identical to pre-feature behaviour (the regression guard)
# ─────────────────────────────────────────────────────────────────────────────────────────────


async def test_disabled_by_default_policy_write_applies_directly(app_client):
    _, _, admin = app_client
    await _create_server(admin)

    resp = await admin.put("/api/v1/servers/test-server/policy", json=_policy_body())
    assert resp.status_code == 200  # NOT 202 — approvals are off
    assert resp.json()["mode"] == "allowlist"

    # No proposals exist and no proposal-shaped events were written.
    resp = await admin.get("/api/v1/proposals")
    assert resp.status_code == 200
    assert resp.json() == []
    events = await _admin_events(admin, action="proposal.create")
    assert events == []


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 2. Enabled: policy PUT returns 202 + proposal; NOTHING is applied
# ─────────────────────────────────────────────────────────────────────────────────────────────


async def test_enabled_policy_put_queues_and_applies_nothing(app_client):
    _, _, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)

    resp = await admin.put("/api/v1/servers/test-server/policy", json=_policy_body())
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["proposal_id"] > 0
    assert body["state"] == "pending"

    # Policy unchanged on re-read; no policy.update event was written.
    policy = await admin.get("/api/v1/servers/test-server/policy")
    assert policy.status_code == 200
    assert policy.json()["mode"] == "passthrough"
    assert await _admin_events(admin, action="policy.update") == []

    # The proposal itself is visible with its create event.
    proposals = await admin.get("/api/v1/proposals")
    assert proposals.status_code == 200
    data = proposals.json()
    assert len(data) == 1
    assert data[0]["target_type"] == "server_policy"
    assert data[0]["target_id"] == "test-server"
    assert data[0]["state"] == "pending"
    assert data[0]["proposer"] == "admin"

    events = await _admin_events(admin, action="proposal.create")
    assert len(events) == 1
    assert events[0]["target_type"] == "proposal"
    assert events[0]["target_id"] == str(body["proposal_id"])


async def test_proposal_approve_reject_require_project_admin(app_client):
    """Remediation (review 2026-08-10): approve/reject require PROJECT admin, not global
    admin — a global-viewer/operator who IS project-poweruser (the default membership
    _create_user grants — see its own comment) can still see the proposal (list + detail,
    viewer-level), but cannot approve or reject it (needs project-admin). Superseded
    test_proposals_routes_are_admin_only's "everything 403s for a non-admin" claim, which
    predates project-scoped proposals (0012_proposals_project_scope.sql)."""
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body()
    )).json()["proposal_id"]

    await _create_user(app, admin, "op-user", "operator")
    operator = await _login(transport, "op-user", "password-12345")

    # List and detail are viewer-level — op-user is project-poweruser in 'default' (where
    # test-server lives, via _create_user's own default-project grant), which qualifies.
    list_resp = await operator.get("/api/v1/proposals")
    assert list_resp.status_code == 200
    assert any(p["id"] == proposal_id for p in list_resp.json())

    detail_resp = await operator.get(f"/api/v1/proposals/{proposal_id}")
    assert detail_resp.status_code == 200

    # Approve/reject need project-ADMIN — poweruser is insufficient.
    for method, path in [
        ("POST", f"/api/v1/proposals/{proposal_id}/approve"),
        ("POST", f"/api/v1/proposals/{proposal_id}/reject"),
    ]:
        resp = await operator.request(method, path, json={})
        assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}"
    await operator.aclose()


async def test_proposal_project_isolation(app_client):
    """A project-A admin cannot see or act on a project-B proposal, even though they're a real
    admin — just not in project B. Proves the disclosure half of the finding is fixed (list
    filters by membership, detail/approve/reject 403 for a non-member) without relying on the
    global-admin superset masking the gap, the way single-project fixtures did before."""
    app, transport, admin = app_client
    project_repo = ProjectRepo(app.state.db)
    member_repo = ProjectMemberRepo(app.state.db)
    await project_repo.create(slug="project-b", name="Project B")

    await _create_server(admin, slug="server-a")  # lands in 'default'
    await admin.post("/api/v1/servers", json={
        "slug": "server-b", "name": "Server B", "upstream_url": "http://localhost:8000/mcp",
        "project_slug": "project-b",
    })
    await _enable_approvals(admin)

    proposal_a = (await admin.put(
        "/api/v1/servers/server-a/policy", json=_policy_body()
    )).json()["proposal_id"]
    proposal_b = (await admin.put(
        "/api/v1/servers/server-b/policy", json=_policy_body()
    )).json()["proposal_id"]

    # user-a: project-admin in 'default' only, no membership in project-b.
    create_resp = await admin.post(
        "/api/v1/users", json={"username": "user-a", "password": "password-12345", "role": "viewer"}
    )
    default_project = await project_repo.get("default")
    await member_repo.upsert(
        user_id=create_resp.json()["id"], project_id=default_project.id, role="admin",
    )
    user_a = await _login(transport, "user-a", "password-12345")

    # Sees project-a's proposal in the list, not project-b's.
    list_resp = await user_a.get("/api/v1/proposals")
    assert list_resp.status_code == 200
    seen_ids = {p["id"] for p in list_resp.json()}
    assert proposal_a in seen_ids
    assert proposal_b not in seen_ids

    # Can approve project-a's own proposal — the deadlock fix: project-admin, global-viewer,
    # no global role bump needed.
    approve_a = await user_a.post(f"/api/v1/proposals/{proposal_a}/approve", json={})
    assert approve_a.status_code == 200, approve_a.text

    # Cannot see or act on project-b's proposal.
    detail_b = await user_a.get(f"/api/v1/proposals/{proposal_b}")
    assert detail_b.status_code == 403
    approve_b = await user_a.post(f"/api/v1/proposals/{proposal_b}/approve", json={})
    assert approve_b.status_code == 403
    reject_b = await user_a.post(f"/api/v1/proposals/{proposal_b}/reject", json={})
    assert reject_b.status_code == 403
    await user_a.aclose()


async def test_config_import_proposal_requires_global_admin_even_for_project_admin_everywhere(app_client):
    """A config_import proposal's project_id is NULL by design (it can touch servers across
    every project in one file) — proves the None-branch in require_proposal_project_role
    requires GLOBAL admin explicitly, not a silent permissive fallthrough for a user who
    happens to be project-admin in every project they're a member of."""
    app, transport, admin = app_client
    await _enable_approvals(admin)

    yaml_text = (
        "version: 1\nservers:\n  - slug: from-import\n    name: From Import\n"
        "    upstream_url: http://localhost:9000/mcp\n"
    )
    import_resp = await admin.post(
        "/api/v1/config/import", json={"yaml": yaml_text, "apply": True}
    )
    assert import_resp.status_code == 202, import_resp.text
    proposal_id = import_resp.json()["proposal_id"]

    project_repo = ProjectRepo(app.state.db)
    member_repo = ProjectMemberRepo(app.state.db)
    create_resp = await admin.post(
        "/api/v1/users", json={"username": "user-a", "password": "password-12345", "role": "viewer"}
    )
    default_project = await project_repo.get("default")
    await member_repo.upsert(
        user_id=create_resp.json()["id"], project_id=default_project.id, role="admin",
    )
    user_a = await _login(transport, "user-a", "password-12345")

    # Project-admin in the only project they're a member of — still not global admin, so the
    # config_import proposal (project_id IS NULL) must stay out of reach.
    detail = await user_a.get(f"/api/v1/proposals/{proposal_id}")
    assert detail.status_code == 403
    approve = await user_a.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert approve.status_code == 403
    await user_a.aclose()


async def test_proposals_state_filter_validates(app_client):
    _, _, admin = app_client
    resp = await admin.get("/api/v1/proposals", params={"state": "bogus"})
    assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 3. Four-eyes: self-approval 403 (distinct message); different admin approves and applies
# ─────────────────────────────────────────────────────────────────────────────────────────────


async def test_self_approval_rejected_with_distinct_message(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body()
    )).json()["proposal_id"]

    resp = await admin.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert resp.status_code == 403
    assert "four-eyes" in resp.json()["detail"].lower()
    assert "proposer" in resp.json()["detail"].lower()

    # Nothing applied, still pending.
    policy = await admin.get("/api/v1/servers/test-server/policy")
    assert policy.json()["mode"] == "passthrough"
    assert (await admin.get("/api/v1/proposals")).json()[0]["state"] == "pending"


async def test_different_admin_approval_applies_and_records_both_identities(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    await _create_user(app, admin, "admin-two", "admin")
    approver = await _login(transport, "admin-two", "password-12345")

    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body()
    )).json()["proposal_id"]

    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/approve", json={"reason": "looks good"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "approved"
    assert resp.json()["resolver"] == "admin-two"

    # The policy IS applied now.
    policy = await admin.get("/api/v1/servers/test-server/policy")
    assert policy.json()["mode"] == "allowlist"

    # Both identities land in the audit trail: proposal.approve carries the proposer in
    # `after` and the approver as the event's actor; policy.update carries the approver.
    approve_events = await _admin_events(admin, action="proposal.approve")
    assert len(approve_events) == 1
    ev = approve_events[0]
    assert ev["actor"] == "admin-two"  # resolver identity
    after = json.loads(ev["after"])
    assert after["proposer"] == "admin"  # proposer identity
    assert after["resolver"] == "admin-two"
    assert after["state"] == "approved"
    assert "looks good" in ev["summary"]

    update_events = await _admin_events(admin, action="policy.update")
    assert len(update_events) == 1
    assert update_events[0]["actor"] == "admin-two"
    await approver.aclose()


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 4. Staleness / TOCTOU — the most important test in the file
# ─────────────────────────────────────────────────────────────────────────────────────────────


async def test_approve_after_out_of_band_change_is_refused_and_applies_nothing(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    await _create_user(app, admin, "admin-two", "admin")
    approver = await _login(transport, "admin-two", "password-12345")

    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body(mode="allowlist")
    )).json()["proposal_id"]

    # Out-of-band change: another path (e.g. GitOps reconcile, which is admin-direct by design)
    # flips the same policy while the proposal sits pending.
    server = await app.state.server_repo.get("test-server")
    await app.state.server_repo.set_policy(server.id, ServerPolicy(**_policy_body(mode="denylist")))

    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert resp.status_code == 409, resp.text
    assert "state changed, re-review" in resp.json()["detail"]

    # The out-of-band value stands; the proposed one was NOT applied; proposal stays pending.
    policy = await admin.get("/api/v1/servers/test-server/policy")
    assert policy.json()["mode"] == "denylist"
    assert (await admin.get("/api/v1/proposals")).json()[0]["state"] == "pending"
    assert await _admin_events(admin, action="policy.update") == []
    await approver.aclose()


async def test_proposal_detail_shows_stale_flag_before_approval(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body()
    )).json()["proposal_id"]

    # Fresh proposal: preview shows the diff, not stale.
    detail = await admin.get(f"/api/v1/proposals/{proposal_id}")
    assert detail.status_code == 200
    assert detail.json()["stale"] is False
    assert any("mode" in d for d in detail.json()["preview"])

    # Drift the policy out-of-band: the detail view now flags stale before anyone clicks.
    server = await app.state.server_repo.get("test-server")
    await app.state.server_repo.set_policy(server.id, ServerPolicy(**_policy_body(mode="denylist")))
    detail = await admin.get(f"/api/v1/proposals/{proposal_id}")
    assert detail.json()["stale"] is True


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 5. Reject + expiry paths write correct events; resolved proposals can't be re-approved
# ─────────────────────────────────────────────────────────────────────────────────────────────


async def test_reject_writes_event_and_cannot_be_approved_later(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    await _create_user(app, admin, "admin-two", "admin")
    approver = await _login(transport, "admin-two", "password-12345")

    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body()
    )).json()["proposal_id"]

    resp = await approver.post(
        f"/api/v1/proposals/{proposal_id}/reject", json={"reason": "not now"}
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "rejected"

    events = await _admin_events(admin, action="proposal.reject")
    assert len(events) == 1
    assert events[0]["actor"] == "admin-two"
    assert "not now" in events[0]["summary"]

    # Rejecting again and approving both fail — the proposal is resolved.
    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/reject", json={})
    assert resp.status_code == 409
    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert resp.status_code == 409

    # Nothing applied.
    policy = await admin.get("/api/v1/servers/test-server/policy")
    assert policy.json()["mode"] == "passthrough"
    await approver.aclose()


async def test_expiry_sweep_expires_stale_proposals_and_blocks_approval(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    await _create_user(app, admin, "admin-two", "admin")
    approver = await _login(transport, "admin-two", "password-12345")

    proposal_id = (await admin.put(
        "/api/v1/servers/test-server/policy", json=_policy_body()
    )).json()["proposal_id"]

    # Backdate the proposal well past the default 7-day TTL (the sweep compares created_at to
    # now - ttl; a fresh proposal is never due).
    async with app.state.db.writer.acquire() as conn:
        await conn.execute(
            "UPDATE proposals SET created_at = $1 WHERE id = $2",
            "2020-01-01T00:00:00+00:00", proposal_id,
        )
    expired = await app.state.proposal_expiry_job.run_once()
    assert expired == 1

    proposals = (await admin.get("/api/v1/proposals")).json()
    assert proposals[0]["state"] == "expired"
    assert proposals[0]["resolver"] == "expiry-sweep"

    # Expired proposals can't be approved.
    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert resp.status_code == 409

    # The sweep wrote one attributable admin event (not one per proposal).
    events = await _admin_events(admin, action="proposal.expire")
    assert len(events) == 1
    assert "expired 1 stale proposal" in events[0]["summary"]
    await approver.aclose()


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 6. Config import under approvals
# ─────────────────────────────────────────────────────────────────────────────────────────────


def _import_yaml(slug: str = "imported-server") -> str:
    return (
        f"version: 1\nsettings: {{}}\nservers:\n"
        f"  - slug: {slug}\n    name: Imported\n    upstream_url: http://localhost:9000/mcp\n"
    )


async def test_config_import_apply_is_queued_not_applied(app_client):
    _, _, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)

    # Dry-run (apply=false) still previews — a preview changes nothing.
    resp = await admin.post("/api/v1/config/import", json={"yaml": _import_yaml(), "apply": False})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["applied"] is False

    # apply=true queues a proposal instead of applying.
    resp = await admin.post("/api/v1/config/import", json={"yaml": _import_yaml(), "apply": True})
    assert resp.status_code == 202, resp.text
    proposal_id = resp.json()["proposal_id"]

    # Nothing was created.
    servers = (await admin.get("/api/v1/servers")).json()
    assert [s["slug"] for s in servers] == ["test-server"]

    proposals = (await admin.get("/api/v1/proposals")).json()
    assert proposals[0]["target_type"] == "config_import"
    assert proposals[0]["target_id"] == "config"

    # The detail view shows the recomputed plan (the create action) and is not stale.
    detail = await admin.get(f"/api/v1/proposals/{proposal_id}")
    assert detail.json()["stale"] is False
    assert any("would create" in d or "create" in d.lower() for d in detail.json()["preview"])


async def test_config_import_approval_applies_recomputed_plan_with_single_event(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    await _create_user(app, admin, "admin-two", "admin")
    approver = await _login(transport, "admin-two", "password-12345")

    proposal_id = (await admin.post(
        "/api/v1/config/import", json={"yaml": _import_yaml(), "apply": True}
    )).json()["proposal_id"]

    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert resp.status_code == 200, resp.text

    # The import applied.
    servers = (await admin.get("/api/v1/servers")).json()
    assert [s["slug"] for s in servers] == ["imported-server", "test-server"]

    # One config.import event (the single-event shape, not one per touched server).
    events = await _admin_events(admin, action="config.import")
    assert len(events) == 1
    assert events[0]["actor"] == "admin-two"
    await approver.aclose()


async def test_config_import_approval_refused_when_config_drifted(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)
    await _create_user(app, admin, "admin-two", "admin")
    approver = await _login(transport, "admin-two", "password-12345")

    proposal_id = (await admin.post(
        "/api/v1/config/import", json={"yaml": _import_yaml(), "apply": True}
    )).json()["proposal_id"]

    # Any intervening config change (another server created directly) makes the import stale.
    await admin.post("/api/v1/servers", json={
        "slug": "drift-server", "name": "Drift", "upstream_url": "http://localhost:9001/mcp",
    })

    resp = await approver.post(f"/api/v1/proposals/{proposal_id}/approve", json={})
    assert resp.status_code == 409
    assert "state changed, re-review" in resp.json()["detail"]

    # Nothing from the proposal was imported.
    servers = (await admin.get("/api/v1/servers")).json()
    assert "imported-server" not in [s["slug"] for s in servers]
    await approver.aclose()


# ─────────────────────────────────────────────────────────────────────────────────────────────
# 7. approval_pending webhook fires with no diff contents (payload secrecy)
# ─────────────────────────────────────────────────────────────────────────────────────────────


async def test_approval_pending_webhook_fires_without_diff_contents(app_client):
    app, transport, admin = app_client
    await _create_server(admin)
    await _enable_approvals(admin)

    receiver = _WebhookReceiver()
    await receiver.start()
    try:
        await SettingsRepo(app.state.db).set_many({
            "webhook_url": receiver.url,
            "webhook_enabled": "true",
            "webhook_events": "approval_pending",
        })

        resp = await admin.put("/api/v1/servers/test-server/policy", json=_policy_body())
        assert resp.status_code == 202
        proposal_id = resp.json()["proposal_id"]

        # Delivery is awaited inside the PUT (no debounce for edge events), but poll anyway.
        async def _wait() -> list:
            for _ in range(50):
                if receiver.requests:
                    return receiver.requests
                await asyncio.sleep(0.05)
            return []

        requests = await _wait()
        assert len(requests) == 1
        payload = json.loads(requests[0]["body"])
        assert payload["event"] == "approval_pending"
        assert payload["proposal_id"] == proposal_id
        assert payload["target_type"] == "server_policy"
        assert payload["target_id"] == "test-server"
        assert payload["proposer"] == "admin"

        # SECRECY: no diff contents, no policy payload, no YAML — only the handles.
        raw = requests[0]["body"].decode()
        assert "allowlist" not in raw
        assert "param_rules" not in raw
        assert "proposal_id" in raw
    finally:
        await receiver.stop()
