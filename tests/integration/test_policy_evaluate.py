"""Integration tests for POST /api/v1/policy/evaluate (#122).

One test per acceptance criterion on the issue, plus the two invariants that are cheap to state
and expensive to discover broken:

- `auth_mode: open` must NOT bypass this endpoint ("no unauthenticated mode, not even behind a
  flag") — TestAuthentication.test_auth_mode_open_does_not_bypass_evaluation.
- no upstream contact, proven with run_fastmcp_server's call_counter, the same proof
  test_dlp_redaction.py's TestBlockNeverReachesUpstream and test_quotas.py use rather than a
  hand-rolled listener.

Fixture choices mirror test_quotas.py: real setup wizard, a REAL minted API key as the Bearer
token, auth_mode='keyed' throughout (this endpoint is keyed to api_key_id, and open mode never
produces one).
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from db.models import ParamRule, ServerPolicy
from db.repo import AuditRepo, ServerRepo

from .fastmcp_fixture import run_fastmcp_server

pytestmark = pytest.mark.parametrize(
    "app_env", [{"auth_mode": "keyed", "probe_on_create": False}], indirect=True
)

EVALUATE = "/api/v1/policy/evaluate"


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def eval_app(app_env, upstream):
    """App in keyed mode with the wizard run, a server registered against the real FastMCP
    fixture, and a `bash` param rule blocking `rm -rf`. Yields
    (db, admin_client, transport, slug, upstream)."""
    server_repo = ServerRepo(app_env.db)
    server = await server_repo.create(slug="e", name="E", upstream_url=f"{upstream.url}/mcp")
    await server_repo.set_policy(server.id, ServerPolicy(
        param_rules={"bash": {"command": ParamRule(block_patterns=["rm -rf"])}},
    ))

    async with app_env.client() as admin_client:
        setup = await admin_client.post(
            "/api/v1/setup", json={"admin_password": "hunter22222", "auth_mode": "keyed"}
        )
        assert setup.status_code == 200
        yield app_env.db, admin_client, app_env.transport, "e", upstream


async def _mint_key(admin_client, name="guard", **fields) -> str:
    resp = await admin_client.post("/api/v1/keys", json={"name": name, **fields})
    assert resp.status_code == 201, resp.text
    return resp.json()["plaintext"]


async def _evaluate(transport, key, slug="e", tool="bash", arguments=None, headers=None):
    body = {"server": slug, "tool_name": tool, "arguments": arguments or {}}
    hdrs = {"Authorization": f"Bearer {key}"} if key else {}
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
        return await c.post(EVALUATE, json=body, headers={**hdrs, **(headers or {})})


async def _audit_rows(db, origin="local-eval"):
    """Reads the evaluation audit rows, after letting AuditLogger's batching loop flush.

    AuditLogger.log enqueues and returns; the insert happens on a background loop every
    FLUSH_INTERVAL_SECONDS (0.1). Same 0.3s settle other integration suites use — see
    test_quotas.py.
    """
    await asyncio.sleep(0.3)
    return await AuditRepo(db).query(origin=origin)


class TestAuthentication:
    """Acceptance: unauthenticated request -> 401."""

    async def test_no_bearer_returns_401(self, eval_app):
        _, _, transport, slug, _ = eval_app
        resp = await _evaluate(transport, key=None)
        assert resp.status_code == 401

    async def test_invalid_key_returns_401(self, eval_app):
        _, _, transport, slug, _ = eval_app
        resp = await _evaluate(transport, key="acropolis_not-a-real-key")
        assert resp.status_code == 401

    async def test_disabled_key_returns_401(self, eval_app):
        _, admin_client, transport, slug, _ = eval_app
        created = await admin_client.post("/api/v1/keys", json={"name": "doomed"})
        key = created.json()["plaintext"]
        assert (await _evaluate(transport, key)).status_code == 200

        disable = await admin_client.patch(
            f"/api/v1/keys/{created.json()['id']}", params={"enabled": False}
        )
        assert disable.status_code == 200, disable.text
        assert (await _evaluate(transport, key)).status_code == 401

    async def test_malformed_authorization_header_returns_401(self, eval_app):
        """Every malformed Authorization shape is rejected, whichever guard catches it.

        Note for future maintainers: the bearer-prefix check in verify_evaluation_key is
        deliberately REDUNDANT with the verify() call after it, and no test can isolate it.
        The handler slices auth_header[7:] unconditionally, and that slice mangles the
        "acropolis_" prefix of any real key (a bare key becomes "is_..."), so verify() rejects
        every input the prefix check would have caught. Mutating the prefix check to `if False`
        leaves the whole suite green — that is defense-in-depth working, not missing coverage.
        Do not "fix" it by removing the prefix check: it produces the accurate 401 detail
        ("missing bearer token" vs "invalid or disabled api key"), which is what an operator
        debugging a client integration actually needs.
        """
        _, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client, name="prefixless")

        # The scheme is REQUIRED: a bare key with no "Bearer " prefix is the realistic client
        # mistake. `key` is a genuinely valid key, so the 401 is about the missing scheme.
        bare = await _evaluate(transport, key=None, headers={"Authorization": key})
        assert bare.status_code == 401, "a key without the Bearer scheme must be rejected"

        # Same key, correct scheme -> 200. Positive control proving the 401 above is the missing
        # scheme and not a bad key.
        assert (await _evaluate(transport, key, arguments={"command": "ls"})).status_code == 200

        for header in ("", "Bearer", f"Basic {key}", "Basic dXNlcjpwYXNz"):
            resp = await _evaluate(transport, key=None, headers={"Authorization": header})
            assert resp.status_code == 401, f"header {header!r} must be rejected"

    async def test_admin_session_is_not_accepted(self, eval_app):
        """The two credential systems stay disjoint: a logged-in admin session is NOT a valid
        credential here. Quota has no identity without an ApiKeyRecord, so a session-authed
        call would be structurally unmeterable."""
        _, admin_client, _, slug, _ = eval_app
        resp = await admin_client.post(
            EVALUATE, json={"server": slug, "tool_name": "bash", "arguments": {}}
        )
        assert resp.status_code == 401

    async def test_auth_mode_open_does_not_bypass_evaluation(self, eval_app):
        """"No unauthenticated mode, not even behind a flag." auth_mode governs the DATA PLANE;
        flipping it to open must leave this endpoint requiring a key. Asserted in one test
        alongside the data plane actually going keyless, so the flag is proven to have taken
        effect rather than merely been written."""
        _, admin_client, transport, slug, _ = eval_app

        switch = await admin_client.put("/api/v1/settings", json={"auth_mode": "open"})
        assert switch.status_code == 200
        assert switch.json()["auth_mode"] == "open"

        # The data plane is now genuinely keyless...
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
            dp = await c.post(
                f"/mcp/{slug}",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "echo", "arguments": {"message": "hi"}}},
                headers={"Content-Type": "application/json", "Accept": "application/json",
                         "Mcp-Method": "tools/call", "Mcp-Name": "echo"},
            )
        assert dp.status_code != 401, "precondition: auth_mode=open must free the data plane"

        # ...but the evaluation endpoint is not.
        assert (await _evaluate(transport, key=None)).status_code == 401


class TestDecision:
    """Acceptance: a blocked command reports blocked+reason; a clean one reports allowed."""

    async def test_blocked_command_returns_decision(self, eval_app):
        _, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        resp = await _evaluate(transport, key, arguments={"command": "rm -rf /"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["blocked"] is True
        assert body["rule"] == "block_pattern"
        assert body["matched"] == "rm -rf"
        assert body["reason"]

    async def test_allowed_command_returns_not_blocked(self, eval_app):
        _, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        resp = await _evaluate(transport, key, arguments={"command": "ls -la"})
        assert resp.status_code == 200
        assert resp.json() == {"blocked": False, "reason": None, "rule": None, "matched": None}

    async def test_key_from_another_project_is_refused(self, eval_app):
        """Project scoping — the endpoint's authorization boundary.

        A key minted in project B must not evaluate against a server in project A, even though
        it is a perfectly valid, enabled key. Found by mutating the scope check to a no-op:
        18/18 passed, because every other test uses a single project and never exercises it.
        """
        db, admin_client, transport, slug, _ = eval_app
        created = await admin_client.post(
            "/api/v1/projects", json={"slug": "other", "name": "Other"}
        )
        assert created.status_code == 201, created.text

        other_key = await _mint_key(admin_client, name="outsider", project_slug="other")
        resp = await _evaluate(transport, other_key, slug=slug, arguments={"command": "ls"})
        assert resp.status_code == 403, resp.text

        # Positive control on the SAME server: an in-project key does get an answer, so the 403
        # above is the project boundary and not some unrelated failure.
        insider = await _mint_key(admin_client, name="insider")
        assert (await _evaluate(transport, insider, slug=slug,
                                arguments={"command": "ls"})).status_code == 200

    async def test_scoped_key_cannot_reach_an_unlisted_server(self, eval_app):
        """The other half of key_scope_violation: server_scopes naming a different slug."""
        db, admin_client, transport, slug, _ = eval_app
        server_repo = ServerRepo(db)
        await server_repo.create(slug="other-srv", name="Other", upstream_url="http://127.0.0.1:1/mcp")

        narrow = await _mint_key(admin_client, name="narrow", server_scopes=["other-srv"])
        resp = await _evaluate(transport, narrow, slug=slug, arguments={"command": "ls"})
        assert resp.status_code == 403, resp.text

    async def test_unknown_server_404s(self, eval_app):
        _, admin_client, transport, _, _ = eval_app
        key = await _mint_key(admin_client)
        resp = await _evaluate(transport, key, slug="nope")
        assert resp.status_code == 404

    async def test_response_never_carries_dlp_redacted_arguments(self, eval_app):
        """docs/dlp.md's audit-safety invariant, extended to this response surface: the body
        has exactly the four contract fields and nothing else."""
        _, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        resp = await _evaluate(transport, key, arguments={"command": "ls"})
        assert set(resp.json()) == {"blocked", "reason", "rule", "matched"}


class TestAuditing:
    """Acceptance: every evaluation appears in the audit log with its decision."""

    async def test_every_evaluation_is_audited(self, eval_app):
        db, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        await _evaluate(transport, key, arguments={"command": "rm -rf /"})
        await _evaluate(transport, key, arguments={"command": "ls -la"})

        rows = await _audit_rows(db)
        assert len(rows) == 2
        decisions = sorted(r["decision"] for r in rows)
        assert decisions == ["ALLOWED", "BLOCKED"]
        for row in rows:
            assert row["endpoint"] == "policy-evaluate"
            assert row["origin"] == "local-eval"
            assert row["tool"] == "bash"
            assert row["api_key_id"] is not None
            assert row["status_code"] == 200

    async def test_failed_auth_is_not_audited(self, eval_app):
        """401s are deliberately not audited — otherwise an unauthenticated caller could flood
        audit_events with no credential at all."""
        db, _, transport, slug, _ = eval_app
        await _evaluate(transport, key=None)
        await _evaluate(transport, key="acropolis_bogus")
        assert await _audit_rows(db) == []

    async def test_evaluations_excluded_from_stats(self, eval_app):
        """A non-NULL origin keeps evaluations out of /stats via count_since's `origin IS NULL`
        filter — an evaluation is not traffic."""
        _, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        before = (await admin_client.get("/api/v1/stats")).json()
        await _evaluate(transport, key, arguments={"command": "rm -rf /"})
        after = (await admin_client.get("/api/v1/stats")).json()
        assert after == before


class TestMetering:
    """Acceptance: rate limit and quota apply."""

    async def test_rate_limit_applies(self, eval_app):
        db, admin_client, transport, slug, _ = eval_app
        server_repo = ServerRepo(db)
        server = await server_repo.get(slug)
        await server_repo.set_policy(server.id, ServerPolicy(
            rate_limit="1/minute",
            param_rules={"bash": {"command": ParamRule(block_patterns=["rm -rf"])}},
        ))
        key = await _mint_key(admin_client)

        assert (await _evaluate(transport, key, arguments={"command": "ls"})).status_code == 200
        second = await _evaluate(transport, key, arguments={"command": "ls"})
        assert second.status_code == 429

        rows = await _audit_rows(db)
        assert any(r["rule"] == "rate_limit" and r["decision"] == "BLOCKED" for r in rows)

    async def test_quota_applies(self, eval_app):
        db, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client, name="tight", quota_calls=1, quota_period="day")

        assert (await _evaluate(transport, key, arguments={"command": "ls"})).status_code == 200
        second = await _evaluate(transport, key, arguments={"command": "ls"})
        assert second.status_code == 429

        rows = await _audit_rows(db)
        assert any(r["rule"] == "quota" and r["decision"] == "BLOCKED" for r in rows)

    async def test_rate_limit_bucket_is_shared_with_data_plane(self, eval_app):
        """The endpoint consumes the SAME srv:{slug} bucket as a real tools/call, so a caller
        cannot double its effective budget by alternating surfaces."""
        db, admin_client, transport, slug, _ = eval_app
        server_repo = ServerRepo(db)
        server = await server_repo.get(slug)
        await server_repo.set_policy(server.id, ServerPolicy(rate_limit="1/minute"))
        key = await _mint_key(admin_client)

        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as c:
            dp = await c.post(
                f"/mcp/{slug}",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "echo", "arguments": {"message": "hi"}}},
                headers={"Content-Type": "application/json", "Accept": "application/json",
                         "Mcp-Method": "tools/call", "Mcp-Name": "echo",
                         "Authorization": f"Bearer {key}"},
            )
        assert dp.status_code == 200, dp.text

        # The one token for this minute is spent — the evaluation must be refused.
        assert (await _evaluate(transport, key, arguments={"command": "ls"})).status_code == 429


class TestNoUpstreamContact:
    """Acceptance: no upstream request is made, asserted with a fixture that would record one."""

    async def test_evaluation_never_contacts_upstream(self, eval_app):
        _, admin_client, transport, slug, upstream = eval_app
        key = await _mint_key(admin_client)
        before = dict(upstream.call_counter)

        blocked = await _evaluate(transport, key, arguments={"command": "rm -rf /"})
        allowed = await _evaluate(transport, key, arguments={"command": "ls -la"})
        assert blocked.status_code == 200 and allowed.status_code == 200
        assert blocked.json()["blocked"] is True and allowed.json()["blocked"] is False

        assert dict(upstream.call_counter) == before, (
            "policy/evaluate must never forward — the upstream call counter moved"
        )


class TestSecretHandling:
    """Acceptance: a secret in the command string must not be written to the audit row.

    Split deliberately. What #122 genuinely delivers is asserted normally; the inline-secret
    gap belongs to #125 and is pinned with a STRICT xfail so it converts into a hard failure the
    moment that issue lands, rather than sitting silent.
    """

    async def test_secret_never_appears_in_response(self, eval_app):
        _, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        resp = await _evaluate(
            transport, key,
            arguments={"command": "kubectl create secret generic x --from-literal=password=hunter2"},
        )
        assert resp.status_code == 200
        assert "hunter2" not in resp.text

    async def test_secret_under_sensitive_key_is_redacted_in_audit(self, eval_app):
        """summarize_args redacts by KEY NAME, which does work when the argument is named
        like a secret."""
        db, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        await _evaluate(transport, key, arguments={"password": "hunter2"})

        rows = await _audit_rows(db)
        assert len(rows) == 1
        assert "hunter2" not in rows[0]["args_summary"]
        assert "[redacted]" in rows[0]["args_summary"]

    @pytest.mark.xfail(
        strict=True,
        reason="#125: summarize_args redacts by key name only, so a secret inline in a command "
               "string still reaches args_summary. When #125 lands this xfail flips to a "
               "failure — convert this into the positive assertion then.",
    )
    async def test_secret_inline_in_command_is_redacted_in_audit(self, eval_app):
        db, admin_client, transport, slug, _ = eval_app
        key = await _mint_key(admin_client)
        await _evaluate(
            transport, key,
            arguments={"command": "kubectl create secret generic x --from-literal=password=hunter2"},
        )

        rows = await _audit_rows(db)
        assert len(rows) == 1
        assert "hunter2" not in rows[0]["args_summary"]
