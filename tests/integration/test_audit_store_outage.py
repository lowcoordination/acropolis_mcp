"""
Issue #109: isolate audit reads in /metrics and /stats so an audit-store outage degrades the
audit-derived numbers only, and everything config-sourced still renders.

Before this fix, both endpoints called AuditRepo inside the same handler as the config-store
reads with no error isolation. That was harmless while there was exactly one database (an audit
read failing meant a config read was about to fail too), but once #108 allows the audit log to
live on a separate database, the two stores can fail independently — and an audit outage would
500 the whole /metrics scrape ("is the gateway up?") and the whole /stats dashboard payload
("how many servers are healthy?"), even though everything config-sourced was perfectly readable.

These tests simulate the outage the same way a real one would surface in the handler: by making
AuditRepo's read methods raise. The app itself stays on a real Postgres; the failure is injected
at the repo boundary, which is exactly where a separate/down audit database would fail.

The request path (Pipeline) is deliberately out of scope: it was already isolated from audit
failures before #109 (rollup errors swallowed, quota fail-open, AuditLogger non-blocking), so
proxied traffic keeps flowing during an audit outage regardless of this change.
"""
from __future__ import annotations

import pytest

from db.repo import AuditRepo, ServerRepo


pytestmark = pytest.mark.parametrize("app_env", [{"probe_on_create": False}], indirect=True)


@pytest.fixture
async def app_client(app_env):
    async with app_env.client() as client:
        yield client, app_env.db


class _AuditStoreDown:
    """Stand-in for an unreachable audit database — every read method raises, exactly as a
    connection failure to a separate audit Postgres would. The real outage would fail at the
    asyncpg call inside the repo; this fails one layer up, at the repo's public boundary,
    which is all the handlers can see."""

    @staticmethod
    async def _raise(*args, **kwargs):
        raise RuntimeError("simulated audit store outage (issue #109)")


# ---------------------------------------------------------------------------
# /metrics — scrape stays 200, audit family omitted, config gauges intact
# ---------------------------------------------------------------------------

class TestMetricsDegradesWhenAuditStoreDown:
    async def test_healthy_path_still_emits_audit_family_and_store_up(self, app_client):
        """Regression guard: the refactor must not change what a healthy store produces —
        the full audit family, acropolis_audit_store_up 1, and the server gauges."""
        client, db = app_client
        server_repo = ServerRepo(db)
        await server_repo.create(slug="metrics-ok", name="OK", upstream_url="http://127.0.0.1:1/mcp")

        resp = await client.get("/metrics")
        assert resp.status_code == 200
        body = resp.text
        assert 'acropolis_audit_events_total{decision="ALLOWED"}' in body
        assert 'acropolis_audit_events_total{decision="BLOCKED"}' in body
        assert "acropolis_audit_store_up 1" in body
        assert 'acropolis_server_health{slug="metrics-ok"}' in body

    async def test_audit_read_failure_omits_family_but_keeps_config_gauges(self, app_client, monkeypatch):
        """The core claim of #109: when the audit store is down, /metrics must still return
        200 with the config-sourced gauges (registered servers, per-server health), must omit
        the audit-events family entirely (a missing series is visibly missing; a 0 would be
        indistinguishable from 'no traffic'), and must expose acropolis_audit_store_up 0 so the
        outage is directly alertable rather than inferred from a gap."""
        client, db = app_client
        server_repo = ServerRepo(db)
        await server_repo.create(slug="metrics-down", name="Down", upstream_url="http://127.0.0.1:1/mcp")

        monkeypatch.setattr(AuditRepo, "count_since", _AuditStoreDown._raise)
        resp = await client.get("/metrics")

        assert resp.status_code == 200
        body = resp.text
        assert "acropolis_audit_events_total" not in body
        assert "acropolis_audit_store_up 0" in body
        # Config-sourced gauges survive the audit outage untouched.
        assert 'acropolis_registered_servers{health_status="unknown"} 1' in body
        assert 'acropolis_server_health{slug="metrics-down"}' in body

    async def test_audit_failure_never_raises_partway_into_family(self, app_client, monkeypatch):
        """A failure on the SECOND count_since call (after the first succeeded) must still
        degrade the whole family, not emit a half-populated counter — the scrape must never see
        a partial acropolis_audit_events_total series that implies the first call's data is
        representative."""
        client, db = app_client
        calls = {"n": 0}

        async def flaky_count_since(self, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RuntimeError("simulated audit store outage (issue #109)")
            return 7

        monkeypatch.setattr(AuditRepo, "count_since", flaky_count_since)
        resp = await client.get("/metrics")

        assert resp.status_code == 200
        assert "acropolis_audit_events_total" not in resp.text
        assert "acropolis_audit_store_up 0" in resp.text
        assert "acropolis_registered_servers" in resp.text


# ---------------------------------------------------------------------------
# /stats — dashboard payload stays 200, audit-derived fields null, server data intact
# ---------------------------------------------------------------------------

class TestStatsDegradesWhenAuditStoreDown:
    async def test_healthy_path_returns_counts_and_recent_blocked(self, app_client):
        """Regression guard: with a healthy store, /stats must keep returning plain ints and a
        real recent_blocked list — the nullable fields only matter in the degraded case."""
        client, _db = app_client
        resp = await client.get("/api/v1/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body["requests_24h"], int)
        assert isinstance(body["blocked_24h"], int)
        assert isinstance(body["allowed_24h"], int)
        assert isinstance(body["recent_blocked"], list)
        assert isinstance(body["servers_total"], int)

    async def test_audit_read_failure_nulls_audit_fields_but_keeps_server_data(self, app_client, monkeypatch):
        """The core claim of #109 on the dashboard side: an audit outage must not 500 /stats —
        servers_total/healthy/unhealthy and server_health[] are config-sourced and were already
        in hand, so they keep rendering. Only the audit-derived fields degrade to null."""
        client, db = app_client
        server_repo = ServerRepo(db)
        await server_repo.create(slug="stats-down", name="Down", upstream_url="http://127.0.0.1:1/mcp")

        monkeypatch.setattr(AuditRepo, "count_since", _AuditStoreDown._raise)
        monkeypatch.setattr(AuditRepo, "query", _AuditStoreDown._raise)
        resp = await client.get("/api/v1/stats")

        assert resp.status_code == 200
        body = resp.json()
        assert body["requests_24h"] is None
        assert body["blocked_24h"] is None
        assert body["allowed_24h"] is None
        assert body["recent_blocked"] is None
        # Config-sourced fields are untouched by the outage.
        assert body["servers_total"] == 1
        assert body["servers_healthy"] == 0
        assert body["servers_unhealthy"] == 0
        assert [s["slug"] for s in body["server_health"]] == ["stats-down"]

    async def test_partial_audit_failure_nulls_all_audit_fields(self, app_client, monkeypatch):
        """A failure on the SECOND count_since call (after the first succeeded) must null the
        WHOLE audit-derived set, not just the failed field. A mixed response (a real
        requests_24h next to a null allowed_24h) would let a viewer misread "unavailable" as
        "zero" — the same all-or-nothing guarantee /metrics gives the counter family, so the
        two endpoints can't disagree about what an audit outage looks like."""
        client, db = app_client
        server_repo = ServerRepo(db)
        await server_repo.create(slug="stats-flaky", name="Flaky", upstream_url="http://127.0.0.1:1/mcp")
        calls = {"n": 0}

        async def flaky_count_since(self, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RuntimeError("simulated audit store outage (issue #109)")
            return 7

        monkeypatch.setattr(AuditRepo, "count_since", flaky_count_since)
        resp = await client.get("/api/v1/stats")

        assert resp.status_code == 200
        body = resp.json()
        # Even though the first count_since succeeded, the whole set is nulled.
        assert body["requests_24h"] is None
        assert body["blocked_24h"] is None
        assert body["allowed_24h"] is None
        assert body["recent_blocked"] is None
        # Config-sourced fields are untouched.
        assert body["servers_total"] == 1
        assert [s["slug"] for s in body["server_health"]] == ["stats-flaky"]
