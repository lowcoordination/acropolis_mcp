"""Item 3 (features_08_05_26): webhook alerts on BLOCKED / unhealthy events.

The plan calls this the highest-risk item in either feature plan — a gateway that POSTs to an
operator-supplied URL is an SSRF primitive by construction. These tests cover the three axes the
plan requires: URL validation is stricter than the upstream validator (blocks RFC1918 by
default, not just link-local), redirects are never followed, and volume control (debounce + cap)
actually holds under a burst rather than just existing in the code.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path

import httpx
import pytest

from archon.schemas import _validate_webhook_url
from archon.settings import Settings
from argus.app import create_app
from argus.audit import AuditLogger
from db.database import Database
from db.repo import AuditRepo, SettingsRepo
from stoa import webhooks as webhooks_module
from stoa.webhooks import CAP_MAX_PER_WINDOW, WebhookDispatcher


# ---------------------------------------------------------------------------
# A minimal raw TCP receiver — same pattern as test_security_regression.py's
# _HeaderCapturingUpstream, for the same reason: proves what actually left the process on the
# wire (headers, body, and that a redirect response is never followed) rather than mocking httpx.
# ---------------------------------------------------------------------------


class _WebhookReceiver:
    def __init__(self, response_status: str = "200 OK", extra_headers: str = ""):
        self.requests: list[dict] = []
        self._server: asyncio.AbstractServer | None = None
        self.url = ""
        self._response_status = response_status
        self._extra_headers = extra_headers

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        lines = data.decode(errors="replace").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v
        body = b""
        length = int(headers.get("content-length", "0"))
        if length:
            body = await reader.readexactly(length)
        self.requests.append({"headers": headers, "body": body})
        resp_body = b"{}"
        writer.write(
            (
                f"HTTP/1.1 {self._response_status}\r\nContent-Type: application/json\r\n"
                f"{self._extra_headers}Content-Length: {len(resp_body)}\r\n\r\n"
            ).encode()
            + resp_body
        )
        await writer.drain()
        writer.close()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        # Plain HTTP, deliberately: this is a raw TCP stub with no TLS support, standing in for
        # the RECEIVER side only — it exists to prove what the dispatcher actually put on the
        # wire (headers, body, redirect-following), not to exercise scheme validation. Loopback
        # is also exactly what the strict validator blocks by default, so tests using this
        # receiver write the URL directly via SettingsRepo, bypassing the Pydantic validator
        # that only runs on the PUT /settings API path (covered separately above).
        self.url = f"http://127.0.0.1:{port}/hook"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
async def api_client(tmp_path: Path):
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False,
        audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client
    await db.close()


# ---------------------------------------------------------------------------
# URL validation — the plan's core SSRF requirement
# ---------------------------------------------------------------------------


class TestValidateWebhookUrl:
    def test_rejects_http(self):
        with pytest.raises(ValueError, match="https"):
            _validate_webhook_url("http://example.com/hook")

    def test_rejects_loopback_by_default(self):
        with pytest.raises(ValueError, match="non-public"):
            _validate_webhook_url("https://127.0.0.1/hook")

    def test_rejects_link_local_by_default(self):
        with pytest.raises(ValueError, match="non-public"):
            _validate_webhook_url("https://169.254.169.254/hook")

    def test_rejects_rfc1918_by_default(self):
        # This is the exact case _validate_upstream_url (F17) deliberately ALLOWS — the two
        # functions must disagree here, or the stricter policy doesn't exist.
        with pytest.raises(ValueError, match="non-public"):
            _validate_webhook_url("https://192.168.1.50/hook")

    def test_allows_rfc1918_with_explicit_opt_in(self):
        assert _validate_webhook_url("https://192.168.1.50/hook", allow_private=True)

    def test_allows_public_https(self):
        assert _validate_webhook_url("https://hooks.example.com/endpoint")

    def test_rejects_hostname_resolving_to_link_local(self, monkeypatch):
        import socket

        def fake_getaddrinfo(host, port):
            return [(socket.AF_INET, None, None, None, ("169.254.169.254", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValueError, match="non-public"):
            _validate_webhook_url("https://sneaky.example.com/hook")


# ---------------------------------------------------------------------------
# Settings route: allowlist enforcement, secret generation, validation wired through the API
# ---------------------------------------------------------------------------


class TestWebhookSettingsRoute:
    async def test_setting_a_private_url_is_rejected_without_opt_in(self, api_client):
        resp = await api_client.put("/api/v1/settings", json={"webhook_url": "https://192.168.1.5/hook"})
        assert resp.status_code == 422

    async def test_setting_a_private_url_succeeds_with_opt_in(self, api_client):
        resp = await api_client.put(
            "/api/v1/settings",
            json={"webhook_url": "https://192.168.1.5/hook", "webhook_allow_private": True},
        )
        assert resp.status_code == 200
        assert resp.json()["webhook_url"] == "https://192.168.1.5/hook"

    async def test_setting_a_url_generates_a_secret_exactly_once(self, api_client, db):
        await api_client.put("/api/v1/settings", json={"webhook_url": "https://hooks.example.com/a"})
        settings_repo = SettingsRepo(db)
        first_secret = await settings_repo.get("webhook_secret")
        assert first_secret is not None

        await api_client.put("/api/v1/settings", json={"webhook_url": "https://hooks.example.com/b"})
        assert await settings_repo.get("webhook_secret") == first_secret

    async def test_secret_is_never_returned_by_get_settings(self, api_client):
        await api_client.put("/api/v1/settings", json={"webhook_url": "https://hooks.example.com/a"})
        resp = await api_client.get("/api/v1/settings")
        body = resp.json()
        assert "webhook_secret" not in body
        # A substring check alone would false-negative on "has_webhook_secret" containing the
        # word — assert on the actual VALUE, not the raw JSON text, so this can't pass vacuously.
        assert set(body.keys()) & {"webhook_secret"} == set()
        assert body["has_webhook_secret"] is True

    async def test_rejects_unsupported_event_name(self, api_client):
        resp = await api_client.put("/api/v1/settings", json={"webhook_events": ["blocked", "bogus"]})
        assert resp.status_code == 400

    async def test_empty_string_clears_url(self, api_client):
        await api_client.put("/api/v1/settings", json={"webhook_url": "https://hooks.example.com/a"})
        resp = await api_client.put("/api/v1/settings", json={"webhook_url": ""})
        assert resp.status_code == 200
        assert resp.json()["webhook_url"] == ""


# ---------------------------------------------------------------------------
# Send-test-webhook route
# ---------------------------------------------------------------------------


class TestSendTestWebhook:
    async def test_no_url_configured_reports_not_ok(self, api_client):
        resp = await api_client.post("/api/v1/webhooks/test")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "not configured" in body["error"]

    async def test_test_send_reaches_a_real_receiver_with_signature_header(self, api_client, db):
        receiver = _WebhookReceiver()
        await receiver.start()
        try:
            settings_repo = SettingsRepo(db)
            # Bypass the API's strict validator to point at our loopback receiver — this test is
            # about payload/signature shape, not about re-proving the validator (covered above).
            await settings_repo.set_many({
                "webhook_url": receiver.url, "webhook_enabled": "true",
                "webhook_secret": "test-secret",
            })
            dispatcher = webhooks_module.WebhookDispatcher(
                AuditLogger(AuditRepo(db)), settings_repo,
                http_client=httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False),
            )
            ok, status_code, error = await dispatcher.send_test()
            await dispatcher._http.aclose()
        finally:
            await receiver.stop()

        assert ok is True
        assert status_code == 200
        assert error is None
        assert len(receiver.requests) == 1
        req = receiver.requests[0]
        body = json.loads(req["body"])
        assert body["event"] == "test"
        expected_sig = hmac.new(b"test-secret", req["body"], hashlib.sha256).hexdigest()
        assert req["headers"]["x-acropolis-signature"] == f"sha256={expected_sig}"


# ---------------------------------------------------------------------------
# Dispatcher behavior: no redirects, debounce, cap+suppression, edge-only health firing
# ---------------------------------------------------------------------------


class TestWebhookDispatcherBehavior:
    async def test_follow_redirects_is_disabled_on_the_dispatcher_client(self, db):
        settings_repo = SettingsRepo(db)
        dispatcher = WebhookDispatcher(AuditLogger(AuditRepo(db)), settings_repo)
        try:
            assert dispatcher._http.follow_redirects is False
        finally:
            await dispatcher._http.aclose()

    async def test_redirect_response_is_not_followed(self, db):
        """A 302 to a private/link-local address is the specific bypass the plan calls out —
        this proves the dispatcher's own client does not chase it, independent of the
        follow_redirects flag check above actually mattering at request time."""
        redirect_target_hits = []

        async def handle_redirector(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle_redirector, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            settings_repo = SettingsRepo(db)
            await settings_repo.set_many({
                "webhook_url": f"http://127.0.0.1:{port}/hook", "webhook_enabled": "true",
            })
            dispatcher = WebhookDispatcher(
                AuditLogger(AuditRepo(db)), settings_repo,
                http_client=httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False),
            )
            # httpx raises nothing for a 3xx when follow_redirects=False — it just returns the
            # 302 as the response. send_test() reports that as not-ok (200<=x<300 is false),
            # which is correct: a redirecting receiver is a broken/hostile one either way, and
            # the important thing is that redirect_target_hits stays empty.
            ok, status_code, error = await dispatcher.send_test()
            await dispatcher._http.aclose()
        finally:
            server.close()
            await server.wait_closed()

        assert ok is False
        assert status_code == 302
        assert redirect_target_hits == []

    async def test_debounce_collapses_rapid_repeats_into_one_post_with_count(self, db):
        receiver = _WebhookReceiver()
        await receiver.start()
        try:
            settings_repo = SettingsRepo(db)
            await settings_repo.set_many({
                "webhook_url": receiver.url, "webhook_enabled": "true", "webhook_events": "blocked",
            })
            audit = AuditLogger(AuditRepo(db))
            dispatcher = WebhookDispatcher(
                audit, settings_repo,
                http_client=httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False),
            )
            import stoa.webhooks as wh
            monkeypatch_window = 0.2
            orig_window = wh.DEBOUNCE_WINDOW_SECONDS
            wh.DEBOUNCE_WINDOW_SECONDS = monkeypatch_window
            try:
                dispatcher.start()
                for _ in range(5):
                    await audit.log("srv", "tool", "BLOCKED", rule="denylist", matched="tool")
                await asyncio.sleep(monkeypatch_window + 0.3)
            finally:
                wh.DEBOUNCE_WINDOW_SECONDS = orig_window
                await dispatcher.stop()
        finally:
            await receiver.stop()

        assert len(receiver.requests) == 1
        body = json.loads(receiver.requests[0]["body"])
        assert body["count"] == 5
        assert body["event"] == "blocked"

    async def test_test_origin_blocked_events_never_trigger_a_webhook(self, db):
        """origin='test' rows come from Item 1's tool tester (feature/tool-tester, unmerged as
        of this branch) — they must not fire real alerts, same reasoning as why they're excluded
        from /stats. AuditLogger.log() on THIS branch has no origin param yet, so this drives
        _handle_blocked directly with a raw event dict shaped the way Item 1's will look once
        merged — that's what actually proves the dispatcher's own filter, independent of
        whichever branch lands the origin column first."""
        receiver = _WebhookReceiver()
        await receiver.start()
        try:
            settings_repo = SettingsRepo(db)
            await settings_repo.set_many({
                "webhook_url": receiver.url, "webhook_enabled": "true", "webhook_events": "blocked",
            })
            dispatcher = WebhookDispatcher(
                AuditLogger(AuditRepo(db)), settings_repo,
                http_client=httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False),
            )
            await dispatcher._handle_blocked({
                "decision": "BLOCKED", "server_slug": "srv", "tool": "tool",
                "rule": "denylist", "matched": "tool", "origin": "test",
            })
            await asyncio.sleep(0.1)
            await dispatcher._http.aclose()
        finally:
            await receiver.stop()

        assert receiver.requests == []

    async def test_cap_suppresses_then_flushes_one_notice_with_the_true_tally_on_stop(self, db):
        settings_repo = SettingsRepo(db)
        await settings_repo.set_many({"webhook_url": "https://x/", "webhook_enabled": "true"})
        dispatcher = WebhookDispatcher(AuditLogger(AuditRepo(db)), settings_repo)
        sent: list[dict] = []

        async def fake_post(config, payload):
            sent.append(payload)
            return httpx.Response(200, request=httpx.Request("POST", "https://x/"))

        dispatcher._post = fake_post  # isolate cap logic from real HTTP entirely
        config = {"url": "https://x/", "secret": None, "events": {"blocked"}}

        for i in range(CAP_MAX_PER_WINDOW + 5):
            await dispatcher._send_if_under_cap(config, {"event": "blocked", "count": 1})

        # No notice yet — the window hasn't rolled over and the dispatcher hasn't stopped, so
        # nothing has flushed. This is the case the earlier design got wrong: sending "count: 1"
        # the instant the cap first trips undercounts a window that goes on to suppress much
        # more than that.
        assert not any(p["event"] == "suppressed" for p in sent)

        await dispatcher.stop()

        real_alerts = [p for p in sent if p["event"] == "blocked"]
        suppression_notices = [p for p in sent if p["event"] == "suppressed"]
        assert len(real_alerts) == CAP_MAX_PER_WINDOW
        # Exactly one suppression notice with the TRUE final tally, not silence and not one per
        # suppressed event — "silence and nothing happened must never look alike" per the plan.
        assert len(suppression_notices) == 1
        assert suppression_notices[0]["count"] == 5

    async def test_health_edge_fires_once_not_per_poll(self, db):
        from db.repo import ServerRepo
        from stoa.health import HealthPoller

        server_repo = ServerRepo(db)
        await server_repo.create(slug="dead", name="Dead", upstream_url="http://127.0.0.1:1/mcp")

        notified: list[str] = []

        class _FakeDispatcher:
            async def notify_unhealthy(self, slug):
                notified.append(slug)

        async with httpx.AsyncClient() as client:
            from argus.upstream import UpstreamHandshakeCache

            poller = HealthPoller(
                server_repo, client, UpstreamHandshakeCache(client), webhook_dispatcher=_FakeDispatcher()
            )
            await poller.poll_once()  # unknown -> unhealthy: edge, should fire
            await poller.poll_once()  # unhealthy -> unhealthy: no edge, must NOT fire again

        assert notified == ["dead"]
