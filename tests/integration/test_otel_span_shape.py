"""Enterprise #9 (OTel tracing) — span-tree-shape tests using an in-memory span exporter.

Rather than going through ACROPOLIS_OTEL_ENABLED (a process-environment gate read once at
create_app() call time — see argus/tracing.py's otel_enabled_by_env), these tests build their
own already-init()'d TracingManager (wired to an InMemorySpanExporter) and swap it directly onto
app.state.pipeline._tracing / app.state.bridge._tracing AFTER create_app() but BEFORE the
lifespan context starts. This is the same "construct via create_app, then reach in and replace
one collaborator" pattern test_secret_resolution_failure.py uses for `_secrets` — necessary here
because there is no settings-object seam for tracing (deliberately: see design decision 6, real
OTel env vars only), so a fixture-level env var wouldn't let us inject an in-memory exporter.

The app's OWN internally-built TracingManager (from build_tracing_manager(), reading the real
process environment) stays wired to app.state.tracing and gets tracing.init() called on it by
the real lifespan — but since ACROPOLIS_OTEL_ENABLED is never set in the test environment, that
manager's init() is a no-op and it never touches the global OTel registry, so there's no
collision with the per-test manager we swap onto pipeline/bridge (see argus/tracing.py's
TracerProvider-is-never-set-globally note for why two managers can coexist safely in one
process).
"""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from argus.tracing import TracingManager
from db.database import Database
from db.models import ServerPolicy
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server

pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402


class _FakeReferenceSecretProvider:
    """Stands in for a real Vault/OpenBao round-trip — resolves any vault://-shaped reference to
    a fixed plaintext, synchronously, no network. Used only to prove the secrets.resolve span
    appears (and only for reference-shaped credentials, never literals) — the actual resolution
    correctness is covered elsewhere (tests/unit/test_secrets_local.py and friends)."""

    def __init__(self, plaintext: str = "Bearer resolved-upstream-token"):
        self._plaintext = plaintext

    async def resolve(self, ref: str) -> str:
        return self._plaintext

    async def store(self, ref: str, value: str) -> str:
        raise NotImplementedError

    async def delete(self, ref: str) -> None:
        raise NotImplementedError


def _install_test_tracing(app) -> InMemorySpanExporter:
    """Builds an active TracingManager backed by an InMemorySpanExporter and swaps it onto both
    Pipeline and ProtocolBridge — the two collaborators that actually open spans."""
    exporter = InMemorySpanExporter()
    manager = TracingManager(enabled=True, sample_ratio=1.0)
    manager.init(exporter=exporter)
    app.state.pipeline._tracing = manager
    app.state.bridge._tracing = manager
    app.state.tracing = manager
    return exporter


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


@pytest.fixture
async def traced_app(tmp_path: Path, upstream):
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="traced-server", name="Traced", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)
    exporter = _install_test_tracing(app)

    async with app.router.lifespan_context(app):
        yield app, exporter, server_repo, upstream

    await db.close()


def _span_names(exporter: InMemorySpanExporter) -> list[str]:
    return [s.name for s in exporter.get_finished_spans()]


def _span_by_name(exporter: InMemorySpanExporter, name: str):
    matches = [s for s in exporter.get_finished_spans() if s.name == name]
    assert len(matches) == 1, f"expected exactly one {name!r} span, found {len(matches)}: {_span_names(exporter)}"
    return matches[0]


GEN_2026_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


async def _bridged_tools_call(app, slug: str, tool: str, arguments: dict) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    headers = {**GEN_2026_HEADERS, "Mcp-Method": "tools/call", "Mcp-Name": tool}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
        return await client.post(f"/mcp/{slug}", json=body, headers=headers)


# ---------------------------------------------------------------------------
# (a) plain bridged call: request -> policy.evaluate -> bridge.handshake -> upstream.forward
# ---------------------------------------------------------------------------

class TestBridgedCallSpanTree:
    async def test_span_names_present(self, traced_app):
        app, exporter, _, _ = traced_app
        resp = await _bridged_tools_call(app, "traced-server", "echo", {"message": "hi"})
        assert resp.status_code == 200

        names = _span_names(exporter)
        assert "request" in names
        assert "policy.evaluate" in names
        assert "bridge.handshake" in names
        assert "upstream.forward" in names
        # No DLP configured on this server -> no dlp.scan span at all.
        assert "dlp.scan" not in names
        # No credential reference configured -> no secrets.resolve span at all.
        assert "secrets.resolve" not in names

    async def test_parent_child_relationship(self, traced_app):
        """The root `request` span must be the ancestor of every other span in the tree — proves
        this is a genuine nested trace, not five sibling spans that happen to share a trace id
        by coincidence."""
        app, exporter, _, _ = traced_app
        await _bridged_tools_call(app, "traced-server", "echo", {"message": "hi"})

        spans = {s.name: s for s in exporter.get_finished_spans()}
        root = spans["request"]
        for name in ("policy.evaluate", "bridge.handshake", "upstream.forward"):
            child = spans[name]
            assert child.context.trace_id == root.context.trace_id, (
                f"{name} span is not part of the same trace as the root request span"
            )

    async def test_request_span_has_expected_attributes(self, traced_app):
        app, exporter, _, _ = traced_app
        resp = await _bridged_tools_call(app, "traced-server", "echo", {"message": "hi"})
        assert resp.status_code == 200

        root = _span_by_name(exporter, "request")
        assert root.attributes["acropolis.server_slug"] == "traced-server"
        assert root.attributes["http.status_code"] == 200

    async def test_policy_evaluate_span_has_decision_and_no_argument_values(self, traced_app):
        app, exporter, _, _ = traced_app
        await _bridged_tools_call(app, "traced-server", "echo", {"message": "some argument text"})

        policy_span = _span_by_name(exporter, "policy.evaluate")
        assert policy_span.attributes["acropolis.decision"] == "ALLOWED"
        assert policy_span.attributes["acropolis.tool"] == "echo"
        # Attribute secrecy: only the allowed set. "some argument text" must not appear.
        for value in policy_span.attributes.values():
            assert "some argument text" not in str(value)

    async def test_bridge_handshake_span_has_protocol_version(self, traced_app):
        app, exporter, _, _ = traced_app
        await _bridged_tools_call(app, "traced-server", "echo", {"message": "hi"})

        handshake_span = _span_by_name(exporter, "bridge.handshake")
        assert handshake_span.attributes.get("acropolis.mcp_protocol_version")
        assert handshake_span.attributes.get("acropolis.bridged") is True

    async def test_upstream_forward_span_has_status_code(self, traced_app):
        app, exporter, _, _ = traced_app
        await _bridged_tools_call(app, "traced-server", "echo", {"message": "hi"})

        forward_span = _span_by_name(exporter, "upstream.forward")
        assert forward_span.attributes["http.status_code"] == 200


# ---------------------------------------------------------------------------
# (b) DLP-redacted call: dlp.scan span present, action visible, matched value NOT
# ---------------------------------------------------------------------------

class TestDlpRedactedCallSpanTree:
    async def test_dlp_scan_span_present_with_correct_attributes(self, traced_app):
        app, exporter, server_repo, _ = traced_app
        server = await server_repo.get("traced-server")
        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"email": "redact"}))

        resp = await _bridged_tools_call(app, "traced-server", "echo", {"message": "contact nick@example.com"})
        assert resp.status_code == 200

        names = _span_names(exporter)
        assert "dlp.scan" in names

        dlp_span = _span_by_name(exporter, "dlp.scan")
        assert dlp_span.attributes.get("acropolis.dlp_detector") == "email"
        assert dlp_span.attributes.get("acropolis.dlp_action") == "redact"

        # The matched/redacted VALUE must never appear in ANY span's attributes — this is the
        # core secrecy claim for this span in particular; the full canary sweep across every
        # span (not just dlp.scan) lives in test_otel_secrecy.py.
        for span in exporter.get_finished_spans():
            for value in span.attributes.values():
                assert "nick@example.com" not in str(value)

    async def test_dlp_scan_is_nested_under_policy_evaluate(self, traced_app):
        app, exporter, server_repo, _ = traced_app
        server = await server_repo.get("traced-server")
        await server_repo.set_policy(server.id, ServerPolicy(mode="passthrough", dlp_detectors={"email": "redact"}))

        await _bridged_tools_call(app, "traced-server", "echo", {"message": "contact nick@example.com"})

        spans = {s.name: s for s in exporter.get_finished_spans()}
        dlp_span = spans["dlp.scan"]
        policy_span = spans["policy.evaluate"]
        assert dlp_span.parent is not None
        assert dlp_span.parent.span_id == policy_span.context.span_id

    async def test_no_dlp_configured_means_no_dlp_scan_span(self, traced_app):
        """Regression guard for the "only when DLP is configured" gate — a server with no
        dlp_detectors/dlp_custom_patterns must never get a dlp.scan span, matching evaluate()'s
        own early-return (see Pipeline._evaluate_with_tracing's docstring)."""
        app, exporter, _, _ = traced_app
        await _bridged_tools_call(app, "traced-server", "echo", {"message": "contact nick@example.com"})
        assert "dlp.scan" not in _span_names(exporter)


# ---------------------------------------------------------------------------
# (c) secret-reference call: secrets.resolve span present
# ---------------------------------------------------------------------------

class TestSecretReferenceCallSpanTree:
    async def test_secrets_resolve_span_present_for_reference_credential(self, tmp_path: Path, upstream):
        settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
        db = Database(tmp_path)
        await db.connect()
        server_repo = ServerRepo(db)
        await server_repo.create(
            slug="secured-server", name="Secured", upstream_url=f"{upstream.url}/mcp",
            upstream_auth_header="vault://secret/acropolis/secured#token",
        )

        app = create_app(settings, db)
        exporter = _install_test_tracing(app)
        app.state.pipeline._secrets = _FakeReferenceSecretProvider()

        async with app.router.lifespan_context(app):
            resp = await _bridged_tools_call(app, "secured-server", "echo", {"message": "hi"})
        await db.close()

        assert resp.status_code == 200
        assert "secrets.resolve" in _span_names(exporter)
        resolve_span = _span_by_name(exporter, "secrets.resolve")
        assert resolve_span.attributes["acropolis.server_slug"] == "secured-server"
        # The resolved plaintext must never appear in ANY span attribute.
        for span in exporter.get_finished_spans():
            for value in span.attributes.values():
                assert "resolved-upstream-token" not in str(value)

    async def test_literal_credential_gets_no_secrets_resolve_span(self, tmp_path: Path, upstream):
        """A literal (non-reference) upstream_auth_header is a same-process, zero-I/O
        pass-through (archon/secrets/local.py) — spanning it would be noise around a no-op, so
        the plan's "only when the credential is a reference" gate must actually hold."""
        settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
        db = Database(tmp_path)
        await db.connect()
        server_repo = ServerRepo(db)
        await server_repo.create(
            slug="literal-cred-server", name="Literal", upstream_url=f"{upstream.url}/mcp",
            upstream_auth_header="Bearer some-literal-value",
        )

        app = create_app(settings, db)
        exporter = _install_test_tracing(app)

        async with app.router.lifespan_context(app):
            resp = await _bridged_tools_call(app, "literal-cred-server", "echo", {"message": "hi"})
        await db.close()

        assert resp.status_code == 200
        assert "secrets.resolve" not in _span_names(exporter)
