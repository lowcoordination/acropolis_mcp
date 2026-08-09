"""Enterprise #9 (OTel tracing) — the canary secrecy test. Per the plan, this is the single most
important test in the whole feature: run a call with a memorable fake secret value in a tool
ARGUMENT and a memorable fake CREDENTIAL REFERENCE, capture every span that gets exported (via an
in-memory exporter, the strongest possible proof — not a mock, not a log-line grep, the literal
serialized span objects), and assert neither canary string appears anywhere in them.

Matches the style/rigor of tests/integration/test_secrets_security_sweep.py (enterprise #5's own
canary sweep) — same idea, new surface (spans instead of DB/export/logs).

Two independent canaries, deliberately covering different leak vectors:

- ARGUMENT_CANARY: a fake API key VALUE sitting in a tool call argument. Must never appear in
  any span attribute under ANY code path, including the error/block path (a DLP block still
  evaluates the argument; the whole point of the DLP + audit-log precedent this feature extends
  is that the matched VALUE never surfaces anywhere, only which detector fired).
- CREDENTIAL_CANARY: a fake RESOLVED credential (the plaintext a SecretProvider.resolve() would
  return for a vault:// reference). Must never appear in any span attribute, including on the
  secrets.resolve span itself and including on the upstream.forward span that uses it to build
  the Authorization header.
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

ARGUMENT_CANARY = "sk-CANARY-ARG-a1b2c3d4e5f6-must-never-appear-in-a-span"
CREDENTIAL_CANARY = "Bearer sk-CANARY-CRED-9f8e7d6c5b4a-must-never-appear-in-a-span"
CREDENTIAL_REF = "vault://secret/acropolis/canary-server#token"


class _CanarySecretProvider:
    """Resolves ANY reference to CREDENTIAL_CANARY, unconditionally — stands in for a real
    Vault/OpenBao round-trip, same role _FakeReferenceSecretProvider plays in
    test_otel_span_shape.py, just with a name that makes this file's specific canary claim
    obvious on its own."""

    async def resolve(self, ref: str) -> str:
        return CREDENTIAL_CANARY

    async def store(self, ref: str, value: str) -> str:
        raise NotImplementedError

    async def delete(self, ref: str) -> None:
        raise NotImplementedError


def _serialize_all_spans(exporter: InMemorySpanExporter) -> str:
    """The actual proof mechanism: stringify EVERY field of EVERY exported span — name,
    attributes, events (which is where record_exception's exception.message / exception.stacktrace
    would land if a raw exception object ever got recorded), status description, links — into one
    blob, then the test does a plain substring search. Deliberately broader than just
    `span.attributes` so a leak via an exception message or event body would also be caught, not
    just a leak via a named attribute."""
    chunks = []
    for span in exporter.get_finished_spans():
        chunks.append(span.name)
        chunks.append(str(dict(span.attributes)))
        chunks.append(str(span.status.description))
        for event in span.events:
            chunks.append(event.name)
            chunks.append(str(dict(event.attributes)))
        for link in span.links:
            chunks.append(str(dict(link.attributes)))
    return "\n".join(chunks)


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


async def _run_traced_bridged_call(
    tmp_path: Path, upstream, *, dlp_action: str, secret_provider=None,
) -> InMemorySpanExporter:
    """Registers a server with BOTH a DLP detector configured (so the argument canary gets
    scanned and — depending on dlp_action — either redacted or blocks the call outright) and,
    when secret_provider is given, a vault:// credential reference (so the credential canary
    gets resolved). Sends one tools/call carrying ARGUMENT_CANARY in an argument, with tracing
    fully active against an in-memory exporter, and returns that exporter for the test to sweep.
    """
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False, audit_retention_enabled=False)
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(
        slug="canary-server", name="Canary", upstream_url=f"{upstream.url}/mcp",
        upstream_auth_header=CREDENTIAL_REF if secret_provider is not None else None,
    )
    # aws_access_key is a builtin detector that will NOT match ARGUMENT_CANARY's shape, so use a
    # custom pattern keyed on the canary's own literal prefix — this way the test controls
    # exactly what "matches" means rather than depending on a builtin detector's regex shape.
    from db.models import DlpCustomPattern

    server = await server_repo.get("canary-server")
    await server_repo.set_policy(
        server.id,
        ServerPolicy(
            mode="passthrough",
            dlp_custom_patterns=[
                DlpCustomPattern(name="canary_pattern", pattern=r"sk-CANARY-ARG-[a-f0-9]+", action=dlp_action),
            ],
        ),
    )

    app = create_app(settings, db)
    exporter = InMemorySpanExporter()
    manager = TracingManager(enabled=True, sample_ratio=1.0)
    manager.init(exporter=exporter)
    app.state.pipeline._tracing = manager
    app.state.bridge._tracing = manager
    if secret_provider is not None:
        app.state.pipeline._secrets = secret_provider

    transport = httpx.ASGITransport(app=app)
    headers = {
        "Content-Type": "application/json", "Accept": "application/json",
        "Mcp-Method": "tools/call", "Mcp-Name": "echo",
    }
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": f"my key is {ARGUMENT_CANARY}"}},
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            await client.post("/mcp/canary-server", json=body, headers=headers)

    await db.close()
    return exporter


class TestArgumentCanaryNeverInSpans:
    async def test_redact_action_canary_absent_from_every_span(self, tmp_path, upstream):
        """The redact path is the more dangerous one to get wrong: dlp.scan's own attributes
        (acropolis.dlp_detector / acropolis.dlp_action) are legitimately set, right next to
        where the matched value lives in-process — this is exactly the shape of bug the DLP PR's
        own audit-log fix (summarize_args re-derivation) closed for the audit log; this test is
        the same proof for spans."""
        exporter = await _run_traced_bridged_call(tmp_path, upstream, dlp_action="redact")
        blob = _serialize_all_spans(exporter)
        assert ARGUMENT_CANARY not in blob, "argument canary leaked into a span (redact path)"
        # The detector/action ARE expected to appear — that's the safe, allowed part.
        assert "canary_pattern" in blob or "redact" in blob

    async def test_block_action_canary_absent_from_every_span(self, tmp_path, upstream):
        """The block path evaluates the same argument (to decide whether to block) without ever
        forwarding it — must be equally canary-free, including on the policy.evaluate span's
        error/status path if the call site ever records one."""
        exporter = await _run_traced_bridged_call(tmp_path, upstream, dlp_action="block")
        blob = _serialize_all_spans(exporter)
        assert ARGUMENT_CANARY not in blob, "argument canary leaked into a span (block path)"


class TestCredentialCanaryNeverInSpans:
    async def test_resolved_credential_absent_from_every_span(self, tmp_path, upstream):
        """secrets.resolve span attributes are server_slug only (see
        Pipeline._resolve_credential) — but this test proves it directly against the real
        resolved value, rather than trusting a code-review read of the call site. The credential
        also flows into upstream.forward's headers (as the Authorization value sent to the
        upstream) — that path is swept too, since _serialize_all_spans covers every exported
        span, not just secrets.resolve."""
        exporter = await _run_traced_bridged_call(
            tmp_path, upstream, dlp_action="allow", secret_provider=_CanarySecretProvider(),
        )
        blob = _serialize_all_spans(exporter)
        assert CREDENTIAL_CANARY not in blob, "resolved credential leaked into a span"
        # secrets.resolve must have actually run (sanity: the test exercised the real path).
        names = [s.name for s in exporter.get_finished_spans()]
        assert "secrets.resolve" in names

    async def test_both_canaries_together_absent_from_every_span(self, tmp_path, upstream):
        """The combined case the plan explicitly asks for: one call, both a canary argument AND
        a canary credential reference in play at once, sweeping the FULL exported span set."""
        exporter = await _run_traced_bridged_call(
            tmp_path, upstream, dlp_action="redact", secret_provider=_CanarySecretProvider(),
        )
        blob = _serialize_all_spans(exporter)
        assert ARGUMENT_CANARY not in blob, "argument canary leaked into a span"
        assert CREDENTIAL_CANARY not in blob, "resolved credential leaked into a span"
        # The (non-secret) reference string itself is fine to appear nowhere in particular here
        # (this code path doesn't put it in any span attribute) — no assertion either way; the
        # only load-bearing claims are the two negatives above.
