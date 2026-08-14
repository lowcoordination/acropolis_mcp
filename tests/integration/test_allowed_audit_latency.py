"""Regression test for issue #99: ALLOWED-path audit latency_ms is frozen pre-forward.

`Pipeline._enforce` used to build `audit_common` (including `latency_ms`) once, near the top of
enforcement — before rate limiting, quota checks, and policy evaluation ran. The ALLOWED audit
row logged that frozen value, so every forwarded call's `latency_ms` truncated to ~0 (elapsed
time at that point is sub-millisecond). BLOCKED/error paths were unaffected — `_refuse`/`_error`
already compute `latency_ms` at their own call site. Found by
`tests/bench/bench_pipeline.py` Part 3's audit-vs-client latency cross-check.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

import argus.pipeline as pipeline_mod
from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import AuditRepo, ServerRepo

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def upstream():
    async with run_fastmcp_server() as server:
        yield server


async def test_allowed_audit_row_reflects_real_delay_during_enforcement(
    tmp_path: Path, upstream, monkeypatch,
):
    """Patches Pipeline._evaluate_with_tracing (called just before the ALLOWED audit log, deep
    inside _enforce) to sleep 150ms real time. Before the fix, latency_ms was computed once at
    _enforce's entry — BEFORE this sleep — so it would not reflect the delay at all (~0ms).
    After the fix, latency_ms is computed at the actual ALLOWED log call, which happens AFTER
    the sleep, so it must reflect it.

    Verified against pre-fix argus/pipeline.py: this test fails with latency_ms=0 there and
    passes with latency_ms≈151 post-fix — a clean before/after regression proof, not just a
    plausible-looking assertion.
    """
    settings = Settings(
        data_dir=str(tmp_path), auth_mode="open",
        health_poll_enabled=False, audit_retention_enabled=False,
    )
    db = Database(tmp_path)
    await db.connect()
    server_repo = ServerRepo(db)
    await server_repo.create(slug="verify99", name="Verify99", upstream_url=f"{upstream.url}/mcp")

    app = create_app(settings, db)

    real_evaluate = pipeline_mod.Pipeline._evaluate_with_tracing

    async def slow_evaluate(self, *args, **kwargs):
        await asyncio.sleep(0.15)
        return await real_evaluate(self, *args, **kwargs)

    monkeypatch.setattr(pipeline_mod.Pipeline, "_evaluate_with_tracing", slow_evaluate)

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        headers = {
            "Content-Type": "application/json", "Accept": "application/json",
            "Mcp-Method": "tools/call", "Mcp-Name": "echo",
        }
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi"}},
        }
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            resp = await client.post("/mcp/verify99", json=body, headers=headers)
            assert resp.status_code == 200, resp.text

        await asyncio.sleep(0.3)
        audit = AuditRepo(db)
        rows = await audit.query(server_slug="verify99", decision="ALLOWED", limit=5)
        assert rows, "no ALLOWED audit row found"
        latency = rows[0]["latency_ms"]
        assert latency >= 100, (
            f"latency_ms={latency} — does not reflect the 150ms real delay injected before "
            "the ALLOWED audit log call; looks frozen at pre-delay time (the #99 bug)"
        )

    await db.close()
