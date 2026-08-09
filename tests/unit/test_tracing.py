"""Unit tests for argus/tracing.py — the module-level no-op-degrade behaviour, env parsing, and
the small allowlisted span interface. Integration-level span-tree-shape, propagation, and
secrecy tests live in tests/integration/test_otel_*.py (they need a real Pipeline/app wiring to
be meaningful); this file is the fast, dependency-light companion."""
from __future__ import annotations

import os

import pytest

from argus.tracing import (
    ENABLED_ENV_VAR,
    SAMPLE_RATIO_ENV_VAR,
    TracingManager,
    _DisabledTracingManager,
    build_tracing_manager,
    otel_enabled_by_env,
)


class TestEnvParsing:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv(ENABLED_ENV_VAR, raising=False)
        assert otel_enabled_by_env() is False

    @pytest.mark.parametrize("value", ["1", "true", "True", "TRUE", "yes", "on"])
    def test_recognised_true_values(self, monkeypatch, value):
        monkeypatch.setenv(ENABLED_ENV_VAR, value)
        assert otel_enabled_by_env() is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "garbage"])
    def test_everything_else_is_false(self, monkeypatch, value):
        monkeypatch.setenv(ENABLED_ENV_VAR, value)
        assert otel_enabled_by_env() is False

    def test_build_tracing_manager_default_ratio_is_1(self, monkeypatch):
        monkeypatch.delenv(ENABLED_ENV_VAR, raising=False)
        monkeypatch.delenv(SAMPLE_RATIO_ENV_VAR, raising=False)
        manager = build_tracing_manager()
        assert manager.enabled is False
        assert manager.sample_ratio == 1.0

    def test_build_tracing_manager_reads_ratio(self, monkeypatch):
        monkeypatch.setenv(ENABLED_ENV_VAR, "true")
        monkeypatch.setenv(SAMPLE_RATIO_ENV_VAR, "0.25")
        manager = build_tracing_manager()
        assert manager.enabled is True
        assert manager.sample_ratio == 0.25

    def test_build_tracing_manager_clamps_out_of_range_ratio(self, monkeypatch):
        monkeypatch.setenv(ENABLED_ENV_VAR, "true")
        monkeypatch.setenv(SAMPLE_RATIO_ENV_VAR, "5.0")
        manager = build_tracing_manager()
        assert manager.sample_ratio == 1.0

        monkeypatch.setenv(SAMPLE_RATIO_ENV_VAR, "-1.0")
        manager = build_tracing_manager()
        assert manager.sample_ratio == 0.0

    def test_build_tracing_manager_invalid_ratio_falls_back_to_1(self, monkeypatch):
        monkeypatch.setenv(ENABLED_ENV_VAR, "true")
        monkeypatch.setenv(SAMPLE_RATIO_ENV_VAR, "not-a-float")
        manager = build_tracing_manager()
        assert manager.sample_ratio == 1.0


class TestDisabledManagerIsANoOp:
    """Core regression guard: a TracingManager that was never enabled (the default for every
    existing Pipeline()/ProtocolBridge() construction in this codebase) must behave as a
    complete no-op — no OTel import, no exception, span() always yields something usable."""

    def test_default_manager_is_inactive(self):
        manager = _DisabledTracingManager()
        assert manager.active is False
        assert manager.enabled is False

    def test_disabled_init_never_imports_opentelemetry(self, monkeypatch):
        """Even if `opentelemetry` happens to be installed in this environment (it is, for the
        rest of this test file), a manager constructed with enabled=False must never reach the
        import statement at all — proven by making the import raise if it's ever attempted."""
        import builtins

        real_import = builtins.__import__

        def _guarded_import(name, *args, **kwargs):
            if name == "opentelemetry" or name.startswith("opentelemetry."):
                raise AssertionError("disabled TracingManager.init() must never import opentelemetry")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _guarded_import)
        manager = TracingManager(enabled=False)
        manager.init()  # must not raise, must not import
        assert manager.active is False

    def test_span_context_manager_yields_usable_noop_span(self):
        manager = _DisabledTracingManager()
        with manager.span("request", attributes={"acropolis.server_slug": "x"}) as span:
            # Every method a call site might invoke must be safe to call with no OTel active.
            span.set_attribute("anything", "value")
            span.record_exception(ValueError("boom"))
            span.set_status_error("boom")

    def test_span_context_manager_still_propagates_exceptions(self):
        manager = _DisabledTracingManager()
        with pytest.raises(ValueError):
            with manager.span("request"):
                raise ValueError("boom")

    def test_extract_context_returns_none_when_disabled(self):
        manager = _DisabledTracingManager()
        assert manager.extract_context("00-" + "a" * 32 + "-" + "b" * 16 + "-01") is None

    def test_inject_headers_returns_empty_dict_when_disabled(self):
        manager = _DisabledTracingManager()
        assert manager.inject_headers() == {}

    def test_shutdown_is_a_no_op_when_never_initialized(self):
        manager = _DisabledTracingManager()
        manager.shutdown()  # must not raise


class TestEnabledButOtelNotInstalled:
    """ACROPOLIS_OTEL_ENABLED=true with the `otel` extra genuinely absent must degrade to a
    logged no-op, never a crash. Simulated here via import-guard rather than an actual
    uninstalled-package venv (that's covered separately by
    tests/integration/test_no_otel_installed.py, a subprocess test against a real venv without
    the extra) — this unit test is the fast, in-process companion proving the SAME code path
    (the `except ImportError` in TracingManager.init) behaves correctly."""

    def test_init_degrades_to_noop_on_import_error(self, monkeypatch, caplog):
        import builtins

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "opentelemetry" or name.startswith("opentelemetry."):
                raise ImportError(f"simulated missing package: {name}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _blocking_import)

        manager = TracingManager(enabled=True)
        with caplog.at_level("WARNING"):
            manager.init()

        assert manager.active is False
        assert manager._tracer is None
        assert any("otel" in rec.message.lower() for rec in caplog.records)

        # And span()/extract_context/inject_headers must still be safe to call afterward.
        with manager.span("request") as span:
            span.set_attribute("k", "v")
        assert manager.extract_context("some-traceparent") is None
        assert manager.inject_headers() == {}


class TestEnabledWithOtelInstalled:
    """These require the `otel` extra to actually be installed (it is, in this dev environment
    — see pyproject.toml's `otel` optional-dependencies group and tests/integration/
    test_no_otel_installed.py for the proof that things work WITHOUT it too)."""

    def test_init_builds_active_tracer(self):
        pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        manager = TracingManager(enabled=True, sample_ratio=1.0)
        manager.init(exporter=exporter)
        try:
            assert manager.active is True
            with manager.span("request", attributes={"acropolis.server_slug": "srv"}) as span:
                span.set_attribute("http.status_code", 200)

            spans = exporter.get_finished_spans()
            assert len(spans) == 1
            assert spans[0].name == "request"
            assert spans[0].attributes["acropolis.server_slug"] == "srv"
            assert spans[0].attributes["http.status_code"] == 200
        finally:
            manager.shutdown()

    def test_span_records_exception_and_marks_error_status(self):
        pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        from opentelemetry.trace import StatusCode

        exporter = InMemorySpanExporter()
        manager = TracingManager(enabled=True)
        manager.init(exporter=exporter)
        try:
            with pytest.raises(ValueError):
                with manager.span("policy.evaluate"):
                    raise ValueError("simulated failure")

            spans = exporter.get_finished_spans()
            assert len(spans) == 1
            assert spans[0].status.status_code == StatusCode.ERROR
            # record_exception adds an event; OTel's own start_as_current_span may ALSO record
            # one on the way out (depending on set_status_on_exception's default) — the
            # meaningful assertion is "at least one exception event landed", not an exact count.
            assert len(spans[0].events) >= 1
            assert all(e.name == "exception" for e in spans[0].events)
        finally:
            manager.shutdown()

    def test_inject_and_extract_round_trip(self):
        pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        manager = TracingManager(enabled=True)
        manager.init(exporter=exporter)
        try:
            with manager.span("upstream.forward"):
                headers = manager.inject_headers()
            assert "traceparent" in headers
            # A traceparent this manager itself emitted must be extractable and usable as a
            # parent context for a NEW manager instance (simulating the upstream side).
            downstream = TracingManager(enabled=True)
            downstream.init(exporter=InMemorySpanExporter())
            try:
                ctx = downstream.extract_context(headers["traceparent"])
                assert ctx is not None
            finally:
                downstream.shutdown()
        finally:
            manager.shutdown()

    def test_set_attribute_skips_none_values(self):
        """Call sites pass Optional[str] fields (e.g. decision.rule can be None) straight
        through as attribute values — set_attribute must silently skip None rather than raise
        (the underlying OTel API rejects None attribute values)."""
        pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        manager = TracingManager(enabled=True)
        manager.init(exporter=exporter)
        try:
            with manager.span("policy.evaluate") as span:
                span.set_attribute("acropolis.rule", None)
                span.set_attribute("acropolis.decision", "ALLOWED")
            spans = exporter.get_finished_spans()
            assert "acropolis.rule" not in spans[0].attributes
            assert spans[0].attributes["acropolis.decision"] == "ALLOWED"
        finally:
            manager.shutdown()
