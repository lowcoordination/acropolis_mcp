"""OpenTelemetry tracing (enterprise #9) — manual spans at five instrumentation points, never
auto-instrumentation. See docs/observability.md for the full design writeup and
enterprise_roadmap_2_08_09_26/01-otel-tracing.md (vault) for the worked plan this implements.

Non-negotiables (see that plan; restated here because this module is where they're enforced):

1. **Off by default, true no-op when off.** `ACROPOLIS_OTEL_ENABLED` unset/false means this
   module never imports `opentelemetry`, never builds a TracerProvider, and `span()` degrades to
   a bare no-op context manager. Behaviour and dependencies are byte-identical to pre-feature
   Acropolis. The OTel packages live in the `otel` optional extra (see pyproject.toml) —
   `init()` import-guards them and logs a warning + stays disabled if they aren't installed,
   rather than crashing startup.
2. **Manual spans only.** No FastAPI/httpx auto-instrumentation — those trace every request
   indiscriminately, including health-poll and `/metrics` scrape traffic, burying the signal.
   The only spans this codebase creates are the ones pipeline.py explicitly opens via `span()`
   at: request (root), policy.evaluate, dlp.scan, secrets.resolve, bridge.handshake,
   upstream.forward. Nothing else is traced.
3. **Attribute secrecy.** `span()` accepts a plain dict of attributes — callers are responsible
   for only ever passing the allowed set (server slug, tool name, decision, rule name,
   dlp_detector, dlp_action, bridged flag, HTTP status code). This module does not attempt to
   scrub attribute values; the discipline is enforced at each call site in pipeline.py, exactly
   like `args_summary`'s redaction is enforced by the callers of `AuditLogger.log`, not by
   AuditLogger itself. The canary test (tests/integration/test_otel_secrecy.py) is the actual proof.
4. **Parent-based sampling**, ratio from `ACROPOLIS_OTEL_SAMPLE_RATIO` (default 1.0). A client
   that already sampled its own trace out (a `traceparent` with the sampled flag clear) is never
   force-sampled back in here — `ParentBased(TraceIdRatioBased(ratio))` is exactly this policy:
   respects an existing decision, applies the ratio only when there is no parent context.
5. **OTLP/HTTP export via the STANDARD OTel env vars** (`OTEL_EXPORTER_OTLP_ENDPOINT`,
   `OTEL_EXPORTER_OTLP_HEADERS`, etc.) — no Acropolis-specific endpoint config invented. The only
   Acropolis-specific env var is the `ACROPOLIS_OTEL_ENABLED` gate itself.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

logger = logging.getLogger("argus.tracing")

ENABLED_ENV_VAR = "ACROPOLIS_OTEL_ENABLED"
SAMPLE_RATIO_ENV_VAR = "ACROPOLIS_OTEL_SAMPLE_RATIO"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def otel_enabled_by_env() -> bool:
    """Reads the gate directly from the environment. A plain function rather than a
    Settings field (like ACROPOLIS_SECRET_KEY in archon/secrets/encrypted.py) — deliberately,
    so tracing configuration follows the same "standard OTel env vars, one Acropolis gate" story
    end to end, rather than round-tripping through pydantic-settings for half of it."""
    return os.environ.get(ENABLED_ENV_VAR, "").strip().lower() in _TRUE_VALUES


class _NoOpSpan:
    """Returned by span() when tracing is disabled or unavailable. Every method is a no-op so
    call sites never need an `if tracing_enabled:` branch — see pipeline.py, which calls
    `span.set_attribute(...)` / `span.record_exception(...)` unconditionally."""

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def record_exception(self, exc: BaseException) -> None:
        return None

    def set_status_error(self, description: str = "") -> None:
        return None


_NOOP_SPAN = _NoOpSpan()


class _RealSpan:
    """Thin wrapper around an OTel span, translating this module's small attribute-only
    interface so pipeline.py never imports `opentelemetry` directly. Keeping the wrapper minimal
    (three methods) is deliberate — it's the entire surface a call site is allowed to use, which
    makes "did anyone reach past the allowlist and set an arbitrary attribute" a one-file grep."""

    __slots__ = ("_otel_span",)

    def __init__(self, otel_span: Any):
        self._otel_span = otel_span

    def set_attribute(self, key: str, value: Any) -> None:
        if value is not None:
            self._otel_span.set_attribute(key, value)

    def record_exception(self, exc: BaseException) -> None:
        self._otel_span.record_exception(exc)

    def set_status_error(self, description: str = "") -> None:
        from opentelemetry.trace import Status, StatusCode

        self._otel_span.set_status(Status(StatusCode.ERROR, description))


class TracingManager:
    """Owns the OTel SDK lifecycle (TracerProvider + OTLP exporter) when tracing is enabled, or
    is a complete no-op when it isn't. One instance lives on app.state, built once at startup —
    same shape as AuditLogger / WebhookDispatcher's start()/stop() lifecycle in app.py."""

    def __init__(self, enabled: bool, sample_ratio: float = 1.0):
        self._requested_enabled = enabled
        self._sample_ratio = sample_ratio
        self._tracer: Any = None
        self._provider: Any = None
        self.active = False  # True only once init() has actually built a working SDK tracer.

    @property
    def enabled(self) -> bool:
        """Whether ACROPOLIS_OTEL_ENABLED was true at construction — distinct from `active`,
        which additionally requires the `otel` extra to have actually been importable. Public
        (unlike the underscored constructor args) because archon/api.py's tracing/status
        endpoint reports both to the Settings page."""
        return self._requested_enabled

    @property
    def sample_ratio(self) -> float:
        return self._sample_ratio

    def init(self, exporter: Any = None) -> None:
        """`exporter`, if given, is used in place of the standard-env-var-configured
        OTLPSpanExporter — this is purely a test seam (see
        tests/integration/test_otel_span_shape.py and test_otel_secrecy.py, which pass an
        `InMemorySpanExporter` so assertions can inspect exported spans directly instead of
        standing up a real collector). app.py's real call site never passes this; production
        always gets the standard OTLP/HTTP exporter described in module decision #6."""
        if not self._requested_enabled:
            return
        try:
            from opentelemetry.sdk.resources import SERVICE_NAME, Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
            from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

            if exporter is None:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
        except ImportError:
            # Enterprise #9 non-negotiable #1: ACROPOLIS_OTEL_ENABLED=true with the `otel`
            # extra not installed must degrade to no-op, not crash startup — an operator
            # flipping the gate on a base install shouldn't take the whole gateway down.
            logger.warning(
                "%s=true but the 'otel' optional dependency group is not installed "
                "(pip install acropolis[otel]) — tracing stays disabled.",
                ENABLED_ENV_VAR,
            )
            return

        resource = Resource.create({SERVICE_NAME: "acropolis-gateway"})
        sampler = ParentBased(TraceIdRatioBased(self._sample_ratio))
        provider = TracerProvider(resource=resource, sampler=sampler)
        if exporter is None:
            # OTLPSpanExporter with no explicit endpoint reads the standard
            # OTEL_EXPORTER_OTLP_ENDPOINT / OTEL_EXPORTER_OTLP_TRACES_ENDPOINT /
            # OTEL_EXPORTER_OTLP_HEADERS env vars itself — this is the whole point of design
            # decision #6 (standard OTel env vars, no Acropolis-specific endpoint config).
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        else:
            # Test seam: SimpleSpanProcessor exports synchronously (no background batch thread
            # delay), so a test can assert on `exporter.get_finished_spans()` immediately after
            # the traced call returns, with no sleep/poll needed.
            provider.add_span_processor(SimpleSpanProcessor(exporter))
        # Deliberately NOT calling trace.set_tracer_provider(provider) — that's a process-wide
        # global the OTel API refuses to override once set (logs "Overriding of current
        # TracerProvider is not allowed" and silently keeps the first one), which would make a
        # second TracingManager in the same process (e.g. two tests in the same pytest run, or
        # in principle two Acropolis instances in one process) silently share the FIRST
        # instance's provider/exporter instead of getting its own. Getting the tracer directly
        # from THIS provider instance, never through the global registry, keeps every
        # TracingManager fully self-contained and independently testable.
        self._provider = provider
        self._tracer = provider.get_tracer("acropolis.gateway")
        self.active = True
        logger.info("OpenTelemetry tracing enabled (sample_ratio=%s)", self._sample_ratio)

    def shutdown(self) -> None:
        if self._provider is not None:
            self._provider.shutdown()

    @contextmanager
    def span(
        self, name: str, attributes: Optional[dict[str, Any]] = None,
        parent_context: Any = None,
    ) -> Iterator[Any]:
        """Open a span named `name` (dotted, e.g. "policy.evaluate") as a child of the current
        OTel context, or of `parent_context` if given (used for the root request span, which
        parents under an inbound `traceparent` rather than whatever ambient context exists).

        Yields a `_NoOpSpan`/`_RealSpan` — never the raw OTel span — so callers only ever see
        the three-method allowlisted interface. Always yields something usable even when
        tracing never initialized (self.active is False): a plain `with manager.span(...):` at
        every pipeline.py call site works identically whether tracing is on or off.
        """
        if not self.active or self._tracer is None:
            yield _NOOP_SPAN
            return

        cm = (
            self._tracer.start_as_current_span(name, context=parent_context)
            if parent_context is not None
            else self._tracer.start_as_current_span(name)
        )
        with cm as otel_span:
            wrapped = _RealSpan(otel_span)
            if attributes:
                for k, v in attributes.items():
                    wrapped.set_attribute(k, v)
            try:
                yield wrapped
            except Exception as exc:
                wrapped.record_exception(exc)
                wrapped.set_status_error(str(exc))
                raise

    def extract_context(self, traceparent: Optional[str], tracestate: Optional[str] = None) -> Any:
        """Parse an inbound W3C traceparent/tracestate into an OTel context the root span should
        parent under. Returns None when tracing is inactive or no traceparent was sent — the
        root span then simply starts a new trace, which is correct (no parent to chain to)."""
        if not self.active or not traceparent:
            return None
        from opentelemetry.propagate import extract

        carrier = {"traceparent": traceparent}
        if tracestate:
            carrier["tracestate"] = tracestate
        return extract(carrier)

    def inject_headers(self) -> dict[str, str]:
        """Returns {"traceparent": ..., "tracestate": ...} (tracestate only if non-empty) for
        the CURRENT active span context — call this from inside the upstream.forward span so the
        injected traceparent correctly parent-chains under it. Returns {} when tracing is
        inactive or there is no current recording span (e.g. sampled-out), so call sites can
        unconditionally merge the result into outbound headers with no branching."""
        if not self.active:
            return {}
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)
        return carrier


class _DisabledTracingManager(TracingManager):
    """Convenience singleton for the (extremely common) disabled-by-default case, so app.py
    doesn't need to special-case "no TracingManager was wired" vs. "one was wired but disabled"
    at every call site — Pipeline always has a TracingManager, it's just inert by default."""

    def __init__(self) -> None:
        super().__init__(enabled=False)


def build_tracing_manager() -> TracingManager:
    """Reads ACROPOLIS_OTEL_ENABLED / ACROPOLIS_OTEL_SAMPLE_RATIO from the environment and
    returns a ready-to-init() TracingManager. Mirrors archon.secrets.build_secret_provider's
    shape: one function, called once at startup in app.py, that turns env config into the
    runtime object every other component is handed."""
    enabled = otel_enabled_by_env()
    ratio_raw = os.environ.get(SAMPLE_RATIO_ENV_VAR, "1.0")
    try:
        ratio = float(ratio_raw)
    except ValueError:
        logger.warning("%s=%r is not a valid float; defaulting to 1.0", SAMPLE_RATIO_ENV_VAR, ratio_raw)
        ratio = 1.0
    ratio = max(0.0, min(1.0, ratio))
    return TracingManager(enabled=enabled, sample_ratio=ratio)
