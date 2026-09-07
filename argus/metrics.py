from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Response

from argus.origin import ORIGIN_CLASSES
from db.repo import AuditRepo, ServerRepo
from stoa.gitops import ConfigSource

logger = logging.getLogger("argus.metrics")


def _escape_label(value: str) -> str:
    """Escape a label VALUE per the Prometheus text exposition format.

    Backslash, double-quote AND newline all require escaping — an unescaped newline terminates
    the metric line early and corrupts every series after it in the same scrape, so a single bad
    label value breaks the whole endpoint rather than one series. The newline case was missing
    until #123; no current label can contain one (see the origin CLASS discipline below), but a
    sanitizer that only half-works is worse than none, because the next label added will assume
    it is safe."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def build_metrics_router(server_repo: ServerRepo, audit_repo: AuditRepo, config_source: Optional["ConfigSource"] = None) -> APIRouter:
    """Prometheus text-exposition endpoint (review finding F25, 2026-08-04). Deliberately NOT
    behind require_admin — same posture as /api/v1/health, since a scraper is infra tooling
    polling every 15-30s, not a human. If that's too permissive for a given deployment, put a
    reverse-proxy rule in front of this one path rather than adding gateway-side auth that a
    scrape target wouldn't normally need.

    Scope is deliberately narrow: request/decision counts (already tracked by AuditLogger) and
    per-server health status (already tracked by HealthPoller). Per-upstream call latency is NOT
    included — no latency sample is currently recorded anywhere in the request path, and bolting
    on a histogram here would mean inventing that instrumentation rather than exposing it; tracked
    as a follow-up, not silently declared done."""
    router = APIRouter()

    @router.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        # Issue #109: the four count_since calls are the only audit-store reads in this handler —
        # the server gauges below are config-store reads. Once the audit log can live on a
        # separate database (#108), the two stores can fail independently, and an audit outage
        # must NOT 500 the whole scrape: Prometheus polls this every 15-30s to answer "is the
        # gateway up, are my upstreams healthy", and those gauges come from ServerRepo.
        # On failure we OMIT the acropolis_audit_events_total family rather than reporting 0 —
        # a zero is indistinguishable from "no traffic in 24h" and silently corrupts rate() and
        # alert thresholds; a missing series is visibly missing. acropolis_audit_store_up makes
        # the outage directly alertable instead of inferred from a gap.
        audit_ok = True
        by_origin: dict[str, dict[str, int]] = {}
        try:
            # ONE grouped read, not four-per-origin-class point queries: this handler caches
            # nothing and runs on every 15-30s scrape, so a cross-product would multiply the
            # audit-store load by the number of origin classes. It also subsumes the separate
            # "total" query the OTHER series used to need.
            by_origin = await audit_repo.count_by_origin_class_since(since)
        except Exception:  # noqa: BLE001 — a monitoring endpoint must never 500 on a store outage
            audit_ok = False
            logger.warning(
                "audit store unavailable; /metrics emitting config-derived gauges only", exc_info=True
            )

        servers = await server_repo.list()

        lines = []
        if audit_ok:
            # The `origin` label carries the CLASS only — "gateway" (real traffic), "local" (a
            # local execution evaluation) or "test" (Try-it). Never the full origin value: its
            # detail half carries an API key name and a caller-asserted hostname, which as a
            # Prometheus label is unbounded cardinality that a fleet of ephemeral hosts — or an
            # attacker — could use to blow up the scrape target's series count. The full value
            # stays queryable in the audit log and the Audit UI, where it costs nothing.
            #
            # Every class present in the window is emitted, so a class added later appears
            # without a change here; the three known ones are emitted even at zero so a
            # breakdown never silently loses a series when a class happens to be idle.
            lines += [
                "# HELP acropolis_audit_events_total Audit events recorded in the last 24h, by decision and origin class.",
                "# TYPE acropolis_audit_events_total counter",
            ]
            for origin_class in sorted(set(ORIGIN_CLASSES) | set(by_origin)):
                counts = by_origin.get(origin_class, {})
                known = {d: counts.get(d, 0) for d in ("ALLOWED", "BLOCKED", "ERROR")}
                other = max(sum(counts.values()) - sum(known.values()), 0)
                label = _escape_label(origin_class)
                for decision, value in (*known.items(), ("OTHER", other)):
                    lines.append(
                        f'acropolis_audit_events_total'
                        f'{{decision="{decision}",origin="{label}"}} {value}'
                    )
            lines.append("")
        lines += [
            "# HELP acropolis_audit_store_up Whether the audit store was readable for this scrape (1 = up, 0 = down).",
            "# TYPE acropolis_audit_store_up gauge",
            f"acropolis_audit_store_up {1 if audit_ok else 0}",
            "",
            "# HELP acropolis_registered_servers Registered upstream MCP servers, by health status.",
            "# TYPE acropolis_registered_servers gauge",
        ]
        for status in ("healthy", "unhealthy", "unknown"):
            lines.append(f'acropolis_registered_servers{{health_status="{status}"}} '
                         f'{sum(1 for s in servers if s.health_status == status)}')

        lines.append("")
        lines.append("# HELP acropolis_server_health Per-server health (1 = healthy, 0 = not healthy).")
        lines.append("# TYPE acropolis_server_health gauge")
        for s in servers:
            lines.append(
                f'acropolis_server_health{{slug="{_escape_label(s.slug)}"}} '
                f'{1 if s.health_status == "healthy" else 0}'
            )

        # GitOps drift gauge (Enterprise #7)
        if config_source is not None:
            state = config_source.state
            drift_value = {"in_sync": 0, "drifted": 1, "unknown": 2, "error": 3}.get(state.status, 2)
            lines.append("")
            lines.append("# HELP acropolis_config_drift Config drift state (0=in_sync, 1=drifted, 2=unknown, 3=error).")
            lines.append("# TYPE acropolis_config_drift gauge")
            lines.append(f'acropolis_config_drift {drift_value}')
            if state.last_check is not None:
                lines.append("")
                lines.append("# HELP acropolis_config_last_check_timestamp Unix timestamp of last drift check.")
                lines.append("# TYPE acropolis_config_last_check_timestamp gauge")
                lines.append(f'acropolis_config_last_check_timestamp {state.last_check}')

        body = "\n".join(lines) + "\n"
        return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

    return router
