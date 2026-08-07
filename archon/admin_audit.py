"""Control-plane audit logging — records administrative actions on the gateway.

Every mutating route handler in archon/api.py calls record() with the before/after state
so the diff is captured. This is EXPLICIT, not middleware-based: middleware can't see
before/after state, and repo hooks fire N times during one config import.

Secret discipline: before/after only ever contain allowlisted fields. The allowlists below
enumerate what MAY be recorded, not what may NOT — a future secret can't leak by default.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from db.models import ServerPolicy
from db.repo import AdminEventRepo

# Allowlist of fields that may appear in before/after for server changes.
# upstream_auth_header is deliberately EXCLUDED — it's a live plaintext credential.
RECORDABLE_SERVER_FIELDS = frozenset({
    "slug", "name", "upstream_url", "enabled", "in_aggregate",
    "upstream_protocol", "health_status",
})

# Allowlist of settings keys that may appear in before/after for settings changes.
# webhook_secret, admin_password_hash, session_secret are deliberately EXCLUDED.
RECORDABLE_SETTINGS_KEYS = frozenset({
    "auth_mode", "aggregate_enabled", "default_ttl_ms", "audit_retention_days",
    "webhook_url", "webhook_enabled", "webhook_events",
})


def _policy_diff(current: ServerPolicy, incoming: ServerPolicy) -> list[str]:
    """Human-readable field-level deltas, lifted from config_io.py to avoid drift."""
    deltas: list[str] = []
    if current.mode != incoming.mode:
        deltas.append(f"mode: {current.mode} -> {incoming.mode}")
    if current.rate_limit != incoming.rate_limit:
        deltas.append(f"rate_limit: {current.rate_limit or 'none'} -> {incoming.rate_limit or 'none'}")
    if sorted(current.allowed) != sorted(incoming.allowed):
        deltas.append(f"allowed: {len(current.allowed)} -> {len(incoming.allowed)} tool(s)")
    if sorted(current.denied) != sorted(incoming.denied):
        deltas.append(f"denied: {len(current.denied)} -> {len(incoming.denied)} tool(s)")
    if current.param_rules != incoming.param_rules:
        deltas.append(
            f"param_rules: {len(current.param_rules)} -> {len(incoming.param_rules)} tool(s) with rules"
        )
    return deltas


def _serialize_policy(policy: ServerPolicy) -> dict[str, Any]:
    """Serialize a ServerPolicy to a dict for before/after JSON."""
    return {
        "mode": policy.mode,
        "rate_limit": policy.rate_limit,
        "allowed": sorted(policy.allowed),
        "denied": sorted(policy.denied),
        "param_rules": {
            tool: {param: rule.model_dump() for param, rule in rules.items()}
            for tool, rules in policy.param_rules.items()
        },
    }


def filter_server_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Return only the allowlisted fields from a server dict."""
    return {k: v for k, v in data.items() if k in RECORDABLE_SERVER_FIELDS}


def filter_settings_keys(data: dict[str, str]) -> dict[str, str]:
    """Return only the allowlisted keys from a settings dict."""
    return {k: v for k, v in data.items() if k in RECORDABLE_SETTINGS_KEYS}


async def record(
    repo: AdminEventRepo,
    *,
    action: str,
    summary: str,
    actor: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    before: Optional[dict[str, Any]] = None,
    after: Optional[dict[str, Any]] = None,
    client_ip: Optional[str] = None,
) -> int:
    """Write one admin event. Returns the new row id.

    before/after are serialized to JSON. The caller is responsible for ensuring they only
    contain allowlisted fields (use _filter_server_fields / _filter_settings_keys).
    """
    before_json = json.dumps(before, sort_keys=True) if before is not None else None
    after_json = json.dumps(after, sort_keys=True) if after is not None else None

    return await repo.insert(
        action=action,
        summary=summary,
        actor=actor,
        target_type=target_type,
        target_id=target_id,
        before=before_json,
        after=after_json,
        client_ip=client_ip,
    )


async def record_policy_change(
    repo: AdminEventRepo,
    *,
    server_slug: str,
    current: ServerPolicy,
    incoming: ServerPolicy,
    actor: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> int:
    """Record a policy update with a human-readable diff summary."""
    deltas = _policy_diff(current, incoming)
    summary = "; ".join(deltas) if deltas else "no change"

    return await record(
        repo,
        action="policy.update",
        summary=summary,
        actor=actor,
        target_type="server",
        target_id=server_slug,
        before={"policy": _serialize_policy(current)},
        after={"policy": _serialize_policy(incoming)},
        client_ip=client_ip,
    )


async def record_config_import(
    repo: AdminEventRepo,
    *,
    actions: list[str],  # list of "would create server 'x'", "updated policy on 'y'", etc.
    actor: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> int:
    """Record a config import as ONE event, not one per touched server.

    The actions list comes from ImportPlan.actions — the same objects used for the
    dry-run preview, so the audit trail matches exactly what the operator saw.
    """
    summary = f"import applied: {len(actions)} change(s)"
    if actions:
        summary += "; " + "; ".join(actions[:3])  # first 3 for legibility
        if len(actions) > 3:
            summary += f"; ... and {len(actions) - 3} more"

    return await record(
        repo,
        action="config.import",
        summary=summary,
        actor=actor,
        target_type="config",
        after={"changes": actions},
        client_ip=client_ip,
    )
