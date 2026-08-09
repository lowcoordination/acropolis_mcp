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

from archon.secrets import is_reference
from db.models import ServerPolicy
from db.repo import AdminEventRepo

# Allowlist of fields that may appear in before/after for server changes.
# upstream_auth_header is deliberately EXCLUDED — it's a live plaintext credential (or, as of
# enterprise #5, potentially a non-secret reference — but this allowlist can't tell which
# without inspecting the value, and RECORDABLE_SERVER_FIELDS is used generically by
# filter_server_fields() on dicts that may or may not have already made that distinction. THE
# VALUE never goes through this allowlist either way. See record_secret_reference_change()
# below for the enterprise #5-specific event this module adds instead: it records that a
# reference changed and what it changed TO/FROM only as a boolean shape classification via
# is_reference(), never the string itself.
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
    # Enterprise #10 (DLP): a DLP config change is a security-lowering/relevant action in its
    # own right (turning a detector off, or from block to redact, weakens enforcement) and must
    # be visible in the control-plane audit trail same as any other policy field. Detector
    # names/actions and custom-pattern names/pattern TEXT are operator-authored configuration,
    # not secrets — safe to record in full, unlike the matched VALUES a detector finds at
    # runtime (which never appear here or anywhere in audit_events; see argus/dlp.py).
    if current.dlp_detectors != incoming.dlp_detectors:
        deltas.append(
            f"dlp_detectors: {len(current.dlp_detectors)} -> {len(incoming.dlp_detectors)} configured"
        )
    if current.dlp_custom_patterns != incoming.dlp_custom_patterns:
        deltas.append(
            f"dlp_custom_patterns: {len(current.dlp_custom_patterns)} -> "
            f"{len(incoming.dlp_custom_patterns)} configured"
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
        "dlp_detectors": dict(sorted(policy.dlp_detectors.items())),
        "dlp_custom_patterns": [p.model_dump() for p in policy.dlp_custom_patterns],
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


async def record_secret_reference_change(
    repo: AdminEventRepo,
    *,
    server_slug: str,
    before_value: Optional[str],
    after_value: Optional[str],
    actor: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> Optional[int]:
    """Records that server_slug's upstream_auth_header CHANGED — never the value, in any form,
    on either side of the change, in any tier (a literal, a vault:// reference, or an enc:v1:
    ciphertext are all withheld the same way here; ciphertext is not exempted just because it
    LOOKS unreadable — logging it gratuitously would still be logging derived secret material
    for no operational benefit).

    Per the plan: "a secret-reference change is a control-plane audit event (server slug + that
    the reference changed), but the actual secret value must never be audited or logged". The
    before/after payload here is deliberately just three booleans (was/is something configured,
    was/is it a reference vs. a literal) plus the slug — enough for an operator reviewing the
    audit trail to see WHAT KIND of change happened (e.g. "credential externalized to Vault")
    without any way to recover what the credential actually is or was.

    Returns None (and records nothing) if upstream_auth_header didn't actually change — callers
    (archon/api.py's create/update handlers) call this unconditionally; the no-op-if-unchanged
    check lives here so it can't be forgotten at a call site the way a manual `if` could be.
    """
    if before_value == after_value:
        return None

    def _shape(value: Optional[str]) -> dict[str, Any]:
        return {"configured": value is not None, "is_reference": is_reference(value)}

    before_shape = _shape(before_value)
    after_shape = _shape(after_value)

    if not before_shape["configured"] and after_shape["configured"]:
        summary = "credential configured" + (" (reference)" if after_shape["is_reference"] else "")
    elif before_shape["configured"] and not after_shape["configured"]:
        summary = "credential cleared"
    elif before_shape["is_reference"] != after_shape["is_reference"]:
        summary = (
            "credential externalized to a reference" if after_shape["is_reference"]
            else "credential replaced with a literal"
        )
    else:
        summary = "credential value changed"

    return await record(
        repo,
        action="server.secret_reference_change",
        summary=summary,
        actor=actor,
        target_type="server",
        target_id=server_slug,
        before={"upstream_auth_header": before_shape},
        after={"upstream_auth_header": after_shape},
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
