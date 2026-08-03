from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from db.models import ParamRule, ServerPolicy


@dataclass
class Decision:
    blocked: bool
    reason: Optional[str] = None
    rule: Optional[str] = None
    matched: Optional[str] = None
    args_summary: Optional[dict] = None


def summarize_args(arguments: dict) -> dict:
    """Truncate argument values for the audit log — avoid logging secrets verbatim."""
    summary = {}
    for k, v in arguments.items():
        s = str(v)
        summary[k] = (s[:120] + " [truncated]") if len(s) > 120 else s
    return summary


def _check_param(name: str, value: Any, rule: ParamRule) -> Optional[tuple[str, str]]:
    """
    Validate a single argument against its ParamRule.
    Returns (rule_name, detail) if a violation is found, else None.
    """
    if rule.denied:
        return ("denied_param", f"param '{name}' is not permitted")

    s = str(value)

    if rule.max_length is not None and len(s) > rule.max_length:
        return ("max_length", f"len={len(s)} exceeds max={rule.max_length}")

    for compiled in rule.compiled_patterns():
        if compiled.search(s):
            return ("block_pattern", compiled.pattern)

    if rule.max_value is not None:
        try:
            if float(value) > rule.max_value:
                return ("max_value", f"{value} > {rule.max_value}")
        except (TypeError, ValueError):
            pass

    if rule.min_value is not None:
        try:
            if float(value) < rule.min_value:
                return ("min_value", f"{value} < {rule.min_value}")
        except (TypeError, ValueError):
            pass

    return None


def evaluate(tool_name: str, arguments: dict, server_name: str, policy: ServerPolicy) -> Decision:
    """
    Run the rules engine for a tools/call request.
    Returns a Decision indicating whether to allow or block.

    Security invariant: this function is the only place a block/allow decision is made.
    Callers must pass the JSON-RPC body's tool_name/arguments, never trust routing headers alone.
    """
    args_summary = summarize_args(arguments)

    if policy.mode == "allowlist" and tool_name not in policy.allowed:
        return Decision(
            blocked=True,
            reason=f"'{tool_name}' is not in the allowlist for server '{server_name}'",
            rule="allowlist",
            args_summary=args_summary,
        )

    if policy.mode == "denylist" and tool_name in policy.denied:
        return Decision(
            blocked=True,
            reason=f"'{tool_name}' is explicitly denied on server '{server_name}'",
            rule="denylist",
            args_summary=args_summary,
        )

    # Param validation — runs for ALL modes (including passthrough), since a param rule
    # is an explicit opt-in constraint the operator wrote regardless of the tool-level mode.
    for param_name, rule in policy.param_rules.get(tool_name, {}).items():
        if param_name not in arguments:
            continue
        violation = _check_param(param_name, arguments[param_name], rule)
        if violation:
            rule_name, detail = violation
            return Decision(
                blocked=True,
                reason=f"param '{param_name}' failed rule '{rule_name}': {detail}",
                rule=rule_name,
                matched=detail,
                args_summary=args_summary,
            )

    return Decision(blocked=False, args_summary=args_summary)


def tool_is_visible(tool_name: str, policy: ServerPolicy) -> bool:
    """Whether a tool should appear in a filtered tools/list response."""
    if policy.mode == "allowlist":
        return tool_name in policy.allowed
    if policy.mode == "denylist":
        return tool_name not in policy.denied
    return True
