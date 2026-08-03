from __future__ import annotations

import asyncio
import logging
import multiprocessing
from dataclasses import dataclass
from typing import Any, Optional

from db.models import ParamRule, ServerPolicy

logger = logging.getLogger("argus.policy")

# block_patterns are operator-supplied and editable through the web UI (see db/models.py's
# compile-on-write validation, which caps pattern length but that alone does NOT prevent
# catastrophic backtracking — confirmed directly: "(a+)+$" against 31 chars of crafted input
# hangs Python's `re` for many seconds, comfortably under the 200-char cap).
#
# Policy evaluation is on the critical path of every tools/call request. A naive fix — run the
# match in a thread with an asyncio timeout — does NOT work: Python's `re` engine does not
# release the GIL while matching, so a hung regex in a worker THREAD still starves the event
# loop (and every other coroutine, including the timeout's own callback) for as long as the
# match runs. Confirmed by direct testing before choosing this design; a `time.sleep`-based
# thread times out correctly, a regex-based one does not.
#
# The fix that actually works: run the match in a separate PROCESS and forcibly terminate it
# if it doesn't finish in time. A process can be killed regardless of what it's doing
# internally; a thread cannot.
#
# Context choice: "forkserver", not "fork". Argus is always multi-threaded by the time this
# runs (asyncio + any library-internal threads), and Python's own multiprocessing docs warn
# that fork()ing a multi-threaded process can deadlock the child if another thread held a lock
# (malloc, logging, etc.) at the moment of the fork — confirmed by seeing exactly this warning
# under "fork" during testing. forkserver avoids the hazard: it starts one clean, single-
# threaded helper process early, and forks each worker from THAT — never from Argus's live,
# multi-threaded process. ~22ms overhead per call (vs. ~3ms for fork, ~85ms for spawn which
# re-imports Python each time) — an acceptable cost for correctness on a security-critical path.
_REGEX_MATCH_TIMEOUT_SECONDS = 0.5
_mp_context = multiprocessing.get_context("forkserver")


def _regex_worker(pattern, value: str, result_queue) -> None:
    result_queue.put(pattern.search(value) is not None)


async def _match_with_timeout(compiled, value: str) -> bool:
    """Runs compiled.search(value) in a forked child process with a hard wall-clock timeout.
    If the match doesn't finish in time, the child is forcibly terminated (SIGTERM, then
    SIGKILL if it doesn't die promptly) — this is the part a thread-based approach cannot do.
    Treats a timeout as "no match" rather than "blocked": failing open on a pathological
    pattern is safer than a policy bug turning what should be the ALLOW path into a hang."""
    result_queue = _mp_context.Queue()
    process = _mp_context.Process(target=_regex_worker, args=(compiled, value, result_queue))
    process.start()

    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, result_queue.get, True, _REGEX_MATCH_TIMEOUT_SECONDS),
            timeout=_REGEX_MATCH_TIMEOUT_SECONDS + 0.2,
        )
        process.join(timeout=1.0)
        return result
    except Exception:
        logger.warning(
            "block_pattern match exceeded %.1fs (pattern=%r) — terminating and treating as "
            "no-match; this pattern is likely vulnerable to catastrophic backtracking and "
            "should be rewritten",
            _REGEX_MATCH_TIMEOUT_SECONDS, compiled.pattern,
        )
        process.terminate()
        process.join(timeout=1.0)
        if process.is_alive():
            process.kill()
            process.join(timeout=1.0)
        return False
    finally:
        result_queue.close()


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


async def _check_param(name: str, value: Any, rule: ParamRule) -> Optional[tuple[str, str]]:
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
        if await _match_with_timeout(compiled, s):
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


async def evaluate(tool_name: str, arguments: dict, server_name: str, policy: ServerPolicy) -> Decision:
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
        violation = await _check_param(param_name, arguments[param_name], rule)
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
