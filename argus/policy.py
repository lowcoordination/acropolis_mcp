from __future__ import annotations

import asyncio
import enum
import logging
import multiprocessing
import queue
import re
from concurrent.futures import ThreadPoolExecutor
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

# F2/F10 fix (review 2026-08-04): waiting on result_queue.get() blocks a thread for up to
# _REGEX_MATCH_TIMEOUT_SECONDS + 0.2s. asyncio's default executor (shared by every unrelated
# run_in_executor(None, ...) call in the process, sized min(32, cpu_count+4)) is NOT an
# acceptable place to put that wait: a burst of concurrent tools/call requests against servers
# with block_patterns rules could exhaust it on their own and stall unrelated work sharing the
# same pool. Give this one blocking wait its own small dedicated pool instead.
#
# F2: that pool is ALSO where the original fail-open bug lived. asyncio.wait_for's clock starts
# at SUBMISSION to the executor, not at the point the wait actually begins running — with only
# 16 workers, the 17th+ concurrent match sits queued in the executor's own backlog burning its
# deadline before it ever starts waiting, times out, and was (incorrectly) treated identically
# to "the regex genuinely took too long." Confirmed by the reviewer: 40 concurrent ReDoS
# requests against one server let 10/10 requests on an UNRELATED server bypass block_patterns
# entirely, logged as ALLOWED. Fixed by acquiring a semaphore BEFORE starting the child process
# at all, so the timeout clock only ever measures genuine match time, never queue-wait time —
# a request that can't get a slot yet blocks on the semaphore (bounded, but never silently
# treated as "did not match").
_MAX_CONCURRENT_REGEX_CHECKS = 16
_regex_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_REGEX_CHECKS)
_wait_executor = ThreadPoolExecutor(
    max_workers=_MAX_CONCURRENT_REGEX_CHECKS, thread_name_prefix="policy-regex-wait"
)
# §26 (review 2026-08-04): considered adding an explicit shutdown() for this executor, called
# from the app lifespan, to avoid a benign "Event loop is closed" warning from a worker thread
# finishing after atexit tears things down. Reverted: _wait_executor is a MODULE-level
# singleton, so any one app's shutdown would permanently poison it for every other app sharing
# the process — true of the test suite (many create_app() calls per pytest process) and not
# safely ruled out for any future multi-app-per-process use. The warning is cosmetic
# (interpreter-shutdown-only, no test or request ever failed because of it); a correctness
# regression to silence it is the wrong trade. Left as process-lifetime + atexit, as it always
# was, until this executor is made per-app-instance rather than global.


class MatchOutcome(enum.Enum):
    """F2 fix: a timed-out or otherwise-failed match is no longer silently folded into
    "did not match." Security invariant for a gateway: an UNDETERMINED result on an
    operator-authored block_pattern rule must be treated as a match (block), never as a pass —
    see _check_param, and docs/policy-cookbook.md for the operator-facing explanation."""

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    UNDETERMINED = "undetermined"


def _regex_worker(pattern, value: str, result_queue) -> None:
    result_queue.put(pattern.search(value) is not None)


def _finditer_spans_worker(pattern, value: str, result_queue) -> None:
    # Enterprise #10 (DLP): a SEPARATE bounded worker for callers (argus/dlp.py's custom
    # pattern span recovery) that need every match SPAN, not just a matched/not-matched bool.
    # `pattern.search(value)` (the existing _regex_worker above) proves a pattern terminates
    # promptly for its FIRST match, but re.finditer restarts matching from each match's end —
    # a pattern that resolves its first match quickly is not guaranteed to resolve its second,
    # third, etc. equally quickly (this is exactly the kind of position-dependent backtracking
    # blowup ReDoS patterns are built from). Reusing the identical forkserver/timeout/kill
    # machinery here (same _mp_context, same semaphore, same wall-clock budget via the caller)
    # closes that gap rather than trusting a second, unguarded finditer call once the FIRST
    # match alone has been proven fast.
    result_queue.put([(m.start(), m.end()) for m in pattern.finditer(value)])


async def _match_with_timeout(compiled, value: str) -> MatchOutcome:
    """Runs compiled.search(value) in a forked child process with a hard wall-clock timeout that
    starts only once the process is actually running (see _regex_semaphore above — this is what
    fixes F2). If the match doesn't finish in time, the child is forcibly terminated (SIGTERM,
    then SIGKILL if it doesn't die promptly) — this is the part a thread-based approach cannot
    do. Returns MatchOutcome.UNDETERMINED on timeout or infra failure; the caller (_check_param)
    decides what that means for the block/allow decision — this function no longer makes that
    call itself, which is what let F2's fail-open happen silently."""
    async with _regex_semaphore:
        result_queue = _mp_context.Queue()
        process = _mp_context.Process(target=_regex_worker, args=(compiled, value, result_queue))
        process.start()

        loop = asyncio.get_running_loop()
        try:
            matched = await loop.run_in_executor(
                _wait_executor, result_queue.get, True, _REGEX_MATCH_TIMEOUT_SECONDS
            )
            process.join(timeout=1.0)
            return MatchOutcome.MATCHED if matched else MatchOutcome.NOT_MATCHED
        except queue.Empty:
            # The expected timeout path: result_queue.get(True, timeout) raises queue.Empty
            # when the deadline passes with nothing queued — NOT asyncio.TimeoutError (this
            # was F10: the pre-fix except clause caught asyncio.TimeoutError specifically, so
            # queue.Empty always fell through to the generic handler below, and the tuned
            # actionable warning here was dead code — confirmed uncovered by any test).
            logger.warning(
                "block_pattern match exceeded %.1fs (pattern=%r) — terminating and treating as "
                "UNDETERMINED; this pattern is likely vulnerable to catastrophic backtracking "
                "and should be rewritten",
                _REGEX_MATCH_TIMEOUT_SECONDS, compiled.pattern,
            )
            return MatchOutcome.UNDETERMINED
        except Exception:
            # Not the expected timeout — an infra failure (forkserver unavailable, fd/process
            # limits, queue error). Logged distinctly (F10) so an operator doesn't chase a
            # nonexistent bad regex when the real cause is environmental.
            logger.exception(
                "block_pattern match for pattern=%r failed unexpectedly (not a timeout) — "
                "treating as UNDETERMINED",
                compiled.pattern,
            )
            return MatchOutcome.UNDETERMINED
        finally:
            process.terminate()
            process.join(timeout=1.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)
            result_queue.close()


async def _finditer_spans_with_timeout(compiled, value: str) -> Optional[list[tuple[int, int]]]:
    """Enterprise #10 (DLP) companion to _match_with_timeout, for callers that need every match
    SPAN (redaction needs positions, not just yes/no) rather than a single matched/not-matched
    outcome. Deliberately a SEPARATE function rather than extending _match_with_timeout's return
    type — that function is F2's hardened, narrowly-scoped primitive and this keeps its
    contract (and its test coverage) untouched. Mirrors its process-lifecycle handling exactly
    (same _mp_context, same semaphore, same timeout budget, same terminate/kill teardown) so the
    two stay behaviorally identical on the timeout/kill path; only the worker function and
    result shape differ. Returns None on timeout or infra failure — the caller must treat that
    as UNDETERMINED and fail closed, exactly as MatchOutcome.UNDETERMINED does for
    _match_with_timeout."""
    async with _regex_semaphore:
        result_queue = _mp_context.Queue()
        process = _mp_context.Process(target=_finditer_spans_worker, args=(compiled, value, result_queue))
        process.start()

        loop = asyncio.get_running_loop()
        try:
            spans = await loop.run_in_executor(
                _wait_executor, result_queue.get, True, _REGEX_MATCH_TIMEOUT_SECONDS
            )
            process.join(timeout=1.0)
            return spans
        except queue.Empty:
            logger.warning(
                "dlp custom pattern finditer exceeded %.1fs (pattern=%r) — terminating and "
                "treating as UNDETERMINED",
                _REGEX_MATCH_TIMEOUT_SECONDS, compiled.pattern,
            )
            return None
        except Exception:
            logger.exception(
                "dlp custom pattern finditer for pattern=%r failed unexpectedly (not a timeout) "
                "— treating as UNDETERMINED",
                compiled.pattern,
            )
            return None
        finally:
            process.terminate()
            process.join(timeout=1.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)
            result_queue.close()


@dataclass
class Decision:
    blocked: bool
    reason: Optional[str] = None
    rule: Optional[str] = None
    matched: Optional[str] = None
    args_summary: Optional[dict] = None
    # Enterprise #10 (DLP): set only when a DLP detector fired. dlp_detector/dlp_action/
    # dlp_match_count are safe to audit/log/send in a webhook — dlp_redacted_arguments (when
    # action == "redact") carries the REDACTED (placeholder-substituted) arguments dict, which
    # is safe to forward upstream but is deliberately kept off the audit row and webhook path;
    # only argus/pipeline.py reads it, to build the re-serialized forwarded body. See
    # docs/dlp.md's audit-safety invariant: the matched/redacted value must never appear in the
    # audit log or a webhook payload, only which detector fired and what action was taken.
    dlp_detector: Optional[str] = None
    dlp_action: Optional[str] = None
    dlp_match_count: int = 0
    dlp_redacted_arguments: Optional[dict] = None


# §26 fix (review 2026-08-04): summarize_args's docstring claimed it avoided logging secrets
# verbatim, but it only truncated by LENGTH — a short secret (an 8-character API key, a PIN)
# sailed straight into the audit log untouched. Redact by key name first; length-truncation
# alone was never sufficient for this purpose.
_SENSITIVE_ARG_KEY_RE = re.compile(
    r"(token|password|passwd|secret|key|authorization|credential|api[_-]?key)", re.IGNORECASE
)


def summarize_args(arguments: dict) -> dict:
    """Redact-then-truncate argument values for the audit log — avoid logging secrets verbatim."""
    summary = {}
    for k, v in arguments.items():
        if _SENSITIVE_ARG_KEY_RE.search(k):
            summary[k] = "[redacted]"
            continue
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
        outcome = await _match_with_timeout(compiled, s)
        if outcome is MatchOutcome.MATCHED:
            return ("block_pattern", compiled.pattern)
        if outcome is MatchOutcome.UNDETERMINED:
            # F2 fix: a timeout or infra failure on an operator-authored block_pattern rule is
            # treated as a match, not a pass. The old fail-open-on-timeout design meant a
            # request could disable enforcement just by generating enough concurrent load —
            # confirmed by the reviewer with a 40-concurrent-request probe that dropped block
            # rate from 10/10 to 0/10. Failing closed here means a genuinely pathological
            # pattern degrades to "blocks everything it's checked against" instead of "blocks
            # nothing under load" — visible and loud rather than a silent bypass. See
            # docs/policy-cookbook.md for the operator-facing explanation of this trade-off.
            return ("block_pattern_undetermined", compiled.pattern)

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

    # DLP scan (enterprise #10) — deliberately LAST, after allow/deny and param rules: a call
    # that's going to be blocked outright by an earlier check shouldn't pay for a DLP scan.
    # Deliberately arguments-only (not responses) — see docs/dlp.md for the benchmark-gated
    # scope decision. Every detector defaults to off (ServerPolicy.dlp_detectors defaults to
    # {}), so a server with no DLP config configured takes this branch's early-return on the
    # very first line of dlp_scan and is byte-identical to pre-DLP behavior.
    if policy.dlp_detectors or policy.dlp_custom_patterns:
        from argus.dlp import dlp_scan

        dlp_result = await dlp_scan(arguments, policy)
        if dlp_result.action in ("block", "redact"):
            # args_summary (audit-log-only, see summarize_args) is built from the ORIGINAL
            # arguments and only redacts by SENSITIVE KEY NAME — it has no idea a DLP detector
            # just found a secret sitting in an innocuously-named key like "message". Without
            # this, a DLP-driven block/redact would still write the raw matched value straight
            # into audit_events.args_summary, defeating the entire audit-safety invariant this
            # feature is built around. Re-summarize from the redacted arguments (falling back
            # to the placeholder-substituted whole value on block, where dlp_scan doesn't
            # bother building a full redacted copy — see argus/dlp.py's dlp_scan short-circuit).
            safe_arguments = dlp_result.redacted_arguments
            if safe_arguments is None:
                safe_arguments = {
                    k: (f"[REDACTED:{dlp_result.detector}]" if isinstance(v, str) else v)
                    for k, v in arguments.items()
                }
            args_summary = summarize_args(safe_arguments)
        if dlp_result.action == "block":
            return Decision(
                blocked=True,
                reason=f"DLP detector '{dlp_result.detector}' matched a blocked pattern",
                rule="dlp",
                args_summary=args_summary,
                dlp_detector=dlp_result.detector,
                dlp_action="block",
                dlp_match_count=dlp_result.match_count,
            )
        if dlp_result.action == "redact":
            return Decision(
                blocked=False,
                args_summary=args_summary,
                dlp_detector=dlp_result.detector,
                dlp_action="redact",
                dlp_match_count=dlp_result.match_count,
                dlp_redacted_arguments=dlp_result.redacted_arguments,
            )

    return Decision(blocked=False, args_summary=args_summary)


def tool_is_visible(tool_name: str, policy: ServerPolicy) -> bool:
    """Whether a tool should appear in a filtered tools/list response."""
    if policy.mode == "allowlist":
        return tool_name in policy.allowed
    if policy.mode == "denylist":
        return tool_name not in policy.denied
    return True
