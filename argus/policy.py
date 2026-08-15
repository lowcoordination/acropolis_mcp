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

from archon.settings import Settings
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
# R5 (issue #32, 2026-08-10): measured on the devbox (Python 3.14.6) at ~109ms per match p50 —
# ~5x the 22ms figure above, which came from the original author's environment. The number is
# machine/Python-version dependent; treat the magnitude, not the constant, as the claim. Full
# measurement (single-match cost, concurrency ceiling ~126 matches/s at the 16-way semaphore
# cap, adversarial 0.5s-timeout tail) and the go/no-go verdict on an re2 rewrite are recorded
# in tests/bench/results/r5-redos-2026-08-10.md.
#
# Issue #106 (2026-08-15): R5 measured that ~109ms as the cost of the *whole* round trip
# (forkserver fork + child bootstrap + IPC + the actual pattern.search()) without separating
# how much of it is match time versus process orchestration. On a slower or more loaded host
# than the one R5 measured, orchestration alone can consume 70-96% of _REGEX_MATCH_TIMEOUT_
# SECONDS, so a completely benign, non-backtracking pattern can spuriously time out — reported
# and reproduced independently (see the readiness-Event fix below and _WORKER_READY_TIMEOUT_
# SECONDS). The 0.5s budget is intended to measure ONLY pattern.search(); it must not be
# spent on fork/bootstrap/IPC, which is what the readiness handshake below exists to guarantee.
#
# Sourced from Settings (not a bare module constant) so an operator on slower hardware can
# raise it via ACROPOLIS_REGEX_MATCH_TIMEOUT_SECONDS / ACROPOLIS_WORKER_READY_TIMEOUT_SECONDS
# without patching this module. Read ONCE at import time, same as _MAX_CONCURRENT_REGEX_CHECKS
# below already sizes the semaphore/pool at import — this module has no per-request access to a
# request-scoped Settings instance (policy.evaluate is a free function called deep in
# argus/pipeline.py with no settings parameter), so a fresh Settings() here, read at import,
# is the smallest change consistent with how this module already treats its budgets as
# load-time constants rather than something threaded through every call.
_settings = Settings()
_REGEX_MATCH_TIMEOUT_SECONDS = _settings.regex_match_timeout_seconds

# A SEPARATE, more generous budget for the worker to become ready (forked, bootstrapped, and
# about to call pattern.search()). This is an infrastructure budget, not a regex budget — it
# should be sized for "is the forkserver itself alive and able to fork", never tuned as if it
# were a ReDoS threshold. Deliberately far larger than _REGEX_MATCH_TIMEOUT_SECONDS: a cold
# forkserver (first call after process start) has been measured at ~5x the warm per-call cost,
# and this budget must comfortably cover that plus headroom for a loaded host, without itself
# becoming a new source of false UNDETERMINED.
_WORKER_READY_TIMEOUT_SECONDS = _settings.worker_ready_timeout_seconds
_mp_context = multiprocessing.get_context("forkserver")

# _wait_for_worker (a single blocking call combining the readiness wait and the result wait,
# see its docstring) occupies a thread for up to _WORKER_READY_TIMEOUT_SECONDS +
# _REGEX_MATCH_TIMEOUT_SECONDS, so it gets its OWN small pool, not asyncio's default executor
# (shared by every unrelated run_in_executor(None, ...) call in the process, sized
# min(32, cpu_count+4)): a burst of concurrent tools/call requests against servers with
# block_patterns rules could otherwise exhaust the shared pool on their own and stall unrelated
# work on it.
#
# The semaphore is acquired BEFORE starting the child process, so neither timeout clock (ready
# or match) measures queue-wait time. asyncio.wait_for's clock starts at SUBMISSION to the
# executor: with only 16 workers, the 17th+ concurrent match would sit queued in the executor's
# own backlog burning its deadline before the match ever starts, time out, and be treated
# identically to "the regex genuinely took too long" — a fail-open bypass under load. A request
# that can't get a slot must block on the semaphore (bounded), never silently count as "did not
# match".
_MAX_CONCURRENT_REGEX_CHECKS = 16
_regex_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_REGEX_CHECKS)
_wait_executor = ThreadPoolExecutor(
    max_workers=_MAX_CONCURRENT_REGEX_CHECKS, thread_name_prefix="policy-regex-wait"
)
# Deliberately no shutdown() for _wait_executor: it is a MODULE-level singleton, so any one
# app's shutdown would permanently poison it for every other app sharing the process — true of
# the test suite (many create_app() calls per pytest process) and not safely ruled out for any
# future multi-app-per-process use. A benign "Event loop is closed" warning from a worker
# thread finishing after atexit tears things down is cosmetic (interpreter-shutdown-only); a
# correctness regression to silence it is the wrong trade. Lives for the process, as atexit
# handles it.


class MatchOutcome(enum.Enum):
    """A timed-out or otherwise-failed match is NOT folded into "did not match".

    Security invariant for a gateway: an UNDETERMINED result on an operator-authored
    block_pattern rule must be treated as a match (block), never as a pass — see _check_param,
    and docs/policy-cookbook.md for the operator-facing explanation."""

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    UNDETERMINED = "undetermined"


def _regex_worker(pattern, value: str, result_queue, ready_event) -> None:
    # Issue #106: signal readiness with a multiprocessing.Event, NOT by put()ing a sentinel on
    # result_queue. mp.Queue.put() is ASYNCHRONOUS — it hands the object to a background
    # feeder thread in the child, which only flushes it to the pipe on its own schedule. A
    # child that put()s a sentinel and then immediately enters a GIL-hogging pattern.search()
    # can starve that very feeder thread for the entire match, so the sentinel never arrives —
    # confirmed directly: a genuine catastrophic-backtracking pattern was misreported as
    # "worker never became ready" under that design, exactly backwards. Event.set() is
    # synchronous and OS-level (semaphore-backed), so it is visible to the parent immediately,
    # independent of whether the child's GIL is later held by a hung regex match.
    ready_event.set()
    result_queue.put(pattern.search(value) is not None)


def _finditer_spans_worker(pattern, value: str, result_queue, ready_event) -> None:
    # DLP: a SEPARATE bounded worker for callers (argus/dlp.py's custom pattern span recovery)
    # that need every match SPAN, not just a matched/not-matched bool. `pattern.search(value)`
    # (the existing _regex_worker above) proves a pattern terminates promptly for its FIRST
    # match, but re.finditer restarts matching from each match's end — a pattern that resolves
    # its first match quickly is not guaranteed to resolve its second, third, etc. equally
    # quickly (position-dependent backtracking blowup is exactly what ReDoS patterns are built
    # from). Reusing the identical forkserver/timeout/kill machinery (same _mp_context, same
    # semaphore, same wall-clock budget via the caller) closes that gap rather than trusting a
    # second, unguarded finditer call once the FIRST match alone has been proven fast.
    ready_event.set()
    result_queue.put([(m.start(), m.end()) for m in pattern.finditer(value)])


def _wait_for_worker(
    ready_event, result_queue, ready_timeout: float, match_timeout: float
):
    """Runs in _wait_executor (a worker THREAD, never the event loop): blocks on the readiness
    handshake, then on the result — both are blocking calls with no asyncio equivalent.

    Issue #106: this is the actual fix, split into two SEPARATE waits with two SEPARATE
    budgets, so the 0.5s match deadline can no longer be spent on fork/bootstrap/IPC:

      1. ready_event.wait(ready_timeout) — an INFRASTRUCTURE budget. Covers forkserver fork +
         child interpreter bootstrap + import + the Event.set() IPC round-trip. None of that is
         "the pattern is slow" — it is "can this host start a worker process at all right now".
         Deliberately generous (default 5s / _WORKER_READY_TIMEOUT_SECONDS) and covers the
         measured ~5x cold-start penalty (forkserver helper not yet spawned) with headroom.
      2. result_queue.get(True, match_timeout) — the REGEX budget. Starts only once the worker
         has confirmed (via the Event, not a queue put — see _regex_worker) that it is past
         bootstrap and about to call pattern.search()/finditer(). Whatever this measures is
         match time, full stop — no spawn overhead can leak into it via either path.

    Raises TimeoutError (not ready in time — infra) or queue.Empty (ready but match exceeded
    its budget — pattern) so the caller can attribute the UNDETERMINED to the right cause and
    log something an operator can actually act on."""
    if not ready_event.wait(ready_timeout):
        raise TimeoutError("worker did not become ready in time")
    return result_queue.get(True, match_timeout)


async def _run_worker_with_timeout(worker_fn, compiled, value: str, log_label: str):
    """Shared process-lifecycle machinery for _match_with_timeout and
    _finditer_spans_with_timeout: spawn a forkserver child running `worker_fn`, wait for it via
    the readiness-then-result handshake in _wait_for_worker, and unconditionally terminate/kill
    it afterward. Deliberately factored out (issue #106) so the two call sites cannot drift
    out of sync on the readiness/timeout/kill semantics the way two independently-maintained
    copies could — only the worker function, the result shape, and each caller's log wording
    differ, both handled by the two thin wrappers below.

    Returns (outcome, log_reason) where outcome is the raw value put by worker_fn (a bool for
    _regex_worker, a list of spans for _finditer_spans_worker) on success, or None on any
    failure; log_reason is one of "match_timeout" (ready, but the match itself exceeded its
    budget — likely a pathological pattern), "not_ready" (the worker never confirmed it was
    running within its infra budget — a host/forkserver problem, NOT a pattern problem), or
    "error" (an unexpected exception — forkserver unavailable, fd/process limits, queue error).
    log_label distinguishes the caller (e.g. "block_pattern match" vs "dlp custom pattern
    finditer") in the log messages without duplicating the three message bodies at each site."""
    async with _regex_semaphore:
        result_queue = _mp_context.Queue()
        ready_event = _mp_context.Event()
        process = _mp_context.Process(
            target=worker_fn, args=(compiled, value, result_queue, ready_event)
        )
        process.start()

        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                _wait_executor,
                _wait_for_worker,
                ready_event,
                result_queue,
                _WORKER_READY_TIMEOUT_SECONDS,
                _REGEX_MATCH_TIMEOUT_SECONDS,
            )
            process.join(timeout=1.0)
            return result, None
        except queue.Empty:
            # The worker confirmed it was running (Event set) but did not produce a result
            # within _REGEX_MATCH_TIMEOUT_SECONDS — the match itself is the slow part.
            logger.warning(
                "%s exceeded %.1fs (pattern=%r) — terminating and treating as UNDETERMINED; "
                "this pattern is likely vulnerable to catastrophic backtracking and should be "
                "rewritten",
                log_label, _REGEX_MATCH_TIMEOUT_SECONDS, compiled.pattern,
            )
            return None, "match_timeout"
        except TimeoutError:
            # The worker never confirmed it was running within _WORKER_READY_TIMEOUT_SECONDS —
            # an infra problem (forkserver overloaded/unavailable, host too slow to fork+
            # bootstrap in time), not a property of the pattern. Distinct message on purpose:
            # this is the case issue #106 reports — a benign pattern spuriously blocked because
            # THIS host, not the pattern, couldn't finish in time. Rewriting the pattern would
            # not help; raising ACROPOLIS_WORKER_READY_TIMEOUT_SECONDS or investigating host
            # load/forkserver health would.
            logger.warning(
                "%s: worker did not become ready within %.1fs (pattern=%r) — this host or its "
                "forkserver could not start a worker process in time; treating as UNDETERMINED. "
                "This is NOT evidence the pattern is pathological — consider raising "
                "ACROPOLIS_WORKER_READY_TIMEOUT_SECONDS or investigating host load",
                log_label, _WORKER_READY_TIMEOUT_SECONDS, compiled.pattern,
            )
            return None, "not_ready"
        except Exception:
            # Neither of the above — an infra failure (forkserver unavailable, fd/process
            # limits, queue error). Logged distinctly so an operator doesn't chase a
            # nonexistent bad regex when the real cause is environmental.
            logger.exception(
                "%s for pattern=%r failed unexpectedly (not a timeout) — treating as "
                "UNDETERMINED",
                log_label, compiled.pattern,
            )
            return None, "error"
        finally:
            process.terminate()
            process.join(timeout=1.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)
            result_queue.close()


async def _match_with_timeout(compiled, value: str) -> MatchOutcome:
    """Runs compiled.search(value) in a forked child process with a hard wall-clock timeout that
    starts only once the worker has confirmed (via a readiness Event, not process.start()
    returning) that it is actually running and about to match — see _run_worker_with_timeout
    and _wait_for_worker for why process.start() returning is not sufficient. If the match
    doesn't finish in time, the child is forcibly terminated (SIGTERM, then SIGKILL if it
    doesn't die promptly) — the part a thread-based approach cannot do. Returns
    MatchOutcome.UNDETERMINED on timeout (either kind) or infra failure; the caller
    (_check_param) decides what that means for the block/allow decision, so an undetermined
    result is never silently folded into "did not match"."""
    matched, _ = await _run_worker_with_timeout(_regex_worker, compiled, value, "block_pattern match")
    if matched is None:
        return MatchOutcome.UNDETERMINED
    return MatchOutcome.MATCHED if matched else MatchOutcome.NOT_MATCHED


async def _finditer_spans_with_timeout(compiled, value: str) -> Optional[list[tuple[int, int]]]:
    """DLP companion to _match_with_timeout, for callers that need every match SPAN
    (redaction needs positions, not just yes/no) rather than a single matched/not-matched
    outcome. Deliberately a SEPARATE function rather than extending _match_with_timeout's
    return type — that keeps its narrow contract and its test coverage untouched. Shares
    _run_worker_with_timeout with _match_with_timeout (same _mp_context, same semaphore, same
    readiness/timeout/kill handling) so the two stay behaviorally identical on the timeout/kill
    path; only the worker function and result shape differ. Returns None on timeout (either
    kind) or infra failure — the caller must treat that as UNDETERMINED and fail closed,
    exactly as MatchOutcome.UNDETERMINED does for _match_with_timeout."""
    spans, _ = await _run_worker_with_timeout(
        _finditer_spans_worker, compiled, value, "dlp custom pattern finditer"
    )
    return spans


# Fraction of _REGEX_MATCH_TIMEOUT_SECONDS that warm_forkserver()'s calibration check treats as
# "close enough to the budget to warn about". Chosen to catch the issue #106 scenario (steady-
# state overhead at 70-96% of the budget) while staying well clear of ordinary warm-match
# variance, which the R5 measurements put at low single-digit percent on a reference host.
_CALIBRATION_WARN_THRESHOLD = 0.5


async def warm_forkserver() -> None:
    """Issue #106, suggestion #4: spend one throwaway match at app startup so the FIRST real
    policy-checked request doesn't pay to spawn the forkserver helper process itself. Measured
    cold-start cost (no helper yet spawned) is ~5x the warm per-call cost — see the issue and
    tests/bench/results/r5-redos-2026-08-10.md. Calling this from a request handler would just
    move the cold-start penalty onto whichever request happens to be first; calling it once
    from the app's startup/lifespan hook (see argus/app.py) pays it before any request exists.

    Also implements issue #106 suggestion #3: if even a WARM match on this host already
    consumes a large fraction of _REGEX_MATCH_TIMEOUT_SECONDS, log a clear warning at boot
    rather than letting an operator discover it later as a live request's spurious block. A
    fresh Event/Queue/Process is used for the warmup, identical to a real match — anything
    that would make a real call slow will make this slow too.

    Deliberately swallows any exception: this is a best-effort startup optimization, not a
    correctness requirement. A forkserver that can't be warmed here will still work correctly
    (if slower) on the first real request via the exact same code path — see
    _run_worker_with_timeout's own infra-failure handling, which is unconditional and does not
    depend on warm_forkserver() having run first. A broken forkserver should surface as an
    UNDETERMINED/blocked policy decision on first use, not as a crash at boot on an otherwise
    unrelated startup step."""
    import time

    try:
        compiled = re.compile(r"acropolis-forkserver-warmup-probe")
        start = time.monotonic()
        outcome = await _match_with_timeout(compiled, "warmup")
        elapsed = time.monotonic() - start

        if outcome is not MatchOutcome.NOT_MATCHED:
            # Should be unreachable (the probe pattern cannot match "warmup"), but this is a
            # calibration check, not the security-critical path — log and move on rather than
            # let a warmup oddity look like a startup failure.
            logger.warning(
                "policy: forkserver warmup probe returned unexpected outcome %s — matching "
                "still proceeds normally on real requests via the same code path", outcome,
            )
            return

        logger.info("policy: forkserver warmed (probe match took %.1fms)", elapsed * 1000)

        if elapsed > _REGEX_MATCH_TIMEOUT_SECONDS * _CALIBRATION_WARN_THRESHOLD:
            logger.warning(
                "policy: a warm, trivially-fast regex match took %.1fms on this host — over "
                "%.0f%% of the configured %.1fs block_pattern match budget. Even benign "
                "block_patterns may spuriously time out under load or on further-loaded "
                "requests. Consider raising ACROPOLIS_REGEX_MATCH_TIMEOUT_SECONDS or "
                "investigating host performance (see issue #106).",
                elapsed * 1000, _CALIBRATION_WARN_THRESHOLD * 100, _REGEX_MATCH_TIMEOUT_SECONDS,
            )
    except Exception:
        logger.exception(
            "policy: forkserver warmup failed — not fatal, matching still proceeds normally "
            "(with cold-start cost) on the first real request"
        )


@dataclass
class Decision:
    blocked: bool
    reason: Optional[str] = None
    rule: Optional[str] = None
    matched: Optional[str] = None
    args_summary: Optional[dict] = None
    # DLP: set only when a DLP detector fired. dlp_detector/dlp_action/dl_match_count are safe
    # to audit/log/send in a webhook — dlp_redacted_arguments (when action == "redact")
    # carries the REDACTED (placeholder-substituted) arguments dict, which is safe to forward
    # upstream but is deliberately kept off the audit row and webhook path; only
    # argus/pipeline.py reads it, to build the re-serialized forwarded body. See docs/dlp.md's
    # audit-safety invariant: the matched/redacted value must never appear in the audit log or
    # a webhook payload, only which detector fired and what action was taken.
    dlp_detector: Optional[str] = None
    dlp_action: Optional[str] = None
    dlp_match_count: int = 0
    dlp_redacted_arguments: Optional[dict] = None


# Redact by KEY NAME before truncating by length: length-truncation alone is insufficient for
# secret safety — a short secret (an 8-character API key, a PIN) survives it untouched and
# would land in the audit log verbatim.
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
            # Fail closed: a timeout or infra failure on an operator-authored block_pattern
            # rule is treated as a match, not a pass. Fail-open-on-timeout meant a request
            # could disable enforcement just by generating enough concurrent load; failing
            # closed degrades a pathological pattern to "blocks everything it's checked
            # against" — visible and loud rather than a silent bypass. See
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

    # DLP scan — deliberately LAST, after allow/deny and param rules: a call that's going to
    # be blocked outright by an earlier check shouldn't pay for a DLP scan. Deliberately
    # arguments-only (not responses) — see docs/dlp.md for the benchmark-gated scope decision.
    # Every detector defaults to off (ServerPolicy.dlp_detectors defaults to {}), so a server
    # with no DLP config takes this branch's early-return on the very first line of dlp_scan
    # and behaves identically to a server without the feature.
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
