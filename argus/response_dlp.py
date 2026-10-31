"""Response DLP (issue #165): scan tools/call RESPONSES for secrets before they reach the caller.

This module is the pure part: it takes a parsed JSON-RPC message and a ServerPolicy and returns
a rewritten message. It knows nothing about HTTP; argus/pipeline.py wires it into the bridged
and passthrough forwarding paths.

Rules it enforces (docs/dlp.md, "Responses"):
  - Only `redact` and `allow` exist for responses. Nothing here can fail a call.
  - Every string value under `result`, `error` and `params` is scanned. Object keys, numbers,
    booleans and nulls are not.
  - The scan budget (`response_dlp_max_bytes`, UTF-8 bytes of string content) bounds the work.
    Over budget, the longest strings are cut to an equal share and end with TRUNCATION_MARKER.
    The kept head is still scanned, with a lookahead past the cut so a secret straddling it is
    redacted rather than left as a prefix.
  - A custom pattern that times out redacts the whole string (fail closed, as for arguments).
  - Matched values never leave this module except inside `ResponseScan.result`, already
    replaced. `detectors_fired` carries names only.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from argus.dlp import (
    BUILTIN_DETECTORS,
    CustomPatternSpec,
    Detector,
    Finding,
    _apply_redactions,
    _scan_value_with_custom_pattern,
    _scan_value_with_detector,
)
from db.models import RESPONSE_DLP_MAX_BYTES_DEFAULT, ServerPolicy

TRUNCATION_MARKER = "[TRUNCATED: response exceeded the {limit} scan limit; narrow the query]"
HARD_LIMIT_MARKER = "[TRUNCATED: response exceeded the hard read limit; narrow the query]"
UNPARSEABLE_MARKER = "[TRUNCATED: response could not be parsed for scanning]"
# The passthrough path stops reading the upstream body at this multiple of the scan budget.
HARD_CEILING_FACTOR = 8
# Characters scanned past a cut, so a secret that starts in the kept head but ends after the cut
# is still found. Covers every built-in except an outsized JWT (whose segments allow more); a
# longer secret straddling the cut would leave a prefix that no longer matches.
CUT_LOOKAHEAD_CHARS = 4096

# Top-level JSON-RPC members whose string leaves are scanned. `params` covers notifications
# (logging, progress) that an SSE tools/call stream can carry ahead of the result.
_SCANNED_MEMBERS = ("result", "error", "params")


@dataclass(frozen=True)
class ResponseScan:
    result: Any                     # the rewritten JSON-RPC message (dict), safe to forward
    detectors_fired: list[str]      # sorted, unique; names only
    match_count: int
    truncated: bool


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key in JSON object")
        out[key] = value
    return out


def loads_strict(data: "str | bytes") -> Any:
    """json.loads that refuses a repeated object key. json.loads keeps the last copy, so a scan
    of the parsed value would miss a secret in an earlier copy, and the passthrough path forwards
    the original bytes when nothing fired. The caller treats the ValueError as unparseable."""
    return json.loads(data, object_pairs_hook=_reject_duplicate_keys)


def format_limit(limit: int) -> str:
    return "1 MB" if limit == RESPONSE_DLP_MAX_BYTES_DEFAULT else f"{limit} bytes"


def marker_message(rpc_id: Any, text: str) -> dict:
    """A valid tools/call result carrying only `text`. Used when the response cannot be scanned:
    the caller gets a readable reason, never the upstream's unscanned bytes."""
    return {
        "jsonrpc": "2.0", "id": rpc_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


def response_dlp_enabled(policy: ServerPolicy, rpc_method: str) -> bool:
    return bool(policy.response_dlp_detectors) and rpc_method == "tools/call"


def _collect(node: Any, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _collect(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect(v, out)


def _rebuild(node: Any, replacements: "iter[str]") -> Any:
    # Same depth-first order as _collect, so the i-th string gets the i-th replacement.
    if isinstance(node, str):
        return next(replacements)
    if isinstance(node, dict):
        return {k: _rebuild(v, replacements) for k, v in node.items()}
    if isinstance(node, list):
        return [_rebuild(v, replacements) for v in node]
    return node


def _equal_share_cap(sizes: list[int], budget: int) -> int:
    """Largest per-string byte cap c such that sum(min(size, c)) <= budget. Strings under c keep
    everything; the longest strings are cut to c (water-filling)."""
    remaining = budget
    ordered = sorted(sizes)
    n = len(ordered)
    for i, size in enumerate(ordered):
        share = remaining // (n - i)
        if size > share:
            return share
        remaining -= size
    return max(ordered, default=0)


def _cut(text: str, max_bytes: int) -> str:
    # Drop a partial trailing code point instead of splitting it.
    return text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")


def _active_scanners(policy: ServerPolicy) -> tuple[list[Detector], list[CustomPatternSpec]]:
    redact = {name for name, action in policy.response_dlp_detectors.items() if action == "redact"}
    builtins = [BUILTIN_DETECTORS[n] for n in sorted(redact) if n in BUILTIN_DETECTORS]
    # The response map's action applies to a custom pattern, never its own argument action.
    customs = [
        CustomPatternSpec(name=p.name, pattern=p.pattern, action="redact")
        for p in policy.dlp_custom_patterns
        if p.name in redact
    ]
    return builtins, customs


async def _findings(text: str, builtins: list[Detector], customs: list[CustomPatternSpec]) -> list[Finding]:
    found: list[Finding] = []
    for detector in builtins:
        found.extend(await _scan_value_with_detector(text, detector))
    for spec in customs:
        found.extend(await _scan_value_with_custom_pattern(text, spec))
    return found


async def scan_result(message: Any, policy: ServerPolicy) -> ResponseScan:
    """Scan one JSON-RPC message (or a batch list of them) and return a rewritten copy. The
    input is never mutated."""
    messages = message if isinstance(message, list) else [message]

    leaves: list[str] = []
    for m in messages:
        if isinstance(m, dict):
            for member in _SCANNED_MEMBERS:
                if member in m:
                    _collect(m[member], leaves)

    budget = policy.response_dlp_max_bytes
    sizes = [len(s.encode("utf-8")) for s in leaves]
    truncated = sum(sizes) > budget
    cap = _equal_share_cap(sizes, budget) if truncated else None
    marker = TRUNCATION_MARKER.format(limit=format_limit(budget))

    builtins, customs = _active_scanners(policy)
    fired: set[str] = set()
    match_count = 0
    replaced: list[str] = []
    for text, size in zip(leaves, sizes):
        if cap is not None and size > cap:
            head = _cut(text, cap)
            window = text[: len(head) + CUT_LOOKAHEAD_CHARS]
            findings = [
                Finding(f.detector, f.start, min(f.end, len(head)), "")
                for f in await _findings(window, builtins, customs)
                if f.start < len(head)
            ]
            new_text = _apply_redactions(head, findings) + marker
        else:
            findings = await _findings(text, builtins, customs)
            new_text = _apply_redactions(text, findings) if findings else text
        match_count += len(findings)
        fired.update(f.detector for f in findings)
        replaced.append(new_text)

    it = iter(replaced)
    rebuilt = []
    for m in messages:
        if isinstance(m, dict):
            m = dict(m)
            # Same member order as the collection pass above, whatever the message's key order.
            for member in _SCANNED_MEMBERS:
                if member in m:
                    m[member] = _rebuild(m[member], it)
        rebuilt.append(m)

    return ResponseScan(
        result=rebuilt if isinstance(message, list) else rebuilt[0],
        detectors_fired=sorted(fired),
        match_count=match_count,
        truncated=truncated,
    )
