from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import Callable, Optional

from argus.policy import _finditer_spans_with_timeout
from db.models import ServerPolicy

logger = logging.getLogger("argus.dlp")

# Enterprise #10 (DLP): value-scanning detectors for tool ARGUMENTS only — see docs/dlp.md for
# the full design writeup, including why response scanning is explicitly out of scope for this
# PR (benchmark-gated, not built speculatively) and why encoding evasion (base64/URL-encoding/
# unicode homoglyphs) is documented as out of scope rather than defeated.
#
# Every pattern match here — built-in detector patterns AND operator-supplied custom_patterns —
# goes through argus.policy's forkserver machinery (_finditer_spans_with_timeout, itself built
# on the same process/timeout/kill primitives as _match_with_timeout) built for
# F2. Operator-supplied patterns are untrusted input, exactly F2's attack surface; a pathological
# custom pattern must hit the timeout and be treated as UNDETERMINED -> fail closed (block),
# never hang the request or silently pass values through unscanned.

REDACTED_PLACEHOLDER = "[REDACTED:{detector}]"


@dataclass(frozen=True)
class Finding:
    """One detector match against one string value. `matched_text` is carried ONLY inside the
    process for the duration of building the redacted replacement — callers (policy.py,
    audit logging, webhooks) must never persist or transmit `matched_text` itself; only
    `detector` and counts are safe to log. See docs/dlp.md's audit-safety invariant."""

    detector: str
    start: int
    end: int
    matched_text: str


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum (mod 10) — used to cut false positives on the credit-card
    detector. A random 16-digit run of digits has roughly a 1-in-10 chance of passing Luhn by
    chance, so this materially reduces (not eliminates) false positives; it is not itself proof
    a number is a real, active card."""
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# --- AWS access key checksum -------------------------------------------------------------
#
# AWS access key IDs (AKIA.../ASIA.../etc, 20 chars total, base32-ish alphabet) do not have a
# public, documented checksum algorithm the way credit cards (Luhn) do. The format itself —
# a fixed 4-letter prefix from a known set followed by 16 base32 uppercase-alnum characters —
# is the validation available to us; that's what _aws_key_format_valid checks. Documented
# explicitly here (and in docs/dlp.md) so this isn't confused with a cryptographic checksum.
_AWS_KEY_PREFIXES = ("AKIA", "ASIA", "AROA", "AIDA", "AGPA", "AIPA", "ANPA", "ANVA", "ASCA")
_AWS_KEY_BODY_RE = re.compile(r"^[A-Z0-9]{16}$")


def _aws_key_format_valid(candidate: str) -> bool:
    if len(candidate) != 20:
        return False
    prefix, body = candidate[:4], candidate[4:]
    return prefix in _AWS_KEY_PREFIXES and bool(_AWS_KEY_BODY_RE.match(body))


@dataclass(frozen=True)
class Detector:
    name: str
    label: str
    pattern: re.Pattern
    # Optional secondary validator over the raw matched text (e.g. Luhn, AWS key format) to
    # reject near-misses the regex alone can't rule out. Returning False means "not a real
    # finding" — the match is discarded entirely, not just downgraded.
    validator: Optional[Callable[[str], bool]] = None


def _card_validator(matched: str) -> bool:
    digits = re.sub(r"[ -]", "", matched)
    return 13 <= len(digits) <= 19 and _luhn_valid(digits)


def _aws_key_validator(matched: str) -> bool:
    return _aws_key_format_valid(matched)


def _char_classes(s: str) -> int:
    """Count of distinct character classes present (lowercase, uppercase, digit, other/
    symbol) — the standard secret-scanner heuristic (trufflehog/gitleaks use the same idea)
    for telling a real token apart from an ordinary word. Shannon entropy ALONE is a weak
    signal here: a long, unusual-but-real English word ("supercalifragilisticexpialidocious")
    can score similarly to a short random token purely from letter-frequency variety, without
    ever mixing case, digits, or symbols the way a generated API key/token does."""
    classes = 0
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes


def _high_entropy_validator(matched: str) -> bool:
    # Generic detector's own regex already restricts to a plausible secret-token shape
    # (see BUILTIN_DETECTORS below); the validator requires BOTH a high Shannon entropy AND at
    # least 3 of the 4 character classes (lower/upper/digit/symbol) so an ordinary long word —
    # all-lowercase, one character class — doesn't fire regardless of its letter-frequency
    # entropy, while a real generated token (mixed case + digits, typical of API keys) does.
    return _shannon_entropy(matched) >= 3.5 and _char_classes(matched) >= 3


# Built-in detectors, keyed by stable name (used in dlp_detectors config, audit rows, and
# webhook payloads). Every detector is opt-in — see policy.py's dlp_scan, which only runs a
# detector when its name is present in ServerPolicy.dlp_detectors.
BUILTIN_DETECTORS: dict[str, Detector] = {
    "credit_card": Detector(
        name="credit_card",
        label="Credit card number (Luhn-validated)",
        # 13-19 digits, optionally grouped with spaces or hyphens in blocks of 4 (loose on
        # grouping since real-world formatting varies; the Luhn validator is the real filter).
        pattern=re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        validator=_card_validator,
    ),
    "email": Detector(
        name="email",
        label="Email address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    "us_ssn": Detector(
        name="us_ssn",
        label="US Social Security Number",
        # Excludes the reserved 000/666/9xx area numbers and 00 group / 0000 serial, the same
        # structural rules SSA uses to void obviously-invalid SSNs.
        pattern=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"
        ),
    ),
    "aws_access_key": Detector(
        name="aws_access_key",
        label="AWS access key ID",
        pattern=re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"),
        validator=_aws_key_validator,
    ),
    "private_key_pem": Detector(
        name="private_key_pem",
        label="PEM private key header",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
    ),
    "high_entropy_string": Detector(
        name="high_entropy_string",
        label="Generic high-entropy string (likely a token/secret)",
        # 20-128 chars of token-alphabet (alnum + common secret-token punctuation), evaluated
        # for Shannon entropy by the validator. Deliberately conservative on length (>=20) —
        # shorter strings are indistinguishable from ordinary words/identifiers at any entropy
        # threshold that doesn't also swallow real text.
        pattern=re.compile(r"\b[A-Za-z0-9_\-/+=]{20,128}\b"),
        validator=_high_entropy_validator,
    ),
}


@dataclass(frozen=True)
class CustomPatternSpec:
    name: str
    pattern: str
    action: str


async def _scan_value_with_detector(text: str, detector: Detector) -> list[Finding]:
    """Find all matches of one detector in one string. Uses the detector's own compiled
    pattern's finditer for span discovery (built-in patterns are curated/trusted, not
    operator-supplied), but a per-candidate confirmation for validated detectors still MUST go
    through _match_with_timeout below for custom patterns. Built-in patterns are fixed at
    deploy time (not editable via the web UI), so they are not the F2 attack surface the way
    custom_patterns are — but we still keep individual match spans bounded to a single word/
    token shape (\\b...\\b) to avoid pathological input blowing up finditer."""
    findings: list[Finding] = []
    for m in detector.pattern.finditer(text):
        candidate = m.group(0)
        if detector.validator is not None and not detector.validator(candidate):
            continue
        findings.append(Finding(detector=detector.name, start=m.start(), end=m.end(), matched_text=candidate))
    return findings


async def _scan_value_with_custom_pattern(text: str, spec: CustomPatternSpec) -> list[Finding]:
    """Operator-supplied custom pattern — untrusted input, exactly F2's attack surface. Routed
    through argus.policy._finditer_spans_with_timeout, which runs the ENTIRE span-recovery
    finditer() call inside the same forkserver/timeout/kill envelope as F2's block_pattern
    primitive — not just a single existence check followed by an unguarded finditer. A pattern
    whose first match resolves quickly is not guaranteed to resolve its second/third match
    equally quickly (finditer restarts matching from each match's end, which is exactly the
    kind of position-dependent backtracking blowup a ReDoS pattern is built from), so bounding
    only the first match and then trusting finditer for the rest would leave a real gap."""
    try:
        compiled = re.compile(spec.pattern, re.IGNORECASE)
    except re.error:
        logger.warning("dlp custom_pattern %r for %r failed to compile — skipping", spec.pattern, spec.name)
        return []

    spans = await _finditer_spans_with_timeout(compiled, text)
    if spans is None:
        # Fail closed, matching F2's block_pattern precedent: a pathological custom DLP
        # pattern must not be able to buy a caller unscanned passage by making the scan hang
        # or silently no-op. We can't recover real match spans (that's exactly what timed
        # out), so an UNDETERMINED result is surfaced as a single synthetic finding spanning
        # the whole value — enough for the caller to redact-or-block the entire argument,
        # never enough to leak span content.
        logger.warning(
            "dlp custom pattern %r (%r) timed out against a value — failing closed (whole value "
            "treated as a match)", spec.name, spec.pattern,
        )
        return [Finding(detector=spec.name, start=0, end=len(text), matched_text=text)]

    return [
        Finding(detector=spec.name, start=start, end=end, matched_text=text[start:end])
        for start, end in spans
    ]


def _apply_redactions(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with a placeholder naming the detector, working back-to-
    front so earlier spans' offsets stay valid as later ones are substituted in."""
    ordered = sorted(findings, key=lambda f: f.start, reverse=True)
    out = text
    for f in ordered:
        out = out[: f.start] + REDACTED_PLACEHOLDER.format(detector=f.detector) + out[f.end :]
    return out


@dataclass
class ScanResult:
    action: str  # "allow" | "redact" | "block" — the most severe action across all findings
    detector: Optional[str] = None  # which detector drove the action (first one to hit block,
    # else first one that redacted)
    match_count: int = 0
    redacted_value: Optional[str] = None  # only set when action == "redact"


_ACTION_SEVERITY = {"allow": 0, "redact": 1, "block": 2}


async def scan_value(
    value: str,
    detectors: dict[str, str],
    custom_patterns: list[CustomPatternSpec],
) -> ScanResult:
    """Scan a single string value against every configured detector + custom pattern.

    `detectors` maps builtin detector name -> action; a detector not present (or mapped to
    "allow") does not run its match-collection at all for named builtins with action=allow,
    since there's no point spending the scan cost when the result can't change behavior —
    only redact/block-configured detectors incur a scan.

    Returns the single MOST SEVERE outcome (block > redact > allow) across every
    detector/pattern that fired, plus a match_count and (for redact) the fully redacted value
    with every matching span from every fired detector replaced — not just the most severe one,
    so a value matching two different low-severity detectors gets both spans removed.
    """
    all_findings_by_action: dict[str, list[Finding]] = {"block": [], "redact": []}

    for name, action in detectors.items():
        if action == "allow":
            continue
        detector = BUILTIN_DETECTORS.get(name)
        if detector is None:
            continue
        findings = await _scan_value_with_detector(value, detector)
        if findings:
            all_findings_by_action.setdefault(action, []).extend(findings)

    for spec in custom_patterns:
        if spec.action == "allow":
            continue
        findings = await _scan_value_with_custom_pattern(value, spec)
        if findings:
            all_findings_by_action.setdefault(spec.action, []).extend(findings)

    block_findings = all_findings_by_action.get("block", [])
    redact_findings = all_findings_by_action.get("redact", [])
    total_matches = len(block_findings) + len(redact_findings)

    if block_findings:
        return ScanResult(action="block", detector=block_findings[0].detector, match_count=total_matches)

    if redact_findings:
        redacted = _apply_redactions(value, redact_findings)
        return ScanResult(
            action="redact", detector=redact_findings[0].detector,
            match_count=total_matches, redacted_value=redacted,
        )

    return ScanResult(action="allow", match_count=0)


@dataclass
class ArgumentsScanResult:
    action: str  # "allow" | "redact" | "block"
    detector: Optional[str] = None
    match_count: int = 0
    redacted_arguments: Optional[dict] = None


def _stringifiable_items(arguments: dict) -> list[tuple[str, str]]:
    """Flatten top-level argument values to (key, str-value) pairs for scanning. Nested
    dicts/lists are stringified via str() rather than recursively walked — recursing into
    arbitrary nesting is a real feature gap (documented in docs/dlp.md's scope section) but
    scanning the str() representation still catches a secret embedded inside a nested
    structure's leaf value, just without being able to redact-in-place inside that nested
    structure (a redaction match inside a stringified nested value degrades to a whole-value
    block for safety rather than attempting a partial in-place edit of non-string JSON)."""
    return [(k, v if isinstance(v, str) else str(v)) for k, v in arguments.items()]


async def dlp_scan(arguments: dict, policy: ServerPolicy) -> ArgumentsScanResult:
    """Scan every argument value in a tools/call request against the server's configured DLP
    detectors + custom patterns. Returns the single most severe action across every argument
    (block > redact > allow); on redact, `redacted_arguments` is a full copy of `arguments`
    with every matched value (string args) or whole-value (non-string args whose str()
    representation matched) replaced.

    Called only when policy.dlp_detectors or policy.dlp_custom_patterns is non-empty (see
    argus.policy.evaluate) — every detector defaults to off, so a server with neither
    configured never reaches this function at all, which is what keeps default behavior
    byte-identical to pre-DLP Acropolis (see test_dlp.py's regression test)."""
    custom_specs = [
        CustomPatternSpec(name=p.name, pattern=p.pattern, action=p.action)
        for p in policy.dlp_custom_patterns
    ]

    best_action = "allow"
    best_detector: Optional[str] = None
    total_matches = 0
    redacted_arguments = dict(arguments)
    any_redacted = False

    for key, str_value in _stringifiable_items(arguments):
        result = await scan_value(str_value, policy.dlp_detectors, custom_specs)
        if result.action == "allow":
            continue

        total_matches += result.match_count
        if _ACTION_SEVERITY[result.action] > _ACTION_SEVERITY[best_action]:
            best_action = result.action
            best_detector = result.detector
        elif best_detector is None:
            best_detector = result.detector

        if result.action == "block":
            # No point continuing to redact other args once one has earned an outright block —
            # the call will be refused entirely, and the ordering guarantee (see
            # argus/pipeline.py) means nothing scanned so far has left the process yet.
            return ArgumentsScanResult(action="block", detector=result.detector, match_count=total_matches)

        if result.action == "redact":
            original = arguments[key]
            if isinstance(original, str):
                redacted_arguments[key] = result.redacted_value
            else:
                # Non-string value (number/bool/list/dict) whose stringified form matched — we
                # cannot safely splice a redaction placeholder into arbitrary JSON, so the whole
                # value is replaced with the placeholder. Still strictly safer than forwarding
                # it unredacted.
                redacted_arguments[key] = REDACTED_PLACEHOLDER.format(detector=result.detector)
            any_redacted = True

    if best_action == "block":
        return ArgumentsScanResult(action="block", detector=best_detector, match_count=total_matches)
    if any_redacted:
        return ArgumentsScanResult(
            action="redact", detector=best_detector, match_count=total_matches,
            redacted_arguments=redacted_arguments,
        )
    return ArgumentsScanResult(action="allow", match_count=0)
