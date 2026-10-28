from __future__ import annotations

import time

import pytest

from argus.dlp import (
    BUILTIN_DETECTORS,
    ArgumentsScanResult,
    CustomPatternSpec,
    Finding,
    _aws_key_format_valid,
    _luhn_valid,
    _shannon_entropy,
    dlp_scan,
    scan_value,
)
from db.models import DlpCustomPattern, ServerPolicy

# ---------------------------------------------------------------------------
# Luhn validator — the plan names this test explicitly: a Luhn-INVALID 16-digit number must
# not fire the card detector.
# ---------------------------------------------------------------------------

def test_luhn_valid_test_card_number():
    # A well-known Luhn-valid test card number (Visa test number, not a real account).
    assert _luhn_valid("4111111111111111")


def test_luhn_invalid_sequential_digits_rejected():
    # A Luhn-INVALID 16-digit run — sequential digits, deliberately not a valid card checksum.
    assert not _luhn_valid("1234567890123456")


async def test_credit_card_detector_matches_valid_card():
    findings = await _scan_helper("my card is 4111111111111111", {"credit_card": "redact"})
    assert len(findings) == 1
    assert findings[0].detector == "credit_card"


async def test_credit_card_detector_rejects_luhn_invalid_near_miss():
    """The near-miss test named directly in the plan: a Luhn-invalid 16-digit number must NOT
    fire the card detector, even though it has the right shape."""
    findings = await _scan_helper("reference number 1234567890123456", {"credit_card": "redact"})
    assert findings == []


async def test_credit_card_detector_accepts_grouped_digits():
    findings = await _scan_helper("card: 4111 1111 1111 1111", {"credit_card": "redact"})
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Email detector
# ---------------------------------------------------------------------------

async def test_email_detector_matches():
    findings = await _scan_helper("contact me at nick@example.com please", {"email": "redact"})
    assert len(findings) == 1
    assert findings[0].detector == "email"


async def test_email_detector_rejects_non_email_text():
    findings = await _scan_helper("this has an @ sign but is not an email", {"email": "redact"})
    assert findings == []


# ---------------------------------------------------------------------------
# US SSN detector
# ---------------------------------------------------------------------------

async def test_ssn_detector_matches_valid_shape():
    findings = await _scan_helper("ssn: 123-45-6789", {"us_ssn": "redact"})
    assert len(findings) == 1
    assert findings[0].detector == "us_ssn"


@pytest.mark.parametrize("bad_ssn", ["000-12-3456", "666-12-3456", "923-12-3456", "123-00-4567", "123-45-0000"])
async def test_ssn_detector_rejects_reserved_area_group_serial(bad_ssn):
    """SSA reserves 000/666/9xx area numbers and 00 group / 0000 serial — an SSN-shaped number
    using one of these is structurally invalid and must not fire."""
    findings = await _scan_helper(f"ssn: {bad_ssn}", {"us_ssn": "redact"})
    assert findings == []


# ---------------------------------------------------------------------------
# AWS access key detector
# ---------------------------------------------------------------------------

def test_aws_key_format_valid_accepts_correct_shape():
    assert _aws_key_format_valid("AKIAIOSFODNN7EXAMPLE")


def test_aws_key_format_valid_rejects_bad_prefix():
    assert not _aws_key_format_valid("ZKIAIOSFODNN7EXAMPLE")


def test_aws_key_format_valid_rejects_wrong_length():
    assert not _aws_key_format_valid("AKIASHORT")


async def test_aws_key_detector_matches():
    findings = await _scan_helper("key=AKIAIOSFODNN7EXAMPLE", {"aws_access_key": "redact"})
    assert len(findings) == 1
    assert findings[0].detector == "aws_access_key"


async def test_aws_key_detector_rejects_near_miss_prefix():
    findings = await _scan_helper("key=ZKIAIOSFODNN7EXAMPLE", {"aws_access_key": "redact"})
    assert findings == []


# ---------------------------------------------------------------------------
# PEM private key header detector
# ---------------------------------------------------------------------------

async def test_pem_detector_matches_rsa_header():
    findings = await _scan_helper(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----",
        {"private_key_pem": "redact"},
    )
    assert len(findings) == 1
    assert findings[0].detector == "private_key_pem"


async def test_pem_detector_matches_plain_header():
    findings = await _scan_helper("-----BEGIN PRIVATE KEY-----", {"private_key_pem": "redact"})
    assert len(findings) == 1


async def test_pem_detector_does_not_match_public_key():
    findings = await _scan_helper("-----BEGIN PUBLIC KEY-----", {"private_key_pem": "redact"})
    assert findings == []


# ---------------------------------------------------------------------------
# High-entropy generic string detector
# ---------------------------------------------------------------------------

def test_shannon_entropy_of_repeated_char_is_zero():
    assert _shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_random_looking_string_is_high():
    assert _shannon_entropy("aB3xQ9zR7mK2pL6vN8wT") > 3.5


async def test_high_entropy_detector_matches_random_token():
    findings = await _scan_helper(
        "token=sk_live_aB3xQ9zR7mK2pL6vN8wT4jY1", {"high_entropy_string": "redact"}
    )
    assert len(findings) >= 1
    assert findings[0].detector == "high_entropy_string"


async def test_high_entropy_detector_rejects_ordinary_word():
    findings = await _scan_helper(
        "supercalifragilisticexpialidocious is a long word", {"high_entropy_string": "redact"}
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Detector registry sync with db/models.py's validated name set
# ---------------------------------------------------------------------------

def test_dlp_detector_names_match_builtin_registry():
    from db.models import _VALID_DLP_DETECTOR_NAMES

    assert set(BUILTIN_DETECTORS.keys()) == _VALID_DLP_DETECTOR_NAMES


# ---------------------------------------------------------------------------
# Built-in detector patterns must not be vulnerable to catastrophic backtracking.
#
# Self-review finding: the ORIGINAL email detector pattern
# (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b") was vulnerable — confirmed ~15s
# against "a."*20000 + "@" + "b."*20000 — despite being curated, non-operator-supplied text.
# Built-in patterns are matched DIRECTLY (not routed through the forkserver, see
# _scan_value_with_detector's docstring for why), so each one must be individually proven safe
# rather than relying on runtime protection. This test is the regression guard for that bar —
# it must pass for every CURRENT detector, and any future detector added to BUILTIN_DETECTORS
# should be added to the adversarial-input list below before shipping.
# ---------------------------------------------------------------------------

_EMAIL_REDOS_ADVERSARIAL_INPUT = "a." * 20000 + "@" + "b." * 20000


def test_email_detector_pattern_resists_redos():
    """The specific input that broke the original pattern — must now complete quickly."""
    pattern = BUILTIN_DETECTORS["email"].pattern
    start = time.monotonic()
    list(pattern.finditer(_EMAIL_REDOS_ADVERSARIAL_INPUT))
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"email pattern took {elapsed:.2f}s on adversarial input — ReDoS regression"


def test_all_builtin_detector_patterns_resist_randomized_fuzz():
    """Broader net than the one known-bad input above: randomized fuzz input drawn from each
    pattern's own relevant alphabet, run against every built-in detector, bounding worst-case
    time. Not exhaustive (fuzzing never is), but catches the class of bug the email detector
    had — a future detector pattern that's slow on structured-but-adversarial input."""
    import random

    rng = random.Random(1234)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_@+= "
    for name, detector in BUILTIN_DETECTORS.items():
        for _ in range(15):
            n = rng.randint(500, 20000)
            text = "".join(rng.choices(alphabet, k=n))
            start = time.monotonic()
            list(detector.pattern.finditer(text))
            elapsed = time.monotonic() - start
            assert elapsed < 1.0, f"detector {name!r} took {elapsed:.2f}s on fuzzed input len={n} — possible ReDoS"


# ---------------------------------------------------------------------------
# Actions: allow / redact / block
# ---------------------------------------------------------------------------

async def test_allow_action_never_scans():
    """A detector mapped to 'allow' must produce zero findings — allow means do nothing, not
    'detect but don't act'."""
    result = await scan_value("card 4111111111111111", {"credit_card": "allow"}, [])
    assert result.action == "allow"
    assert result.match_count == 0


async def test_redact_action_replaces_span_and_keeps_rest_of_value():
    result = await scan_value("my email is nick@example.com, thanks", {"email": "redact"}, [])
    assert result.action == "redact"
    assert "nick@example.com" not in result.redacted_value
    assert "[REDACTED:email]" in result.redacted_value
    assert result.redacted_value.startswith("my email is ")
    assert result.redacted_value.endswith(", thanks")


async def test_block_action_reports_block_without_needing_redacted_value():
    result = await scan_value("card 4111111111111111", {"credit_card": "block"}, [])
    assert result.action == "block"
    assert result.detector == "credit_card"


async def test_block_takes_precedence_over_redact_when_both_fire():
    result = await scan_value(
        "email nick@example.com card 4111111111111111",
        {"email": "redact", "credit_card": "block"},
        [],
    )
    assert result.action == "block"


# ---------------------------------------------------------------------------
# Custom patterns — operator-supplied, untrusted input (F2 attack surface)
# ---------------------------------------------------------------------------

async def test_custom_pattern_matches_and_redacts():
    spec = CustomPatternSpec(name="employee_id", pattern=r"EMP-\d{6}", action="redact")
    result = await scan_value("employee EMP-123456 requested access", {}, [spec])
    assert result.action == "redact"
    assert "EMP-123456" not in result.redacted_value
    assert "[REDACTED:employee_id]" in result.redacted_value


async def test_custom_pattern_no_match_allows():
    spec = CustomPatternSpec(name="employee_id", pattern=r"EMP-\d{6}", action="redact")
    result = await scan_value("nothing sensitive here", {}, [spec])
    assert result.action == "allow"


async def test_custom_pattern_block_action():
    spec = CustomPatternSpec(name="internal_secret", pattern=r"SECRET-\d+", action="block")
    result = await scan_value("value SECRET-42", {}, [spec])
    assert result.action == "block"
    assert result.detector == "internal_secret"


async def test_pathological_custom_pattern_hits_redos_timeout_and_fails_closed():
    """The security-critical case, mirroring argus/policy.py's own F2 test: a pathological
    custom DLP pattern must not hang the scan, and an UNDETERMINED (timed-out) match is treated
    as a match — fail CLOSED, matching F2's precedent — not silently skipped."""
    spec = CustomPatternSpec(name="evil", pattern=r"^(a*)*\1$", action="block")
    evil_input = "a" * 30 + "b"

    start = time.monotonic()
    result = await scan_value(evil_input, {}, [spec])
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, "pathological custom pattern must not hang the scan"
    assert result.action == "block"
    assert result.detector == "evil"


async def test_pathological_custom_pattern_redact_action_fails_closed_too():
    """Same ReDoS case but with action=redact — a timed-out match still can't be trusted to
    have found nothing, so it must be treated as a full-value match (redacted, not passed
    through untouched)."""
    spec = CustomPatternSpec(name="evil", pattern=r"^(a*)*\1$", action="redact")
    evil_input = "a" * 30 + "b"

    result = await scan_value(evil_input, {}, [spec])
    assert result.action == "redact"
    assert evil_input not in result.redacted_value


def test_custom_pattern_invalid_regex_is_skipped_not_raised():
    """A pattern that fails to compile (shouldn't happen given DlpCustomPattern's own
    field_validator, but defense in depth) must not crash the scan — it's simply inert."""
    import asyncio

    spec = CustomPatternSpec(name="broken", pattern="[", action="block")
    result = asyncio.run(scan_value("anything", {}, [spec]))
    assert result.action == "allow"


# ---------------------------------------------------------------------------
# dlp_scan — the arguments-dict-level entry point used by argus.policy.evaluate
# ---------------------------------------------------------------------------

async def test_dlp_scan_redacts_matching_argument_leaves_others_untouched():
    policy = ServerPolicy(dlp_detectors={"email": "redact"})
    result = await dlp_scan(
        {"message": "email me at nick@example.com", "count": 5}, policy
    )
    assert result.action == "redact"
    assert "nick@example.com" not in result.redacted_arguments["message"]
    assert result.redacted_arguments["count"] == 5


async def test_dlp_scan_no_detectors_configured_allows():
    policy = ServerPolicy()
    result = await dlp_scan({"message": "card 4111111111111111"}, policy)
    assert result.action == "allow"
    assert result.redacted_arguments is None


async def test_dlp_scan_block_short_circuits_before_redacting_other_args():
    policy = ServerPolicy(dlp_detectors={"email": "redact", "credit_card": "block"})
    result = await dlp_scan(
        {"a": "email nick@example.com", "b": "card 4111111111111111"}, policy
    )
    assert result.action == "block"
    assert result.detector == "credit_card"


async def test_dlp_scan_non_string_argument_whole_value_redacted():
    """A non-string argument (e.g. a nested dict) whose str() representation matches can't be
    spliced in place — the whole value is replaced with the placeholder rather than risking a
    corrupted partial edit of non-string JSON."""
    policy = ServerPolicy(dlp_detectors={"email": "redact"})
    result = await dlp_scan({"payload": {"contact": "nick@example.com"}}, policy)
    assert result.action == "redact"
    assert result.redacted_arguments["payload"] == "[REDACTED:email]"


async def test_dlp_scan_with_custom_patterns():
    policy = ServerPolicy(
        dlp_custom_patterns=[DlpCustomPattern(name="employee_id", pattern=r"EMP-\d{6}", action="block")]
    )
    result = await dlp_scan({"note": "assigned to EMP-123456"}, policy)
    assert result.action == "block"
    assert result.detector == "employee_id"


async def _scan_helper(text: str, detectors: dict[str, str]) -> list[Finding]:
    """Test helper: run scan_value and return the underlying Finding list by re-deriving it
    from redacted spans when redact, or by probing block/allow directly. Simplify by scanning
    with action='redact' forced for the detectors under test (already what callers pass) and
    inspecting via a block-mode probe for existence, since ScanResult doesn't expose raw
    Finding objects directly for the redact path beyond the final string."""
    result = await scan_value(text, detectors, [])
    if result.action == "allow":
        return []
    # Reconstruct approximate finding count/detector identity from match_count/detector for
    # assertions that only need "did detector X fire N times", which is all these tests check.
    return [Finding(detector=result.detector, start=0, end=0, matched_text="") for _ in range(result.match_count)]


# ---------------------------------------------------------------------------
# Response DLP (issue #165): five detectors for secrets that show up in logs and ConfigMaps.
# Fake tokens are assembled at runtime so no literal token-shaped string sits in the source
# (keeps secret scanners and push protection quiet; the values are not real credentials).
# ---------------------------------------------------------------------------

import base64 as _b64
import json as _json


def _b64url(obj) -> str:
    return _b64.urlsafe_b64encode(_json.dumps(obj).encode()).rstrip(b"=").decode()


_FAKE_JWT = ".".join([
    _b64url({"alg": "HS256", "typ": "JWT"}),
    _b64url({"sub": "1234567890", "name": "dlp-test", "iat": 1516239022}),
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
])
_FAKE_GHP = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
_FAKE_GH_PAT = "github" + "_pat_" + "11ABCDEFG0123456789abc" + "_" + ("Zx9" * 19 + "Qw")


async def _redact(text: str, name: str) -> str | None:
    result = await scan_value(text, {name: "redact"}, [])
    return result.redacted_value if result.action == "redact" else None


def test_fake_tokens_have_the_real_shapes():
    assert len(_FAKE_GHP) == 40
    assert len(_FAKE_GH_PAT) == len("github_pat_") + 82
    assert _FAKE_JWT.count(".") == 2 and _FAKE_JWT.startswith("eyJ")


async def test_bearer_token_redacts_only_the_token():
    out = await _redact("Authorization: Bearer abc.DEF-123_xyz.789", "bearer_token")
    assert out == "Authorization: Bearer [REDACTED:bearer_token]"


@pytest.mark.parametrize("text", [
    "the bearer of bad news",
    "Bearer authentication is described in RFC 6750",
    "Bearer short_tok3n",
])
async def test_bearer_token_near_misses(text):
    assert await _redact(text, "bearer_token") is None


async def test_jwt_redacts_whole_token():
    out = await _redact(f"token issued: {_FAKE_JWT} (expires 1h)", "jwt")
    assert out == "token issued: [REDACTED:jwt] (expires 1h)"


@pytest.mark.parametrize("text", [
    "commit 4f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
    "eyJhbGciOi",
    "eyJhbGciOiJIUzI1NiJ9 alone",
])
async def test_jwt_near_misses(text):
    assert await _redact(text, "jwt") is None


async def test_github_classic_token_redacted():
    out = await _redact(f"GH={_FAKE_GHP} done", "github_token")
    assert out == "GH=[REDACTED:github_token] done"


async def test_github_fine_grained_pat_redacted():
    out = await _redact(f"using {_FAKE_GH_PAT}", "github_token")
    assert out == "using [REDACTED:github_token]"


async def test_github_token_near_miss():
    assert await _redact("ghp_short and gho_ also short", "github_token") is None


async def test_secret_assignment_redacts_value_keeps_key():
    out = await _redact("DB_PASSWORD=hunter2hunter2", "secret_assignment")
    assert out == "DB_PASSWORD=[REDACTED:secret_assignment]"


async def test_secret_assignment_json_style():
    out = await _redact('{"client_secret": "x9Qz7LmN2pR4"}', "secret_assignment")
    assert out == '{"client_secret": "[REDACTED:secret_assignment]"}'


@pytest.mark.parametrize("text", [
    "password_policy=strict",
    "token_count: 5",
    "max_token: 4096",
    '"secret": true',
    "password: null",
    "PWD=/home/app",
    "secretName: app-credentials-ref",
])
async def test_secret_assignment_near_misses(text):
    assert await _redact(text, "secret_assignment") is None


async def test_url_credentials_redacts_password_only():
    out = await _redact("dsn postgres://app:s3cr3t@db:5432/x ok", "url_credentials")
    assert out == "dsn postgres://app:[REDACTED:url_credentials]@db:5432/x ok"


@pytest.mark.parametrize("text", [
    "https://user@host/path",
    "https://host:8080/path@x",
    "see https://example.com/a:b",
])
async def test_url_credentials_near_misses(text):
    assert await _redact(text, "url_credentials") is None


_NEW_DETECTORS = ("bearer_token", "jwt", "github_token", "secret_assignment", "url_credentials")


async def test_png_base64_fires_none_of_the_new_detectors():
    png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg"
    text = (png * 3)[:200]
    for name in _NEW_DETECTORS:
        assert await _redact(text, name) is None, name


def test_new_detectors_registered():
    for name in _NEW_DETECTORS:
        assert name in BUILTIN_DETECTORS


def test_all_builtin_detector_patterns_resist_structured_fuzz():
    """Same bound as the randomized fuzz above, but the alphabet carries the separators the
    response detectors key on (`:` `/` `@` `=` quotes, `Bearer`, `eyJ`), so their bounded
    quantifiers are actually exercised rather than failing on the first character."""
    import random

    rng = random.Random(4321)
    tokens = list("abcXYZ019._-:/@=\"' \t") + ["Bearer ", "eyJ", "password=", "://", "ghp_", "token: "]
    for name, detector in BUILTIN_DETECTORS.items():
        for _ in range(15):
            n = rng.randint(500, 20000)
            text = "".join(rng.choices(tokens, k=n))
            start = time.monotonic()
            list(detector.pattern.finditer(text))
            elapsed = time.monotonic() - start
            assert elapsed < 1.0, f"detector {name!r} took {elapsed:.2f}s on structured fuzz len={len(text)}"


async def test_nested_findings_never_leak_the_outer_span():
    """Two findings where one sits inside the other. Before span merging, back-to-front
    splicing used offsets from the original string after the inner placeholder had shifted
    them, and the tail of the outer match survived into the output."""
    outer = CustomPatternSpec(name="outer", pattern=r"KEY[0-9]{20}END", action="redact")
    inner = CustomPatternSpec(name="i", pattern=r"[0-9]{3}", action="redact")
    secret = "KEY01234567890123456789END"
    result = await scan_value(f"x {secret} y", {}, [outer, inner])
    assert result.action == "redact"
    assert "END" not in result.redacted_value
    for digit_run in ("4567", "6789", "0123"):
        assert digit_run not in result.redacted_value
    assert result.redacted_value == "x [REDACTED:outer] y"
