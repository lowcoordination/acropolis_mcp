from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, PrivateAttr, field_validator

SLUG_RE = re.compile(r"^[a-z0-9-]+$")


class ParamRule(BaseModel):
    max_length: Optional[int] = None
    block_patterns: list[str] = []
    max_value: Optional[float] = None
    min_value: Optional[float] = None
    denied: bool = False

    @field_validator("block_patterns")
    @classmethod
    def _validate_patterns(cls, patterns: list[str]) -> list[str]:
        # Compile-on-write: bad or oversized regex fail at save time, not at first match.
        # ReDoS mitigation for a web-editable field: cap pattern length.
        for p in patterns:
            if len(p) > 200:
                raise ValueError(f"block pattern too long (max 200 chars): {p!r}")
            try:
                re.compile(p, re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"invalid regex {p!r}: {e}") from e
        return patterns

    _compiled_cache: Optional[list[re.Pattern]] = PrivateAttr(default=None)

    def compiled_patterns(self) -> list[re.Pattern]:
        # F26 fix (review 2026-08-04): this recompiled every pattern from scratch on every call,
        # and it's on the tools/call hot path (argus/policy.py's _check_param runs it per param
        # per request). block_patterns is validated (and thus fixed) at construction time and
        # never mutated afterward — see the field_validator above — so it's safe to compile once
        # and cache on the instance.
        if self._compiled_cache is None:
            self._compiled_cache = [re.compile(p, re.IGNORECASE) for p in self.block_patterns]
        return self._compiled_cache


class ToolPolicy(BaseModel):
    tool_name: str
    action: str  # "allow" | "deny"
    rate_limit: Optional[str] = None


_VALID_POLICY_MODES = {"passthrough", "allowlist", "denylist"}
_RATE_LIMIT_PERIODS = {"second", "minute", "hour"}


def _validate_rate_limit_spec(spec: str) -> None:
    # Mirrors argus.rate_limiter.parse_spec's grammar without importing it — rate_limiter sits
    # above db in this codebase's layering (it depends on nothing here), and this module
    # shouldn't invert that just to reuse a two-line parser.
    parts = spec.strip().split("/")
    if len(parts) != 2:
        raise ValueError(f"invalid rate limit {spec!r}: expected 'N/period', e.g. '5/minute'")
    count_str, unit = parts[0], parts[1].strip().lower()
    try:
        count = int(count_str)
    except ValueError:
        raise ValueError(f"invalid rate limit {spec!r}: {count_str!r} is not an integer") from None
    if count <= 0:
        raise ValueError(f"invalid rate limit {spec!r}: count must be positive")
    if unit not in _RATE_LIMIT_PERIODS:
        raise ValueError(f"invalid rate limit {spec!r}: period must be one of {sorted(_RATE_LIMIT_PERIODS)}")


_VALID_DLP_ACTIONS = {"allow", "redact", "block"}
# Kept in sync with argus.dlp.BUILTIN_DETECTORS' keys by test_models.py's
# test_dlp_detector_names_match_builtin_registry — not imported directly here to avoid db/
# depending on argus/ (db sits below argus in this codebase's layering, same reasoning as
# rate_limiter's spec grammar being duplicated rather than imported in _validate_rate_limit_spec
# above).
_VALID_DLP_DETECTOR_NAMES = {
    "credit_card", "email", "us_ssn", "aws_access_key", "private_key_pem", "high_entropy_string",
}
_MAX_CUSTOM_PATTERN_LENGTH = 200


class DlpCustomPattern(BaseModel):
    name: str
    pattern: str
    action: str = "block"

    @field_validator("pattern")
    @classmethod
    def _validate_pattern(cls, pattern: str) -> str:
        # Same compile-on-write ReDoS mitigation as ParamRule.block_patterns: cap length and
        # reject anything that doesn't even compile. This does NOT by itself prevent
        # catastrophic backtracking (see ParamRule's comment on the same point) — the runtime
        # protection is argus.dlp routing every custom-pattern match through
        # argus.policy._match_with_timeout's forkserver machinery, never raw `re` directly.
        if len(pattern) > _MAX_CUSTOM_PATTERN_LENGTH:
            raise ValueError(f"custom pattern too long (max {_MAX_CUSTOM_PATTERN_LENGTH} chars): {pattern!r}")
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid regex {pattern!r}: {e}") from e
        return pattern

    @field_validator("action")
    @classmethod
    def _validate_action(cls, action: str) -> str:
        if action not in _VALID_DLP_ACTIONS:
            raise ValueError(f"action must be one of {sorted(_VALID_DLP_ACTIONS)}, got {action!r}")
        return action


class ServerPolicy(BaseModel):
    mode: str = "passthrough"  # passthrough | allowlist | denylist
    rate_limit: Optional[str] = None
    allowed: list[str] = []
    denied: list[str] = []
    # tool_name -> param_name -> ParamRule
    param_rules: dict[str, dict[str, ParamRule]] = {}
    # Enterprise #10 (DLP): detector name -> "allow" | "redact" | "block". EVERY detector
    # defaults to off — a server with an empty dict here (the default) runs zero DLP scanning
    # and behaves byte-identically to pre-DLP Acropolis; see test_dlp.py's
    # test_no_dlp_config_is_byte_identical_to_pre_dlp_behavior. Rides the existing JSON policy
    # column — no migration needed (config export/import carries it for free, see
    # test_config_io.py's DLP round-trip test).
    dlp_detectors: dict[str, str] = {}
    # Operator-defined regex patterns, evaluated in addition to the named built-in detectors.
    # UNTRUSTED input — see argus/dlp.py's module docstring on why every match against these
    # goes through the F2 ReDoS-safe forkserver path, never raw `re`.
    dlp_custom_patterns: list[DlpCustomPattern] = []

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, mode: str) -> str:
        # F26 fix (review 2026-08-04): mode was an unvalidated bare str — a typo'd mode from the
        # API or a hand-edited guard-config.yml import silently fell through every `if mode ==
        # ...` check in argus/policy.py as neither allow- nor deny-list, defaulting to
        # passthrough behavior without ever surfacing that the operator's actual intent (an
        # allowlist, most likely) was never applied.
        if mode not in _VALID_POLICY_MODES:
            raise ValueError(f"mode must be one of {sorted(_VALID_POLICY_MODES)}, got {mode!r}")
        return mode

    @field_validator("rate_limit")
    @classmethod
    def _validate_rate_limit(cls, rate_limit: Optional[str]) -> Optional[str]:
        # F26 fix (review 2026-08-04): an unparseable rate_limit string used to save
        # successfully and then raise ValueError out of argus.rate_limiter.parse_spec on the
        # VERY NEXT tools/call against that server (RateLimiterRegistry.ensure_current re-parses
        # the spec on every request, not just once at save time — see Pipeline._check_rate_limits'
        # own comment on why). Validating at save time turns "every subsequent call 500s" into
        # "the bad policy is rejected with a 400 and never reaches the database."
        if rate_limit is not None:
            _validate_rate_limit_spec(rate_limit)
        return rate_limit

    @field_validator("dlp_detectors")
    @classmethod
    def _validate_dlp_detectors(cls, detectors: dict[str, str]) -> dict[str, str]:
        for name, action in detectors.items():
            if name not in _VALID_DLP_DETECTOR_NAMES:
                raise ValueError(
                    f"unknown dlp detector {name!r} (known: {sorted(_VALID_DLP_DETECTOR_NAMES)})"
                )
            if action not in _VALID_DLP_ACTIONS:
                raise ValueError(f"dlp_detectors[{name!r}] action must be one of {sorted(_VALID_DLP_ACTIONS)}, got {action!r}")
        return detectors


class ServerRecord(BaseModel):
    id: int
    slug: str
    name: str
    upstream_url: str
    enabled: bool
    in_aggregate: bool
    upstream_protocol: Optional[str] = None
    health_status: str = "unknown"
    last_seen_at: Optional[str] = None
    discover_json: Optional[str] = None
    created_at: str
    updated_at: str
    # F23 fix (review 2026-08-04): a literal Authorization header value injected on outbound
    # requests to THIS server's upstream — e.g. "Bearer <token>" or "Basic <base64>". None means
    # no credential configured (the upstream is either unauthenticated or on a trusted network).
    # Never echoed back in API responses that a non-admin could read; see ServerResponse in
    # archon/schemas.py, which deliberately omits this field entirely.
    upstream_auth_header: Optional[str] = None

    @field_validator("slug")
    @classmethod
    def _validate_slug(cls, slug: str) -> str:
        if not SLUG_RE.match(slug):
            raise ValueError(f"slug must match [a-z0-9-]+: {slug!r}")
        return slug


class ApiKeyRecord(BaseModel):
    id: int
    name: str
    key_prefix: str
    enabled: bool
    server_scopes: Optional[list[str]] = None
    created_at: str
    last_used_at: Optional[str] = None


class UserRecord(BaseModel):
    """A control-plane principal — local password auth or OIDC (enterprise #1/#2).

    `role` is deliberately a bare str, not an enum: 02-rbac.md's design decision is that role
    validity/hierarchy is an APPLICATION-layer concern (archon/rbac.py), not a schema-layer one,
    so a future role can be added without a migration. archon/rbac.py's ROLE_RANK is the single
    source of truth for what a "valid" role is; a value here that isn't a ROLE_RANK key must be
    treated as no access everywhere, never a permissive default.
    """
    id: int
    username: str
    email: Optional[str] = None
    password_hash: Optional[str] = None  # NULL for OIDC-only users
    role: str = "admin"
    auth_source: str = "local"  # 'local' | 'oidc'
    oidc_subject: Optional[str] = None  # IdP 'sub' — never key identity on email
    enabled: bool = True
    session_version: int = 0  # per-user revocation counter, independent of the global one
    created_at: str
    last_login_at: Optional[str] = None
