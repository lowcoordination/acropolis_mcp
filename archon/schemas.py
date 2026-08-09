from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator, model_validator

from db.models import SLUG_RE, DlpCustomPattern, ParamRule, ServerPolicy


def _validate_slug(slug: str) -> str:
    """F4 fix (review 2026-08-04): ServerCreateRequest had no slug validator at all. The DB
    CHECK constraint (`slug GLOB '[a-z0-9-]*'`) only constrains the FIRST character — GLOB `*`
    matches any sequence of any characters — so 'a_b', 'ab__cd', 'a/../b', 'a b' all passed it.
    ServerRepo.create then did `return await self.get(slug)`, which constructs a ServerRecord
    whose Pydantic validator (db/models.py's SLUG_RE) rejects the same string — AFTER the row
    was already committed. Every subsequent ServerRepo.list() call then raised, permanently
    bricking GET /servers, /stats, aggregate tools/list/discover, and health polling, with no
    way to delete the row via the API since every path that could select it also raised.
    Validating here, before the row is ever written, is the actual fix — see db/repo.py's
    ServerRepo.list() for the defense-in-depth half (skip-and-log instead of propagating, in
    case a bad row exists from some other path).

    This same [a-z0-9-]+ constraint also incidentally closes the '__' aggregate-namespace-
    separator collision the review flagged (argus/aggregate.py's TOOL_NAME_SEPARATOR = '__') —
    underscore was never in this character class, so a slug can never contain '__' once this
    validator actually runs. No separate check needed."""
    if not SLUG_RE.match(slug):
        raise ValueError(f"slug must match [a-z0-9-]+: {slug!r}")
    return slug


def _resolve_host_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Shared by both URL validators: a literal IP is used as-is; a hostname is resolved so
    neither validator can be routed around by DNS pointing a friendly name at a blocked range.
    Returns [] when unresolvable at validation time — callers let a later health probe / send
    attempt surface that failure instead of rejecting registration on a transient DNS blip."""
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass
    try:
        return [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(hostname, None)]
    except (socket.gaierror, ValueError):
        return []


def _validate_upstream_url(url: str) -> str:
    """F17 fix (review 2026-08-04): the HTTP API had NO scheme/host validation on
    upstream_url at all — archon/importer.py validates it for YAML imports, the API path
    didn't, which was its own inconsistency independent of the SSRF half of the finding.

    Full RFC1918/loopback blocking is deliberately NOT applied here: registering a private-LAN
    or localhost upstream (`http://localhost:8010/mcp`, `http://192.168.1.x:8000/mcp`) is this
    product's NORMAL, documented operating mode (see docs/quickstart.md) — a self-hosted MCP
    gateway fronting servers on the same private network. Blocking RFC1918 outright would break
    the primary use case. What IS blocked: the cloud-provider metadata endpoint
    (169.254.169.254) and the rest of the link-local range (169.254.0.0/16) — there is no
    legitimate homelab reason to register one of those, and it's the textbook SSRF payload for
    exfiltrating cloud instance credentials on any deployment that happens to run on EC2/GCE/
    Azure. A hostname that RESOLVES into that range is blocked too, not just a literal IP.

    NOTE: this reasoning does NOT transfer to webhook targets — see _validate_webhook_url below,
    which applies a stricter policy for a fundamentally different trust relationship."""
    parsed = urlparse(url.rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"upstream_url must be a valid http/https URL, got {url!r}")

    hostname = parsed.hostname
    if hostname:
        candidates = _resolve_host_ips(hostname)
        if any(ip.is_link_local for ip in candidates):
            raise ValueError(
                f"upstream_url resolves to a link-local address ({url!r}) — cloud metadata "
                f"endpoints and other 169.254.0.0/16 targets are not permitted"
            )
    return url


def _validate_webhook_url(url: str, *, allow_private: bool = False) -> str:
    """Item 3 (features_08_05_26): deliberately STRICTER than _validate_upstream_url above, and
    the two must not be conflated. An upstream is a thing the operator is knowingly fronting —
    private-LAN is its primary use case. A webhook target is a thing the gateway will POST audit
    data to, unattended, forever; the operator naming a URL once at settings time is a much
    weaker signal than "I registered this MCP server." Default posture: https only, and reject
    loopback/link-local/private/reserved/multicast — i.e. everything ipaddress flags as not a
    normal public unicast address. `allow_private=True` is the explicit opt-in for operators
    genuinely posting to a LAN collector (e.g. their own Slack-compatible relay on the homelab).

    This is pre-flight validation only — it does not close the DNS-rebinding gap (a hostname
    that resolves to a public IP now can resolve to 169.254.169.254 at send time). The dispatcher
    that actually fires requests must also set follow_redirects=False, since a 302 defeats any
    IP check made before the request is sent."""
    parsed = urlparse(url.rstrip("/"))
    if parsed.scheme != "https":
        raise ValueError(f"webhook_url must be https, got {url!r}")
    if not parsed.netloc:
        raise ValueError(f"webhook_url must be a valid https URL, got {url!r}")

    hostname = parsed.hostname
    if hostname and not allow_private:
        candidates = _resolve_host_ips(hostname)
        if any(
            ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast
            for ip in candidates
        ):
            raise ValueError(
                f"webhook_url resolves to a non-public address ({url!r}) — loopback, "
                f"link-local, private (RFC1918), reserved, and multicast targets are blocked by "
                f"default; opt in explicitly if you're posting to a LAN collector"
            )
    return url


class ServerCreateRequest(BaseModel):
    slug: str
    name: str
    upstream_url: str
    enabled: bool = True
    in_aggregate: bool = True
    # F23 fix (review 2026-08-04): a literal Authorization header value for THIS server's
    # upstream, e.g. "Bearer sk-..." or "Basic <base64>". Optional — most homelab MCP servers
    # are unauthenticated on a trusted network. Show-once semantics like API keys aren't
    # practical here (the gateway needs the plaintext on every proxied call), so instead it's
    # simply never returned by GET/list endpoints — see ServerResponse below.
    upstream_auth_header: Optional[str] = None

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: str) -> str:
        return _validate_slug(v)

    @field_validator("upstream_url")
    @classmethod
    def _check_upstream_url(cls, v: str) -> str:
        return _validate_upstream_url(v)


class ServerUpdateRequest(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    enabled: Optional[bool] = None
    in_aggregate: Optional[bool] = None
    # F23: omitting this key from the JSON body means "don't touch it" (checked via
    # `"upstream_auth_header" in body.model_fields_set` in archon/api.py's route handler, wired
    # through to ServerRepo.update's _UNSET sentinel); an explicit `null` means "clear the
    # configured credential". This is why it can't just default to None like the other
    # Optional fields above — None is a meaningful value here, not "field omitted".
    upstream_auth_header: Optional[str] = None

    @field_validator("upstream_url")
    @classmethod
    def _check_upstream_url(cls, v: Optional[str]) -> Optional[str]:
        return _validate_upstream_url(v) if v is not None else v


class ServerResponse(BaseModel):
    slug: str
    name: str
    upstream_url: str
    enabled: bool
    in_aggregate: bool
    upstream_protocol: Optional[str]
    health_status: str
    last_seen_at: Optional[str]
    created_at: str
    updated_at: str
    # F23: whether a credential is configured, WITHOUT ever exposing its value — lets the UI
    # show "credential configured" state without a round-trip that could leak the secret. This
    # stays true whether upstream_auth_header holds a literal or an enterprise #5 reference
    # (vault://..., enc:v1:...) — a reference means "configured" exactly as a literal does.
    has_upstream_auth_header: bool = False
    # Enterprise #5: True when the configured credential is a REFERENCE (vault://, enc:v1:)
    # rather than a literal — never exposes the reference string itself, only this boolean, so
    # the UI can show "externalized" vs "literal" state at a glance without any way to derive
    # the value. False (not just absent) when has_upstream_auth_header is also False — there is
    # no credential to be a reference to.
    upstream_auth_header_is_reference: bool = False
    # Enterprise #5: mirrors servers.health_reason — set only when health_status == "unhealthy"
    # AND the specific cause was a secret-resolution failure (see stoa/health.py's probe_server).
    # Never contains the resolved plaintext credential.
    health_reason: Optional[str] = None


class PolicyResponse(BaseModel):
    mode: str
    rate_limit: Optional[str]
    allowed: list[str]
    denied: list[str]
    param_rules: dict[str, dict[str, ParamRule]]
    dlp_detectors: dict[str, str] = {}
    dlp_custom_patterns: list[DlpCustomPattern] = []


class PolicyUpdateRequest(ServerPolicy):
    pass


class ServerToolResponse(BaseModel):
    name: str
    description: Optional[str]
    status: str  # "allowed" | "denied"
    has_param_rules: bool
    input_schema: Optional[dict] = None


class ServerToolsResponse(BaseModel):
    # Roadmap #6: the tools cache was invisible from the UI — this exposes when it was last
    # refreshed (None if nothing has been fetched yet) alongside the tool list itself, replacing
    # the endpoint's old untyped bare-list response.
    fetched_at: Optional[str]
    tools: list[ServerToolResponse]


class ToolTestRequest(BaseModel):
    tool: str
    arguments: dict = {}


class ToolTestResponse(BaseModel):
    # Feature #1 (in-UI tool tester): mirrors the fields on a real audit row, since the whole
    # point is that this call went through the SAME pipeline a real client's call would.
    decision: str  # ALLOWED | BLOCKED | ERROR
    rule: Optional[str]
    matched: Optional[str]
    reason: Optional[str]
    status_code: Optional[int]
    latency_ms: Optional[int]
    upstream_response: Optional[dict] = None


class KeyCreateRequest(BaseModel):
    name: str
    server_scopes: Optional[list[str]] = None


class KeyCreatedResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    plaintext: str  # only ever present in this one response, at creation time


class KeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    enabled: bool
    server_scopes: Optional[list[str]]
    created_at: str
    last_used_at: Optional[str]


class SettingsResponse(BaseModel):
    auth_mode: str
    aggregate_enabled: bool
    default_ttl_ms: int
    audit_retention_days: int
    setup_complete: bool
    webhook_url: Optional[str]
    webhook_enabled: bool
    webhook_events: list[str]
    webhook_allow_private: bool
    # Whether a signing secret exists — never the secret itself, same has_x pattern as F23's
    # has_upstream_auth_header.
    has_webhook_secret: bool
    # Enterprise #5: which SecretProvider tier is currently active ("local" | "encrypted" |
    # "openbao") — read-only here (selected via the ACROPOLIS_SECRET_PROVIDER env var / process
    # settings, not editable through this API), surfaced purely so the server form can hint
    # which shape of value ("a literal" vs "a vault://... reference") is expected right now.
    secret_provider: str


class SettingsUpdateRequest(BaseModel):
    auth_mode: Optional[str] = None
    aggregate_enabled: Optional[bool] = None
    default_ttl_ms: Optional[int] = None
    audit_retention_days: Optional[int] = None
    # None means "don't touch"; "" means "clear it" (disables webhooks with a dangling URL from
    # ever firing again, since webhook_enabled alone can't be trusted to always be flipped off
    # first). webhook_events is validated against the fixed vocabulary in archon/api.py, not here,
    # so the 400 error message can name the exact bad value. webhook_allow_private is the
    # explicit opt-in named in the plan for operators genuinely posting to a LAN collector — it
    # must be set BEFORE (or in the same request as) a private webhook_url, since validation
    # reads it from the incoming body, not the DB, precisely so it can't be flipped on silently
    # after the fact to justify a URL that was rejected a moment earlier.
    webhook_url: Optional[str] = None
    webhook_enabled: Optional[bool] = None
    webhook_events: Optional[list[str]] = None
    webhook_allow_private: Optional[bool] = None

    @model_validator(mode="after")
    def _check_webhook_url(self) -> "SettingsUpdateRequest":
        if self.webhook_url:
            _validate_webhook_url(self.webhook_url, allow_private=bool(self.webhook_allow_private))
        return self


class WebhookTestResponse(BaseModel):
    ok: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


class ServerHealthSummary(BaseModel):
    slug: str
    health_status: str
    upstream_protocol: Optional[str]


class StatsResponse(BaseModel):
    requests_24h: int
    blocked_24h: int
    allowed_24h: int
    servers_total: int
    servers_healthy: int
    servers_unhealthy: int
    server_health: list[ServerHealthSummary]
    recent_blocked: list[dict]


class AuditEventResponse(BaseModel):
    id: int
    ts: str
    server_slug: Optional[str]
    api_key_id: Optional[int]
    client_ip: Optional[str]
    endpoint: Optional[str]
    rpc_method: Optional[str]
    tool: Optional[str]
    decision: str
    rule: Optional[str]
    matched: Optional[str]
    reason: Optional[str]
    args_summary: Optional[str]
    bridged: bool
    status_code: Optional[int]
    latency_ms: Optional[int]
    origin: Optional[str] = None  # None (normal traffic) | "test" (admin Try-it call)
    dlp_detector: Optional[str] = None  # enterprise #10 — which detector fired, if any
    dlp_action: Optional[str] = None  # "block" | "redact" — never the matched/redacted value
    dlp_match_count: Optional[int] = None


class AdminEventResponse(BaseModel):
    id: int
    ts: str
    actor: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    before: Optional[str] = None
    after: Optional[str] = None
    client_ip: Optional[str] = None
    summary: str


class DriftActionResponse(BaseModel):
    kind: str
    target: str
    detail: str
    description: str


class DriftStatusResponse(BaseModel):
    status: str  # "in_sync" | "drifted" | "unknown" | "error"
    last_check: Optional[float] = None
    last_error: Optional[str] = None
    actions: Optional[list[DriftActionResponse]] = None
    warnings: Optional[list[str]] = None
    errors: Optional[list[str]] = None


class ConfigImportRequest(BaseModel):
    yaml: str
    # Defaults to False so the destructive path is never the accidental one — a client that
    # forgets the flag gets a preview, not a write.
    apply: bool = False


class ConfigImportAction(BaseModel):
    kind: str  # "create" | "update" | "unchanged"
    target: str
    detail: str = ""
    description: str


class ConfigImportResponse(BaseModel):
    applied: bool
    ok: bool
    actions: list[ConfigImportAction]
    warnings: list[str] = []
    errors: list[str] = []


class SetupStatusResponse(BaseModel):
    setup_complete: bool


class SetupRequest(BaseModel):
    admin_password: str
    auth_mode: str = "keyed"


class LoginRequest(BaseModel):
    admin_password: str
    # Bug fix (found in coordinator review of PR #16, 2026-08-07): this field was missing
    # entirely, and archon/setup.py's /login handler was hardcoded to
    # user_repo.get_by_username("admin") regardless of who was actually trying to log in --
    # any locally-created operator/viewer user could never authenticate through the real login
    # route, full stop. Optional, defaulting to "admin", for backward compatibility with the
    # original single-credential form shape (any saved bookmark/script/integration that only
    # ever sent admin_password keeps working unchanged) -- the field name stays
    # "admin_password" for the same reason, even though it now authenticates any user.
    username: str = "admin"


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    auth_source: str
    enabled: bool
    created_at: str
    last_login_at: Optional[str] = None


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    email: Optional[str] = None


class UserRoleUpdateRequest(BaseModel):
    role: str


class UserEnabledUpdateRequest(BaseModel):
    enabled: bool


class CurrentUserResponse(BaseModel):
    """Who the caller is authenticated as — enterprise #1/#2. `user_id` is None for the
    admin-token break-glass path and the legacy pre-migration session, which is itself useful
    signal for the frontend (there's no real "log out" for a bearer token, and the legacy path
    has no user row to show)."""
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: str
    auth_source: str


class OidcStatusResponse(BaseModel):
    enabled: bool
    login_url: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
