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
    # Enterprise #4 (multi-tenancy, issue #5): which project this server belongs to, by slug.
    # Optional in the request shape — omitted (or "default") targets the backfilled default
    # project, so an existing integration/script that never heard of projects keeps working
    # unchanged. archon/api.py resolves this to a project_id and 404s on an unknown slug.
    project_slug: str = "default"

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
    # Enterprise #4 (multi-tenancy): the project this server belongs to. project_slug is what
    # the frontend renders (a project column/filter needs the human-readable slug, not a bare
    # id); project_id rides along for API clients that want the stable numeric key.
    project_id: Optional[int] = None
    project_slug: Optional[str] = None


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


# Security-scan finding: SQLite's INTEGER column is a 64-bit signed value; a quota_calls sent
# as an arbitrary-precision Python int (Pydantic's bare `int` type has no upper bound) would
# pass model validation, reach ApiKeyRepo.create/set_quota, and raise an unhandled
# OverflowError on the INSERT/UPDATE — caught by the app's global exception handler (so this
# was never a crash or an information leak, just an ugly 500 where a clean 422 belongs). This
# cap is deliberately generous — orders of magnitude above any real quota an operator would
# configure — while still comfortably inside SQLite's 64-bit range with room to spare.
_MAX_QUOTA_CALLS = 1_000_000_000


def _validate_quota_pairing(quota_calls: Optional[int], quota_period: Optional[str]) -> None:
    """Shared by KeyCreateRequest and KeyQuotaUpdateRequest (self-review fix: this validation
    was duplicated near-verbatim across both models — a single source avoids the two drifting
    apart the next time one of them changes). A quota_calls with no quota_period (or vice
    versa) is a half-configured, ambiguous state — reject it at the API boundary rather than
    let it reach the DB as a row db/models.py's ApiKeyRecord would itself refuse to construct
    on the way back out."""
    if (quota_calls is None) != (quota_period is None):
        raise ValueError("quota_calls and quota_period must be set together, or both omitted")
    if quota_calls is not None and quota_calls <= 0:
        raise ValueError("quota_calls must be a positive integer")
    if quota_calls is not None and quota_calls > _MAX_QUOTA_CALLS:
        raise ValueError(f"quota_calls must not exceed {_MAX_QUOTA_CALLS}")
    if quota_period is not None and quota_period not in ("day", "month"):
        raise ValueError("quota_period must be 'day' or 'month'")


class KeyCreateRequest(BaseModel):
    name: str
    server_scopes: Optional[list[str]] = None
    # Enterprise #11: both nullable, both default None = unlimited (the off-by-default
    # regression-guard this codebase applies to every optional feature — see
    # tests/integration/test_quotas.py::TestNoQuotaConfiguredIsUnchangedBehavior).
    quota_calls: Optional[int] = None
    quota_period: Optional[str] = None  # "day" | "month"
    # Enterprise #4 (multi-tenancy, issue #5): same default-to-"default" shape as
    # ServerCreateRequest.project_slug — a key minted with no project_slug lands in the
    # backfilled default project, matching pre-feature behavior on a single-project instance.
    project_slug: str = "default"

    @model_validator(mode="after")
    def _quota_fields_are_paired(self) -> "KeyCreateRequest":
        _validate_quota_pairing(self.quota_calls, self.quota_period)
        return self


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
    quota_calls: Optional[int] = None
    quota_period: Optional[str] = None
    project_id: Optional[int] = None
    project_slug: Optional[str] = None


class KeyQuotaUpdateRequest(BaseModel):
    """Body for PATCH /keys/{id}/quota. A separate request model (rather than folding onto the
    existing `enabled: bool` query-param PATCH /keys/{id}) because that route is unusual in
    this codebase already (a bare query param, not a body) and quota is a materially different
    kind of update (two fields, paired, admin-audited with its own action name) — keeping it a
    distinct route/model avoids overloading one PATCH handler with two unrelated shapes of
    partial update."""
    quota_calls: Optional[int] = None
    quota_period: Optional[str] = None

    @model_validator(mode="after")
    def _quota_fields_are_paired(self) -> "KeyQuotaUpdateRequest":
        _validate_quota_pairing(self.quota_calls, self.quota_period)
        return self


class UsageBucketResponse(BaseModel):
    """One aggregated usage row — already summed over whatever period the query requested
    (day/month/all), NOT a raw hourly bucket (see UsageRepo.query's docstring on why raw
    buckets are stored but callers usually want them summed)."""
    api_key_id: Optional[int]
    key_prefix: Optional[str] = None  # populated when api_key_id is a real key; never the hash/plaintext
    server_id: Optional[int]
    server_slug: Optional[str] = None
    tool: Optional[str]
    calls: int


class UsageResponse(BaseModel):
    period: str  # "day" | "month" | "all"
    since: Optional[str]
    buckets: list[UsageBucketResponse]


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
    # Enterprise #9: approval workflows. approvals_enabled defaults to false (off by default —
    # disabled is byte-identical to pre-feature behaviour); approvals_ttl_days is how long a
    # pending proposal lives before the expiry sweep marks it expired (default 7).
    approvals_enabled: bool
    approvals_ttl_days: int


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
    # Enterprise #9: approval workflows. approvals_ttl_days is validated > 0 in the route
    # handler (same place audit_retention_days' range check lives) so the 400 can name the bad
    # value; <= 0 at expiry time means "keep forever", matching audit_retention_days' opt-out.
    approvals_enabled: Optional[bool] = None
    approvals_ttl_days: Optional[int] = None

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


class TracingStatusResponse(BaseModel):
    """Enterprise #9. Deliberately tiny and read-only, same posture as DriftStatusResponse —
    just enough for the Settings page to show an operator whether tracing is actually active,
    never any span content or exporter destination detail (the OTLP endpoint is standard-env-var
    configured, sourced from process environment, not something this API echoes back)."""

    enabled: bool  # ACROPOLIS_OTEL_ENABLED, as read at process startup
    active: bool  # enabled AND the `otel` extra was actually importable (TracingManager.active)
    sample_ratio: float


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


class ProposalPendingResponse(BaseModel):
    """Body of the 202 a write path returns when approvals are enabled and the change was
    queued instead of applied — the shape PUT /servers/{slug}/policy and POST /config/import
    take on instead of their normal 200 bodies. Deliberately tiny: just the proposal id and
    state; everything else lives under /proposals/{id}."""
    proposal_id: int
    state: str = "pending"
    message: str = "change queued for approval"


class ProposalResponse(BaseModel):
    """One proposal row as surfaced by GET /proposals. Identity fields only — the payload
    (policy/YAML intent) is deliberately NOT in the list view; GET /proposals/{id} is where the
    recomputed preview lives, admin-gated like everything here."""
    id: int
    target_type: str  # 'server_policy' | 'config_import'
    target_id: str
    proposer: str
    state: str  # pending | approved | rejected | expired
    created_at: str
    resolved_at: Optional[str] = None
    resolver: Optional[str] = None
    resolution_reason: Optional[str] = None
    # Remediation (review 2026-08-10): None for a 'config_import' proposal (instance-wide by
    # design), the target server's project for a 'server_policy' proposal. See
    # 0012_proposals_project_scope.sql's header.
    project_id: Optional[int] = None


class ProposalDetailResponse(ProposalResponse):
    """GET /proposals/{id}: the proposal plus its RECOMPUTED preview (never a stored stale
    diff — see archon/approvals.py's preview()). `stale` tells the approver up front whether
    approve() will refuse with "state changed, re-review"."""
    preview: list[str]
    stale: bool


class ProposalApproveRequest(BaseModel):
    reason: Optional[str] = None


class ProposalRejectRequest(BaseModel):
    reason: Optional[str] = None


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


# --- Enterprise #4 (multi-tenancy, issue #5) ---------------------------------------------------

class ProjectCreateRequest(BaseModel):
    slug: str
    name: str

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: str) -> str:
        return _validate_slug(v)


class ProjectResponse(BaseModel):
    id: int
    slug: str
    name: str
    created_at: str


class ProjectMemberResponse(BaseModel):
    """One membership row, with the username/email joined in for display — a bare user_id would
    force the frontend into a second round-trip against GET /users (admin-only, and a project
    admin who is NOT a global admin/user-manager has no access to that route at all) just to
    render a member list."""
    user_id: int
    username: str
    role: str  # viewer | poweruser | admin


class ProjectMemberUpsertRequest(BaseModel):
    """Add a member or change an existing member's role — same route either way (idempotent
    upsert on the (user_id, project_id) primary key), mirroring project_members' own PK shape
    rather than having separate add/update routes for what the DB already treats as one
    operation."""
    user_id: int
    role: str

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str) -> str:
        from archon.project_rbac import is_valid_project_role

        if not is_valid_project_role(v):
            raise ValueError(f"role must be one of viewer, poweruser, admin, got {v!r}")
        return v
