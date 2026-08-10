// Mirrors archon/schemas.py and db/models.py — keep in sync with the backend.

export interface ServerResponse {
  slug: string
  name: string
  upstream_url: string
  enabled: boolean
  in_aggregate: boolean
  upstream_protocol: string | null
  health_status: 'unknown' | 'healthy' | 'unhealthy'
  // Enterprise #5: set only when health_status === 'unhealthy' AND the specific cause was a
  // secret-resolution failure — distinguishable from a plain network-level outage, which
  // leaves this null. Never contains the resolved plaintext credential.
  health_reason: string | null
  last_seen_at: string | null
  created_at: string
  updated_at: string
  // F23: whether a credential is configured at all — true for both a literal and an enterprise
  // #5 reference. Never the value itself.
  has_upstream_auth_header: boolean
  // Enterprise #5: true when the configured credential is a vault://... or enc:v1:... reference
  // rather than a literal — lets the UI show "externalized" vs "literal" without ever exposing
  // the value. Meaningless (false) when has_upstream_auth_header is false.
  upstream_auth_header_is_reference: boolean
  // Enterprise #4 (multi-tenancy): the project this server belongs to.
  project_id: number | null
  project_slug: string | null
}

export interface ServerCreateRequest {
  slug: string
  name: string
  upstream_url: string
  enabled?: boolean
  in_aggregate?: boolean
  // Enterprise #5: either a literal Authorization header value or a vault://<mount>/<path>#<key>
  // reference — never returned back by any GET/list response, see ServerResponse above.
  upstream_auth_header?: string
  // Enterprise #4: defaults server-side to "default" when omitted.
  project_slug?: string
}

export interface ServerUpdateRequest {
  name?: string
  upstream_url?: string
  enabled?: boolean
  in_aggregate?: boolean
  // Omit the key entirely to leave the credential untouched; explicit null clears it; any other
  // value replaces it (literal or vault:// reference) — mirrors archon/schemas.py's
  // ServerUpdateRequest three-state handling (see that model's comment on model_fields_set).
  upstream_auth_header?: string | null
}

export interface ParamRule {
  max_length?: number | null
  block_patterns: string[]
  max_value?: number | null
  min_value?: number | null
  denied: boolean
}

export type PolicyMode = 'passthrough' | 'allowlist' | 'denylist'

// Enterprise #10 (DLP). Keep in sync with argus/dlp.py's BUILTIN_DETECTORS and
// db/models.py's _VALID_DLP_DETECTOR_NAMES.
export type DlpDetectorName =
  | 'credit_card'
  | 'email'
  | 'us_ssn'
  | 'aws_access_key'
  | 'private_key_pem'
  | 'high_entropy_string'

export type DlpAction = 'allow' | 'redact' | 'block'

export const DLP_DETECTORS: { name: DlpDetectorName; label: string }[] = [
  { name: 'credit_card', label: 'Credit card number (Luhn-validated)' },
  { name: 'email', label: 'Email address' },
  { name: 'us_ssn', label: 'US Social Security Number' },
  { name: 'aws_access_key', label: 'AWS access key ID' },
  { name: 'private_key_pem', label: 'PEM private key header' },
  { name: 'high_entropy_string', label: 'Generic high-entropy string (likely a secret)' },
]

export interface DlpCustomPattern {
  name: string
  pattern: string
  action: DlpAction
}

export interface PolicyResponse {
  mode: PolicyMode
  rate_limit: string | null
  allowed: string[]
  denied: string[]
  param_rules: Record<string, Record<string, ParamRule>>
  dlp_detectors: Record<string, DlpAction>
  dlp_custom_patterns: DlpCustomPattern[]
}

export type QuotaPeriod = 'day' | 'month'

export interface KeyResponse {
  id: number
  name: string
  key_prefix: string
  enabled: boolean
  server_scopes: string[] | null
  created_at: string
  last_used_at: string | null
  // Enterprise #11: nullable, null = unlimited (the default) — see docs/quotas.md.
  quota_calls: number | null
  quota_period: QuotaPeriod | null
  // Enterprise #4 (multi-tenancy): the project this key belongs to.
  project_id: number | null
  project_slug: string | null
}

export interface KeyCreatedResponse {
  id: number
  name: string
  key_prefix: string
  plaintext: string
}

export interface UsageBucketResponse {
  api_key_id: number | null
  key_prefix: string | null
  server_id: number | null
  server_slug: string | null
  tool: string | null
  calls: number
}

export interface UsageResponse {
  period: 'day' | 'month' | 'all'
  since: string | null
  buckets: UsageBucketResponse[]
}

export interface SettingsResponse {
  auth_mode: 'open' | 'keyed'
  aggregate_enabled: boolean
  default_ttl_ms: number
  audit_retention_days: number
  setup_complete: boolean
  webhook_url: string | null
  webhook_enabled: boolean
  webhook_events: string[]
  webhook_allow_private: boolean
  has_webhook_secret: boolean
  // Enterprise #5: which SecretProvider tier is active — read-only, informational (hints which
  // shape of value the server form should expect: a literal under 'local'/'encrypted', a
  // vault://... reference under 'openbao').
  secret_provider: 'local' | 'encrypted' | 'openbao' | string
  // Enterprise #9: approval workflows — off by default.
  approvals_enabled: boolean
  approvals_ttl_days: number
}

export interface WebhookTestResponse {
  ok: boolean
  status_code: number | null
  error: string | null
}

export interface TracingStatusResponse {
  // Enterprise #9: whether ACROPOLIS_OTEL_ENABLED was set at process startup.
  enabled: boolean
  // Additionally requires the `otel` optional dependency group to have actually been
  // importable — can be false even when `enabled` is true (operator flipped the gate on a
  // base install without the extra). See docs/observability.md.
  active: boolean
  sample_ratio: number
}

export interface ServerHealthSummary {
  slug: string
  health_status: string
  upstream_protocol: string | null
}

export interface StatsResponse {
  requests_24h: number
  blocked_24h: number
  allowed_24h: number
  servers_total: number
  servers_healthy: number
  servers_unhealthy: number
  server_health: ServerHealthSummary[]
  recent_blocked: AuditEvent[]
}

export interface AuditEvent {
  id: number
  ts: string
  server_slug: string | null
  api_key_id: number | null
  client_ip: string | null
  endpoint: string | null
  rpc_method: string | null
  tool: string | null
  decision: 'ALLOWED' | 'BLOCKED' | 'PASSTHROUGH' | 'ERROR'
  rule: string | null
  matched: string | null
  reason: string | null
  args_summary: string | null
  bridged: boolean
  status_code: number | null
  latency_ms: number | null
  dlp_detector: string | null
  dlp_action: DlpAction | null
  dlp_match_count: number | null
}

export interface SetupStatusResponse {
  setup_complete: boolean
}

export interface JsonSchemaProperty {
  type?: string
  title?: string
  description?: string
  default?: unknown
  enum?: unknown[]
}

export interface JsonSchema {
  type?: string
  properties?: Record<string, JsonSchemaProperty>
  required?: string[]
}

export interface ServerTool {
  name: string
  description: string | null
  status: 'allowed' | 'denied'
  has_param_rules: boolean
  input_schema: JsonSchema | null
}

export interface ToolTestResponse {
  decision: string
  rule: string | null
  matched: string | null
  reason: string | null
  status_code: number | null
  latency_ms: number | null
  upstream_response: Record<string, unknown> | null
}

export interface ServerToolsResponse {
  fetched_at: string | null
  tools: ServerTool[]
}

export interface ConfigImportAction {
  kind: 'create' | 'update' | 'unchanged'
  target: string
  detail: string
  description: string
}

export interface ConfigImportResponse {
  applied: boolean
  ok: boolean
  actions: ConfigImportAction[]
  warnings: string[]
  errors: string[]
}

// Enterprise #1/#2: identity + RBAC. Mirrors archon/schemas.py's User*/CurrentUser*/OidcStatus
// response models and archon/rbac.py's role set.
export type Role = 'viewer' | 'operator' | 'admin'

// Rank order mirrors archon/rbac.py's ROLE_RANK — kept here too so the frontend can do
// role-aware UI hiding without a round trip. This is a COURTESY only; the server is the real
// enforcement boundary (see require_role in archon/rbac.py) and every mutating call still gets
// a real 403 from the backend if this table is ever wrong or bypassed.
export const ROLE_RANK: Record<Role, number> = { viewer: 10, operator: 20, admin: 30 }

export function hasRole(current: Role | undefined, minimum: Role): boolean {
  if (!current) return false
  return ROLE_RANK[current] >= ROLE_RANK[minimum]
}

export interface UserResponse {
  id: number
  username: string
  email: string | null
  role: Role
  auth_source: 'local' | 'oidc'
  enabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface UserCreateRequest {
  username: string
  password: string
  role: Role
  email?: string
}

export interface CurrentUserResponse {
  user_id: number | null
  username: string | null
  role: Role
  auth_source: string
}

export interface OidcStatusResponse {
  enabled: boolean
  login_url: string | null
}

// Enterprise #4 (multi-tenancy, issue #5). A SEPARATE role space from the global `Role` above —
// see archon/project_rbac.py's module docstring for why 'poweruser' here has no relationship to
// global 'operator' beyond playing the analogous middle tier. Never compare a ProjectRole and a
// Role directly; they are different rank spaces.
export type ProjectRole = 'viewer' | 'poweruser' | 'admin'

export const PROJECT_ROLE_RANK: Record<ProjectRole, number> = { viewer: 10, poweruser: 20, admin: 30 }

export function hasProjectRole(current: ProjectRole | undefined, minimum: ProjectRole): boolean {
  if (!current) return false
  return PROJECT_ROLE_RANK[current] >= PROJECT_ROLE_RANK[minimum]
}

export interface ProjectResponse {
  id: number
  slug: string
  name: string
  created_at: string
}

export interface ProjectCreateRequest {
  slug: string
  name: string
}

export interface ProjectMemberResponse {
  user_id: number
  username: string
  role: ProjectRole
}

export interface ProjectMemberUpsertRequest {
  user_id: number
  role: ProjectRole
}

// Enterprise #9 (issue #10): approval workflows. A proposal is a queued policy-shaped change
// awaiting a SECOND admin's approval. The list/detail views only ever carry identity + state;
// the detail view additionally carries the RECOMPUTED preview (archon/approvals.py's
// preview()) so an approver never sees a stored stale diff.
export type ProposalTargetType = 'server_policy' | 'config_import'
export type ProposalState = 'pending' | 'approved' | 'rejected' | 'expired'

export interface ProposalResponse {
  id: number
  target_type: ProposalTargetType
  target_id: string
  proposer: string
  state: ProposalState
  created_at: string
  resolved_at: string | null
  resolver: string | null
  resolution_reason: string | null
}

export interface ProposalDetailResponse extends ProposalResponse {
  preview: string[]
  stale: boolean
}

// The body a queued write returns (202) instead of its normal 200 shape when approvals are on.
export interface ProposalPendingResponse {
  proposal_id: number
  state: ProposalState
  message: string
}
