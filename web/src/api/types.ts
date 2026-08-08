// Mirrors archon/schemas.py and db/models.py — keep in sync with the backend.

export interface ServerResponse {
  slug: string
  name: string
  upstream_url: string
  enabled: boolean
  in_aggregate: boolean
  upstream_protocol: string | null
  health_status: 'unknown' | 'healthy' | 'unhealthy'
  last_seen_at: string | null
  created_at: string
  updated_at: string
}

export interface ServerCreateRequest {
  slug: string
  name: string
  upstream_url: string
  enabled?: boolean
  in_aggregate?: boolean
}

export interface ServerUpdateRequest {
  name?: string
  upstream_url?: string
  enabled?: boolean
  in_aggregate?: boolean
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

export interface KeyResponse {
  id: number
  name: string
  key_prefix: string
  enabled: boolean
  server_scopes: string[] | null
  created_at: string
  last_used_at: string | null
}

export interface KeyCreatedResponse {
  id: number
  name: string
  key_prefix: string
  plaintext: string
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
}

export interface WebhookTestResponse {
  ok: boolean
  status_code: number | null
  error: string | null
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
