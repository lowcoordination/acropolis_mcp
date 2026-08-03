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

export interface PolicyResponse {
  mode: PolicyMode
  rate_limit: string | null
  allowed: string[]
  denied: string[]
  param_rules: Record<string, Record<string, ParamRule>>
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
}

export interface SetupStatusResponse {
  setup_complete: boolean
}
