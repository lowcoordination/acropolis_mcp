from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from db.models import ParamRule, ServerPolicy


class ServerCreateRequest(BaseModel):
    slug: str
    name: str
    upstream_url: str
    enabled: bool = True
    in_aggregate: bool = True


class ServerUpdateRequest(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    enabled: Optional[bool] = None
    in_aggregate: Optional[bool] = None


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


class PolicyResponse(BaseModel):
    mode: str
    rate_limit: Optional[str]
    allowed: list[str]
    denied: list[str]
    param_rules: dict[str, dict[str, ParamRule]]


class PolicyUpdateRequest(ServerPolicy):
    pass


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


class SettingsUpdateRequest(BaseModel):
    auth_mode: Optional[str] = None
    aggregate_enabled: Optional[bool] = None
    default_ttl_ms: Optional[int] = None
    audit_retention_days: Optional[int] = None


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


class SetupStatusResponse(BaseModel):
    setup_complete: bool


class SetupRequest(BaseModel):
    admin_password: str
    auth_mode: str = "keyed"


class LoginRequest(BaseModel):
    admin_password: str
