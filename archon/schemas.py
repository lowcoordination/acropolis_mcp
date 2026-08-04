from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator

from db.models import ParamRule, ServerPolicy


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
    Azure. A hostname that RESOLVES into that range is blocked too, not just a literal IP."""
    parsed = urlparse(url.rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"upstream_url must be a valid http/https URL, got {url!r}")

    hostname = parsed.hostname
    if hostname:
        try:
            candidates = [ipaddress.ip_address(hostname)]
        except ValueError:
            # Not a literal IP — resolve it so a hostname can't be used to route around the
            # link-local check (DNS pointing a friendly name at 169.254.169.254).
            try:
                candidates = [
                    ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(hostname, None)
                ]
            except (socket.gaierror, ValueError):
                candidates = []  # unresolvable at validation time — let the health poller report it
        if any(ip.is_link_local for ip in candidates):
            raise ValueError(
                f"upstream_url resolves to a link-local address ({url!r}) — cloud metadata "
                f"endpoints and other 169.254.0.0/16 targets are not permitted"
            )
    return url


class ServerCreateRequest(BaseModel):
    slug: str
    name: str
    upstream_url: str
    enabled: bool = True
    in_aggregate: bool = True

    @field_validator("upstream_url")
    @classmethod
    def _check_upstream_url(cls, v: str) -> str:
        return _validate_upstream_url(v)


class ServerUpdateRequest(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    enabled: Optional[bool] = None
    in_aggregate: Optional[bool] = None

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


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
