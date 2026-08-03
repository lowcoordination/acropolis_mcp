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
