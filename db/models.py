from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, field_validator

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

    def compiled_patterns(self) -> list[re.Pattern]:
        return [re.compile(p, re.IGNORECASE) for p in self.block_patterns]


class ToolPolicy(BaseModel):
    tool_name: str
    action: str  # "allow" | "deny"
    rate_limit: Optional[str] = None


class ServerPolicy(BaseModel):
    mode: str = "passthrough"  # passthrough | allowlist | denylist
    rate_limit: Optional[str] = None
    allowed: list[str] = []
    denied: list[str] = []
    # tool_name -> param_name -> ParamRule
    param_rules: dict[str, dict[str, ParamRule]] = {}


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
