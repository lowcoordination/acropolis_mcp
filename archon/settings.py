from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARGUS_")

    data_dir: str = "./data"
    host: str = "0.0.0.0"
    port: int = 8000

    # "open" = no API key required (trusted LAN); "keyed" = Bearer key required on /mcp/*
    auth_mode: str = "keyed"

    # Admin bearer token for the /api/v1 control plane. If unset, a first-run wizard
    # (M3) is expected to set one; M1 falls back to this env var only.
    admin_token: str | None = None

    max_body_bytes: int = 1_000_000
    upstream_timeout_seconds: float = 120.0
