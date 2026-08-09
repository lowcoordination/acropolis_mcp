from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACROPOLIS_")

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

    # Background health/discover polling of registered servers (stoa.health.HealthPoller).
    # Disabled by default in the test suite (see tests fixtures) — a fully autonomous poller
    # racing a test's own short-lived requests against the same fixture upstream is a source
    # of flaky failures that don't reflect anything wrong with the gateway itself.
    health_poll_enabled: bool = True
    health_poll_interval_seconds: float = 60.0

    # Background audit-log pruning (stoa.retention.AuditRetentionJob). The retention WINDOW
    # itself (settings.audit_retention_days) is DB-backed and editable from the Settings page —
    # this flag/interval only control whether and how often the job checks; disabled by default
    # in the test suite for the same reason health_poll_enabled is.
    audit_retention_enabled: bool = True
    audit_retention_check_interval_seconds: float = 3600.0

    # Enterprise #5: pluggable secret backends. "local" (default) is byte-identical to
    # pre-feature behaviour — `upstream_auth_header` is read/written as a literal, no
    # resolution step at all. "encrypted" and "openbao" resolve a reference
    # (`enc:v1:...` / `vault://...#...`) to its plaintext at call time — see
    # archon/secrets/__init__.py's build_secret_provider() and docs/secrets.md.
    secret_provider: str = "local"

    # encrypted provider key sourcing (ACROPOLIS_SECRET_KEY / ACROPOLIS_SECRET_KEY_FILE) is read
    # directly from os.environ by archon/secrets/encrypted.py rather than modeled as a Settings
    # field — deliberately, so the raw key material never round-trips through a pydantic model
    # that could end up in a repr(), a debug log, or (if this class were ever serialized for
    # any reason) a dumped settings snapshot. Settings fields below are the non-secret ones.

    # openbao provider (a generic Vault KV v2 client — see archon/secrets/openbao.py's module
    # docstring on why "openbao" here names a wire protocol, not a specific product).
    vault_addr: str | None = None
    # vault_token is Optional[str] like admin_token above: real deployments should prefer the
    # ACROPOLIS_VAULT_TOKEN env var over a checked-in default, but pydantic-settings already
    # reads env vars for every field on this model via env_prefix, so this field IS how
    # ACROPOLIS_VAULT_TOKEN gets in — there's no separate raw os.environ read here the way the
    # encrypted provider's key is handled, since a Vault token is inherently short-lived /
    # revocable (unlike a data-encryption key, leaking it is a rotate-and-move-on event, not a
    # rewrite-every-secret event), so the same care doesn't apply.
    vault_token: str | None = None
    vault_role_id: str | None = None
    vault_secret_id: str | None = None
    vault_ttl_seconds: float = 60.0
