from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


# Known deliberate exceptions to "all config goes through Settings" — sites that read
# os.environ directly and MUST NOT be folded into this class:
#   - argus/tracing.py (otel_enabled_by_env, build_tracing_manager): tracing must be decided
#     before the OTel SDK loads, which happens before Settings is necessarily constructed.
#   - archon/secrets/encrypted.py (EnvKeySource, build_key_source): the secret provider
#     bootstraps the mechanism that decrypts settings, so it cannot depend on fully-resolved
#     Settings without a circular dependency.
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACROPOLIS_")

    # Enterprise #7 (issue #8): Postgres is a HARD REQUIREMENT. There is no SQLite fallback and
    # no embedded default — the app refuses to start without a reachable Postgres, the same
    # fail-loud-at-boot posture used for a misconfigured secret provider or webhook URL. A
    # data store that silently degrades to "empty but running" is worse than one that won't boot.
    #
    # Typed Optional[str] with a None default rather than a required field so that the error an
    # operator sees is db/database.py's DatabaseNotConfiguredError (which names the variable and
    # points at docs/postgres.md) rather than a pydantic validation traceback at import time.
    database_url: str | None = None

    # data_dir survives the cutover but no longer holds gateway.db/audit.db — nothing in the
    # database layer reads it now. Kept because it is still the documented location for
    # non-database on-disk state (e.g. ACROPOLIS_SECRET_KEY_FILE's default neighbourhood in
    # docs/secrets.md) and removing the setting would break existing deployments' env files for
    # no benefit.
    data_dir: str = "./data"
    host: str = "0.0.0.0"
    port: int = 8000

    # Connection pool sizing. Defaults match db/database.py's; exposed here so an operator
    # running several replicas can keep total connections under the server's max_connections
    # (each replica opens up to writer+reader of these). See docs/postgres.md.
    db_writer_pool_max: int = 5
    db_reader_pool_max: int = 10

    # Rate-limit backend (issue #31). "memory" (default) keeps token buckets in this process,
    # which is correct for the single-replica deployment deploy/k8s currently enforces but means
    # N replicas would each enforce a full independent copy of every limit. "valkey" puts the
    # buckets in one Valkey/Redis all replicas share — required before scaling past 1 replica.
    # Needs the optional extra: pip install 'acropolis[distributed]'.
    rate_limit_backend: str = "memory"
    rate_limit_backend_url: str | None = None

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

    # block_pattern / DLP custom-pattern regex matching (argus/policy.py, issue #106). Both
    # budgets guard the SAME forkserver-isolated match, but measure different things and must
    # stay separate:
    #   - regex_match_timeout_seconds is the ReDoS budget: how long pattern.search() itself may
    #     run once the worker is confirmed alive. Exceeding it means the PATTERN is suspect.
    #   - worker_ready_timeout_seconds is an infrastructure budget: how long the forkserver may
    #     take to fork + bootstrap a worker before it starts matching. Exceeding it means the
    #     HOST/forkserver is the problem, not the pattern. Cold start (first call after process
    #     start) has been measured at ~5x the warm per-call cost, hence the far larger default.
    # Both fail closed (UNDETERMINED -> blocked) on timeout; these only change how much time
    # is given before that happens, never whether a timeout blocks. See docs/policy-cookbook.md.
    regex_match_timeout_seconds: float = 0.5
    worker_ready_timeout_seconds: float = 5.0
