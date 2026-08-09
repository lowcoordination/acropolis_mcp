"""Export/import Acropolis's own configuration as a single reviewable YAML file.

Distinct from the WAL-safe `sqlite3 .backup` procedure in docs/backup-and-upgrades.md: that is
*disaster recovery* (a binary snapshot of everything, including secrets and the audit log); this
is *configuration as reviewable text* — the servers, policies, and gateway settings you'd want to
diff in a code review or replay onto a fresh instance when migrating compose -> k8s.

Serialization lives here rather than in the route layer so the HTTP API and the CLI
(`python -m argus export` / `import-config`) share one implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from archon.schemas import _validate_upstream_url
from db.database import utcnow
from db.models import ServerPolicy
from db.repo import ServerNotFoundError, ServerRepo, SettingsRepo

EXPORT_VERSION = 1

# Allowlist, deliberately — NOT a denylist of known secrets. The settings table also holds
# `session_secret` and `admin_password_hash`, and dumping the table minus a hardcoded blocklist
# would silently start exporting any FUTURE secret someone adds. Enumerating what may leave is
# the only shape that stays safe as the schema grows.
EXPORTABLE_SETTINGS = ("auth_mode", "aggregate_enabled", "default_ttl_ms", "audit_retention_days")

_NO_API_KEYS_NOTE = (
    "API keys are deliberately NOT exported: they are stored only as hashes (show-once by "
    "design), so exporting them would be useless to restore from and a liability to hold. "
    "Recreate keys through the UI or API after importing."
)

_CREDENTIALS_WARNING = (
    "WARNING: this file was exported with include_credentials=true and contains PLAINTEXT "
    "upstream credentials (upstream_auth_header). Treat it as a secret: do not commit it to "
    "version control, and delete it once imported."
)


@dataclass
class ExportResult:
    data: dict[str, Any]
    warnings: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        header = [f"# Acropolis configuration export (version {EXPORT_VERSION})", f"# {_NO_API_KEYS_NOTE}"]
        # The credentials warning goes INTO the file, not just the HTTP response, because the
        # file is what gets emailed around and committed by mistake later.
        if any(w.startswith("WARNING:") for w in self.warnings):
            header.append(f"#\n# {_CREDENTIALS_WARNING}")
        body = yaml.safe_dump(self.data, sort_keys=False, default_flow_style=False)
        return "\n".join(header) + "\n\n" + body

    def to_stable_yaml(self) -> str:
        """Export without the exported_at timestamp — for committed exports that should be
        byte-identical when the config hasn't changed. Used by GitOps drift detection."""
        data = dict(self.data)
        data.pop("exported_at", None)
        header = [f"# Acropolis configuration export (version {EXPORT_VERSION})", f"# {_NO_API_KEYS_NOTE}"]
        if any(w.startswith("WARNING:") for w in self.warnings):
            header.append(f"#\n# {_CREDENTIALS_WARNING}")
        body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
        return "\n".join(header) + "\n\n" + body


@dataclass
class ImportAction:
    kind: str  # "create" | "update" | "unchanged"
    target: str  # human-readable subject, e.g. "server 'shell'"
    detail: str = ""

    def describe(self, applied: bool = False) -> str:
        """`applied` switches the verb from subjunctive to past tense. Same action objects are
        produced whether previewing or writing — only the wording differs — so a preview can
        never describe something different from what the write actually did."""
        verbs = (
            {"create": "created", "update": "updated", "unchanged": "unchanged"}
            if applied
            else {"create": "would create", "update": "would update", "unchanged": "unchanged"}
        )
        return f"{verbs[self.kind]} {self.target}{f' ({self.detail})' if self.detail else ''}"


@dataclass
class ImportPlan:
    actions: list[ImportAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


async def export_config(
    server_repo: ServerRepo,
    settings_repo: SettingsRepo,
    include_credentials: bool = False,
) -> ExportResult:
    """Build the versioned export envelope.

    `upstream_auth_header` (F23) is a LIVE credential in plaintext, so it is omitted by default
    and the affected servers are named in a warning — an operator who reimports this file needs
    to know it is incomplete rather than discovering it when an upstream starts 401ing.
    """
    result = ExportResult(data={})
    servers_out: list[dict[str, Any]] = []
    servers_with_credentials: list[str] = []

    for server in await server_repo.list():
        policy = await server_repo.get_policy(server.id)
        entry: dict[str, Any] = {
            "slug": server.slug,
            "name": server.name,
            "upstream_url": server.upstream_url,
            "enabled": server.enabled,
            "in_aggregate": server.in_aggregate,
            # mode='exclude none' keeps optional param-rule fields out unless actually set, so
            # the file stays diffable instead of full of `max_value: null` noise.
            "policy": policy.model_dump(exclude_none=True),
        }
        if server.upstream_auth_header is not None:
            servers_with_credentials.append(server.slug)
            if include_credentials:
                entry["upstream_auth_header"] = server.upstream_auth_header
        servers_out.append(entry)

    stored = await settings_repo.get_all()
    settings_out = {k: stored[k] for k in EXPORTABLE_SETTINGS if k in stored}

    result.data = {
        "version": EXPORT_VERSION,
        "exported_at": utcnow(),
        "settings": settings_out,
        "servers": servers_out,
    }

    if servers_with_credentials:
        if include_credentials:
            result.warnings.append(_CREDENTIALS_WARNING)
        else:
            result.warnings.append(
                "upstream credentials were NOT exported for: "
                + ", ".join(sorted(servers_with_credentials))
                + ". Re-enter them after importing, or re-export with include_credentials=true."
            )

    return result


def _policy_diff(current: ServerPolicy, incoming: ServerPolicy) -> list[str]:
    """Human-readable field-level deltas, so the operator sees WHAT changes, not just that
    something does."""
    deltas: list[str] = []
    if current.mode != incoming.mode:
        deltas.append(f"mode: {current.mode} -> {incoming.mode}")
    if current.rate_limit != incoming.rate_limit:
        deltas.append(f"rate_limit: {current.rate_limit or 'none'} -> {incoming.rate_limit or 'none'}")
    if sorted(current.allowed) != sorted(incoming.allowed):
        deltas.append(f"allowed: {len(current.allowed)} -> {len(incoming.allowed)} tool(s)")
    if sorted(current.denied) != sorted(incoming.denied):
        deltas.append(f"denied: {len(current.denied)} -> {len(incoming.denied)} tool(s)")
    if current.param_rules != incoming.param_rules:
        deltas.append(
            f"param_rules: {len(current.param_rules)} -> {len(incoming.param_rules)} tool(s) with rules"
        )
    # Enterprise #10 (DLP) — kept in sync with archon/admin_audit.py's copy of this function
    # (see that module's docstring on why this is duplicated rather than imported).
    if current.dlp_detectors != incoming.dlp_detectors:
        deltas.append(
            f"dlp_detectors: {len(current.dlp_detectors)} -> {len(incoming.dlp_detectors)} configured"
        )
    if current.dlp_custom_patterns != incoming.dlp_custom_patterns:
        deltas.append(
            f"dlp_custom_patterns: {len(current.dlp_custom_patterns)} -> "
            f"{len(incoming.dlp_custom_patterns)} configured"
        )
    return deltas


@dataclass
class _ParsedServer:
    slug: str
    name: str
    upstream_url: str
    enabled: bool
    in_aggregate: bool
    policy: ServerPolicy
    upstream_auth_header: Optional[str]


def _parse(yaml_text: str) -> tuple[list[_ParsedServer], dict[str, str], list[str]]:
    """Parse + validate without touching the DB. Returns (servers, settings, errors)."""
    errors: list[str] = []
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return [], {}, [f"could not parse YAML: {e}"]

    if not isinstance(data, dict):
        return [], {}, ["export file must be a YAML mapping at the top level"]

    version = data.get("version")
    if version != EXPORT_VERSION:
        # Refuse rather than guess: a future version may mean something different by the same
        # key, and silently importing it would corrupt config in ways that look like it worked.
        return [], {}, [
            f"unsupported export version {version!r} (this build understands version {EXPORT_VERSION})"
        ]

    raw_settings = data.get("settings") or {}
    settings: dict[str, str] = {}
    if isinstance(raw_settings, dict):
        for key, value in raw_settings.items():
            if key not in EXPORTABLE_SETTINGS:
                # Same allowlist on the way in as on the way out — an edited file must not be
                # able to write admin_password_hash or session_secret.
                errors.append(f"setting '{key}' is not importable (allowed: {', '.join(EXPORTABLE_SETTINGS)})")
                continue
            settings[key] = str(value)
    else:
        errors.append("'settings' must be a mapping")

    servers: list[_ParsedServer] = []
    raw_servers = data.get("servers") or []
    if not isinstance(raw_servers, list):
        return [], settings, errors + ["'servers' must be a list"]

    for index, raw in enumerate(raw_servers):
        if not isinstance(raw, dict):
            errors.append(f"servers[{index}]: must be a mapping")
            continue
        slug = raw.get("slug")
        if not slug:
            errors.append(f"servers[{index}]: missing 'slug'")
            continue

        upstream_url = raw.get("upstream_url")
        if not upstream_url:
            errors.append(f"server '{slug}': missing 'upstream_url'")
            continue
        try:
            # F17's SSRF guard, reused verbatim. The review specifically flagged that the API
            # validated upstream URLs while the importer did not; an imported file must not be
            # able to register an upstream the API itself would reject.
            upstream_url = _validate_upstream_url(upstream_url)
        except ValueError as e:
            errors.append(f"server '{slug}': {e}")
            continue

        try:
            policy = ServerPolicy(**(raw.get("policy") or {}))
        except Exception as e:
            errors.append(f"server '{slug}': invalid policy: {e}")
            continue

        servers.append(
            _ParsedServer(
                slug=slug,
                name=raw.get("name") or slug,
                upstream_url=upstream_url,
                enabled=bool(raw.get("enabled", True)),
                in_aggregate=bool(raw.get("in_aggregate", True)),
                policy=policy,
                upstream_auth_header=raw.get("upstream_auth_header"),
            )
        )

    return servers, settings, errors


async def plan_import(
    server_repo: ServerRepo,
    settings_repo: SettingsRepo,
    yaml_text: str,
    apply: bool = False,
) -> ImportPlan:
    """Compute (and optionally apply) the delta between an export file and current state.

    Import is destructive, so `apply` defaults to False: the same call that previews is the one
    that writes, which keeps the preview honest — there is no second code path that could drift
    from what was shown.
    """
    plan = ImportPlan()
    servers, settings, errors = _parse(yaml_text)
    plan.errors.extend(errors)

    if plan.errors:
        # Never half-apply. If any entry is invalid the whole file is rejected, so the operator
        # can't end up with three of five servers imported and no clear way back.
        return plan

    for parsed in servers:
        try:
            existing = await server_repo.get(parsed.slug)
        except ServerNotFoundError:
            existing = None

        if existing is None:
            plan.actions.append(
                ImportAction("create", f"server '{parsed.slug}'", f"-> {parsed.upstream_url}")
            )
            if apply:
                created = await server_repo.create(
                    slug=parsed.slug, name=parsed.name, upstream_url=parsed.upstream_url,
                    enabled=parsed.enabled, in_aggregate=parsed.in_aggregate,
                    upstream_auth_header=parsed.upstream_auth_header,
                )
                await server_repo.set_policy(created.id, parsed.policy)
            continue

        field_deltas: list[str] = []
        if existing.upstream_url != parsed.upstream_url:
            field_deltas.append(f"upstream_url: {existing.upstream_url} -> {parsed.upstream_url}")
        if existing.name != parsed.name:
            field_deltas.append(f"name: {existing.name} -> {parsed.name}")
        if existing.enabled != parsed.enabled:
            field_deltas.append(f"enabled: {existing.enabled} -> {parsed.enabled}")
        if existing.in_aggregate != parsed.in_aggregate:
            field_deltas.append(f"in_aggregate: {existing.in_aggregate} -> {parsed.in_aggregate}")

        current_policy = await server_repo.get_policy(existing.id)
        field_deltas.extend(_policy_diff(current_policy, parsed.policy))

        if parsed.upstream_auth_header is not None:
            field_deltas.append("upstream_auth_header: (set from file)")

        if field_deltas:
            plan.actions.append(
                ImportAction("update", f"server '{parsed.slug}'", "; ".join(field_deltas))
            )
            if apply:
                await server_repo.update(
                    slug=parsed.slug, name=parsed.name, upstream_url=parsed.upstream_url,
                    enabled=parsed.enabled, in_aggregate=parsed.in_aggregate,
                    **({"upstream_auth_header": parsed.upstream_auth_header}
                       if parsed.upstream_auth_header is not None else {}),
                )
                await server_repo.set_policy(existing.id, parsed.policy)
        else:
            plan.actions.append(ImportAction("unchanged", f"server '{parsed.slug}'"))

    if settings:
        stored = await settings_repo.get_all()
        changed = {k: v for k, v in settings.items() if stored.get(k) != v}
        if changed:
            plan.actions.append(
                ImportAction(
                    "update", "gateway settings",
                    "; ".join(f"{k}: {stored.get(k, 'unset')} -> {v}" for k, v in sorted(changed.items())),
                )
            )
            if apply:
                await settings_repo.set_many(changed)
        else:
            plan.actions.append(ImportAction("unchanged", "gateway settings"))

    # Servers present locally but absent from the file are left alone, never deleted — an
    # import is "make these exist as described", not "make the world look exactly like this".
    # Deleting on import would make a partial/hand-trimmed file catastrophic.
    file_slugs = {s.slug for s in servers}
    extra = [s.slug for s in await server_repo.list() if s.slug not in file_slugs]
    if extra:
        plan.warnings.append(
            "these servers exist here but are not in the file and were left untouched: "
            + ", ".join(sorted(extra))
        )

    return plan
