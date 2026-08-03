from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

from db.models import ParamRule, ServerPolicy
from db.repo import ServerRepo, SlugConflictError

_PARAM_RULE_FIELDS = {"max_length", "block_patterns", "max_value", "min_value", "denied"}
_SLUG_UNSAFE_CHARS = re.compile(r"[^a-z0-9-]+")


def name_to_slug(name: str) -> str:
    """mcp-guard server names use underscores (e.g. 'mn_land'); Argus slugs are [a-z0-9-]+."""
    slug = _SLUG_UNSAFE_CHARS.sub("-", name.lower()).strip("-")
    if not slug:
        raise ValueError(f"server name {name!r} produces an empty slug")
    return slug


@dataclass
class ImportedServer:
    slug: str
    name: str
    upstream_url: str
    rate_limit: str | None
    policy: ServerPolicy


@dataclass
class ImportResult:
    servers: list[ImportedServer] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_guard_config(yaml_text: str) -> ImportResult:
    """Parse a mcp-guard guard-config.yml into Argus server + policy records.
    Pure parsing, no DB writes — callers decide whether to apply (see `apply_import`)."""
    data = yaml.safe_load(yaml_text) or {}
    result = ImportResult()

    for name, s in (data.get("servers") or {}).items():
        tools_data = s.get("tools", {}) or {}

        param_rules: dict[str, dict[str, ParamRule]] = {}
        for tool_name, params in (tools_data.get("rules") or {}).items():
            param_rules[tool_name] = {}
            for param_name, param_cfg in params.items():
                unknown = set(param_cfg.keys()) - _PARAM_RULE_FIELDS
                if unknown:
                    raise ValueError(
                        f"server '{name}', tool '{tool_name}', param '{param_name}': "
                        f"unknown rule keys: {unknown}"
                    )
                param_rules[tool_name][param_name] = ParamRule(**param_cfg)

        upstream = s["upstream"].rstrip("/")
        parsed = urlparse(upstream)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"server '{name}': upstream must be a valid http/https URL, got {upstream!r}")

        policy = ServerPolicy(
            mode=tools_data.get("mode", "passthrough"),
            allowed=tools_data.get("allowed", []),
            denied=tools_data.get("denied", []),
            param_rules=param_rules,
        )

        slug = name_to_slug(name)
        if slug != name:
            result.warnings.append(f"server '{name}' renamed to slug '{slug}' (Argus slugs are [a-z0-9-]+)")

        # M1 scope: Argus is per-server, not per-port — listen_port from the old config is
        # dropped. Upstream host:port is carried over as-is; homelab migration (deferred)
        # is expected to rewrite these to cluster DNS, not this importer's job.
        result.servers.append(
            ImportedServer(
                slug=slug, name=name, upstream_url=upstream,
                rate_limit=s.get("rate_limit"), policy=policy,
            )
        )

    return result


async def apply_import(repo: ServerRepo, result: ImportResult, dry_run: bool = False) -> list[str]:
    """Write parsed servers + policies to the DB. Returns a list of human-readable actions taken
    (or that would be taken, if dry_run)."""
    actions: list[str] = []
    for imported in result.servers:
        if dry_run:
            actions.append(f"would create server '{imported.slug}' -> {imported.upstream_url}")
            continue
        try:
            server = await repo.create(
                slug=imported.slug, name=imported.name, upstream_url=imported.upstream_url,
            )
            actions.append(f"created server '{imported.slug}' -> {imported.upstream_url}")
        except SlugConflictError:
            server = await repo.get(imported.slug)
            actions.append(f"server '{imported.slug}' already exists, updating policy only")

        policy = imported.policy
        if imported.rate_limit:
            policy = policy.model_copy(update={"rate_limit": imported.rate_limit})
        await repo.set_policy(server.id, policy)
        actions.append(f"applied policy (mode={policy.mode}) to '{imported.slug}'")

    return actions
