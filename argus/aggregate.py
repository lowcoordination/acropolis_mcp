from __future__ import annotations

import re

TOOL_NAME_SEPARATOR = "__"
MAX_TOOL_NAME_LENGTH = 128  # matches common client-side caps (e.g. Claude API tool names)
_VALID_TOOL_NAME_CHARS = re.compile(r"^[a-zA-Z0-9_-]+$")


def namespaced_tool_name(slug: str, tool_name: str) -> str:
    """{slug}__{tool} — '__' chosen because tool names are commonly restricted to
    [a-zA-Z0-9_-], which rules out '.' or ':' as a separator."""
    return f"{slug}{TOOL_NAME_SEPARATOR}{tool_name}"


def split_namespaced_tool_name(namespaced: str) -> tuple[str, str] | None:
    """Reverse of namespaced_tool_name. Returns None if the string isn't validly namespaced
    (e.g. a plain tool name with no separator, or with extra separators in the tool part —
    slugs never contain '__' since they're validated against [a-z0-9-]+ at creation)."""
    if TOOL_NAME_SEPARATOR not in namespaced:
        return None
    slug, _, tool_name = namespaced.partition(TOOL_NAME_SEPARATOR)
    if not slug or not tool_name:
        return None
    return slug, tool_name


def fits_name_limit(slug: str, tool_name: str) -> bool:
    return len(namespaced_tool_name(slug, tool_name)) <= MAX_TOOL_NAME_LENGTH


def namespace_tool_definition(slug: str, tool: dict) -> dict | None:
    """Returns a copy of `tool` with its name namespaced, or None if the namespaced name
    would exceed MAX_TOOL_NAME_LENGTH or contains characters that break the separator scheme
    (the tool is silently excluded from the aggregate rather than erroring the whole list —
    an operator should notice via the server detail page in Archon's UI, not have `/mcp`
    aggregate calls fail for unrelated tools)."""
    name = tool.get("name", "")
    if not name or not _VALID_TOOL_NAME_CHARS.match(name):
        return None
    if not fits_name_limit(slug, name):
        return None
    namespaced = dict(tool)
    namespaced["name"] = namespaced_tool_name(slug, name)
    return namespaced
