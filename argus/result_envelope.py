"""The result fields a 2026-07-28 client requires on everything the gateway hands back (#172).

2026-07-28 clients validate every result strictly: `resultType` is required on all of them, and
`ttlMs` + `cacheScope` on the cacheable methods. Acropolis builds some results itself
(tools/list, server/discover) and relays others from 2025-generation upstreams that know nothing
of these fields, so the gateway has to supply them. Open WebUI 0.13.0 discarded every response
for want of them.

Only ever applied to a 2026-generation caller (argus/generation.py). 2025-generation responses
keep their bare shape.
"""
from __future__ import annotations

from typing import Any

# The methods the 2026-07-28 schema marks cacheable (mcp_types CACHEABLE_METHODS).
CACHEABLE_METHODS: frozenset[str] = frozenset({
    "tools/list", "prompts/list", "resources/list", "resources/read",
    "resources/templates/list", "server/discover",
})

# A tools/list is policy-filtered and policy changes take effect live, so a client must not
# hold a stale view: immediately stale, and private so no shared cache serves it across callers.
DEFAULT_TTL_MS = 0
DEFAULT_CACHE_SCOPE = "private"


def envelope_2026_result(method: str, result: Any) -> Any:
    """Return `result` with the fields a 2026 client requires, filling only what is absent or null.

    A value already present is never overwritten: a 2026 upstream's own `ttlMs`, or a
    `resultType` other than "complete" (e.g. input_required), is the upstream's to decide.
    Returns a copy; a non-dict result (nothing to wrap) comes back unchanged.
    """
    if not isinstance(result, dict):
        return result
    enveloped = dict(result)
    defaults: dict[str, Any] = {"resultType": "complete"}
    if method in CACHEABLE_METHODS:
        defaults.update(ttlMs=DEFAULT_TTL_MS, cacheScope=DEFAULT_CACHE_SCOPE)
    for field, value in defaults.items():
        # An explicit null is as invalid on the wire as a missing field, so it is filled too.
        if enveloped.get(field) is None:
            enveloped[field] = value
    return enveloped
