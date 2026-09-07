"""The audit `origin` vocabulary — what kind of row this is, and where it came from (#123).

`audit_events.origin` answers a question the rest of the row cannot: whether a decision was made
for real client traffic crossing the gateway, for an operator testing their own policy, or on
someone's laptop before a shell command ran. That distinction is the point of the local-execution
epic (#119) — without it there is one log with two meanings mixed together.

Format: `<class>` or `<class>:<detail>`, class first, colon-delimited.

    NULL                                real gateway traffic (the default, and the only
                                        origin that represents a call actually refused for
                                        a client)
    test                                admin "Try it" tool tester
    local:<key-name>                    local evaluation via POST /api/v1/policy/evaluate
    local:<key-name>/<harness>@<host>   ... with a caller-asserted harness and host

TRUST BOUNDARY, and the reason for the ordering: the DERIVED half comes first and is never
caller-controlled. `<key-name>` is the gateway's own record of who holds the presented API key.
The `<harness>@<host>` suffix is asserted by the caller, because the gateway is HTTP-remote from
the harness and cannot observe either — it sees only a client_ip (already its own audit column,
deliberately not duplicated here). A forged assertion is therefore always sitting next to a
derived prefix that contradicts it, which is what keeps the audit log's "proves enforcement
wasn't silently lowered" claim honest for local rows.

The assertion is validated at the API boundary (archon/schemas.py's PolicyEvaluateRequest) with a
charset allowlist that excludes ':', '/', '@', whitespace and newlines, so an assertion cannot
forge extra structure, break class parsing, or corrupt the Prometheus exposition format.

CARDINALITY: only the CLASS is ever safe as a metrics label — see origin_class() and
argus/metrics.py. The detail half contains a hostname and would put unbounded, partly
caller-controlled values into Prometheus time series.
"""
from __future__ import annotations

from typing import Optional

# The class vocabulary. `gateway` is the name for the NULL origin — NULL is the storage
# representation (it predates this scheme and is what /stats filters on), while "gateway" is how
# that same thing is named in an API query parameter or a metrics label, where a literal null is
# awkward to express.
CLASS_GATEWAY = "gateway"
CLASS_LOCAL = "local"
CLASS_TEST = "test"

ORIGIN_CLASSES = (CLASS_GATEWAY, CLASS_LOCAL, CLASS_TEST)

# The stored origin for an admin Try-it call. A bare class token with no detail — it predates
# the class:detail scheme (migration 0004) and is left exactly as it was, since changing a value
# already on disk would silently reclassify every historical row.
TEST_ORIGIN = CLASS_TEST


def local_origin(key_name: str, harness: Optional[str] = None, host: Optional[str] = None) -> str:
    """Build the origin for a local evaluation.

    `key_name` is derived (ApiKeyRecord.name) and always present. `harness`/`host` are the
    caller's assertion and are only appended when BOTH are supplied — a half-assertion would
    produce an ambiguous detail string that cannot be parsed back apart.

    Callers must pass values already validated by PolicyEvaluateRequest; this function does not
    re-validate, it composes. That is deliberate: rejection belongs at the API boundary where it
    can return a 422 naming the offending field, not here where the only options would be
    silently mangling the value or raising deep inside a request.
    """
    detail = key_name
    if harness and host:
        detail = f"{key_name}/{harness}@{host}"
    return f"{CLASS_LOCAL}:{detail}"


def origin_class(origin: Optional[str]) -> str:
    """The class of a stored origin value — the ONLY part safe to use as a metrics label.

    NULL maps to "gateway". An unrecognized value maps to its leading segment, so a class added
    later still aggregates sensibly instead of vanishing from a breakdown; a value with no colon
    is its own class, which is what keeps the legacy bare "test" token working.
    """
    if origin is None:
        return CLASS_GATEWAY
    return origin.split(":", 1)[0]
