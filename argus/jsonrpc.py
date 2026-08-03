from __future__ import annotations

import json
from typing import Any


def sanitize_rpc_id(rpc_id: Any) -> str | int | float | None:
    """
    JSON-RPC 2.0 spec: id must be string, number, or null.
    Clamp strings to 256 chars to prevent oversized error responses.
    Anything else is normalised to null.
    """
    if rpc_id is None:
        return None
    if isinstance(rpc_id, bool):
        return None  # bool is a subclass of int but is not a valid id
    if isinstance(rpc_id, int):
        return rpc_id
    if isinstance(rpc_id, float):
        return rpc_id
    if isinstance(rpc_id, str):
        return rpc_id[:256]
    return None


def rpc_error(rpc_id: Any, message: str, code: int = -32600, data: dict | None = None) -> str:
    """Build a JSON-RPC 2.0 error response body.

    Error code allocation (per MCP spec 2026-07-28): -32000..-32019 is implementation-defined
    (used here for generic gateway errors), -32020..-32099 is reserved for MCP spec codes
    (e.g. -32020 HeaderMismatchError). Callers needing a specific spec code should pass it.
    """
    err: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": sanitize_rpc_id(rpc_id),
        "error": {"code": code, "message": message},
    }
    if data:
        err["error"]["data"] = data
    return json.dumps(err)


# MCP spec 2026-07-28 error code allocation
HEADER_MISMATCH_ERROR = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022
