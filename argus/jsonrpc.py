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

# JSON-RPC 2.0 standard codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600


class NotASingleMessage(ValueError):
    """The POST body is not exactly one JSON-RPC object (issue #166). `code` is the JSON-RPC
    error code to serve; `reason` is safe to return to the client and to audit."""

    def __init__(self, code: int, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def parse_single_message(body_bytes: bytes) -> dict:
    """Parse a data-plane POST body that must hold exactly one JSON-RPC message.

    Every MCP version Acropolis speaks (2025-06-18, 2026-07-28) says the Streamable HTTP POST
    body MUST be a single JSON-RPC request, notification or response; 2025-06-18 removed
    batching. Anything else is refused, never forwarded. The data plane used to forward
    whatever it could not read as an object, and that skipped all enforcement (#166).

    ValueError covers JSONDecodeError and UnicodeDecodeError (invalid UTF-8). RecursionError
    is what json.loads raises for deeply nested arrays, well under max_body_bytes.
    """
    try:
        parsed = json.loads(body_bytes)
    except (ValueError, RecursionError):
        raise NotASingleMessage(
            PARSE_ERROR, "Parse error: body is not UTF-8 JSON, or is nested too deeply",
        ) from None
    if isinstance(parsed, list):
        raise NotASingleMessage(
            INVALID_REQUEST,
            "JSON-RPC batching is not supported (removed in MCP 2025-06-18); "
            "send one message per request",
        )
    if not isinstance(parsed, dict):
        raise NotASingleMessage(INVALID_REQUEST, "body must be a single JSON-RPC object")
    return parsed
