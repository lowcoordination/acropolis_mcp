from __future__ import annotations

from enum import Enum

from fastapi import Request

from argus.headers import MCP_METHOD_HEADER


class ClientGeneration(str, Enum):
    """Which MCP protocol generation a request appears to come from.

    2026-07-28 made Mcp-Method REQUIRED on every Streamable HTTP POST and removed the
    initialize handshake entirely (stateless). 2025-06-18 clients never send that header and
    always initialize() before any other call. Detection is necessarily a heuristic — the
    spec gives no version field on the wire that's cheaper to check than "is this header here".
    """

    GEN_2026 = "2026-07-28"
    GEN_2025 = "2025-06-18"


def detect_client_generation(request: Request) -> ClientGeneration:
    if request.headers.get(MCP_METHOD_HEADER) is not None:
        return ClientGeneration.GEN_2026
    return ClientGeneration.GEN_2025
