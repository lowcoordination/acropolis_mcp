"""A real FastMCP 2025-06-18-generation server, run in-process for integration tests.

Deliberately pinned to protocol 2025-06-18 (mcp==1.29.0) to match the real homelab fleet —
see the pyproject.toml comment on the dev dependency for why.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket

import uvicorn
from mcp.server.fastmcp import FastMCP


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_test_server(call_counter: dict[str, int]) -> FastMCP:
    mcp = FastMCP("test-fixture", host="127.0.0.1", port=0)

    def _count(name: str) -> None:
        call_counter[name] = call_counter.get(name, 0) + 1

    @mcp.tool()
    def echo(message: str) -> str:
        """Echo the message back."""
        _count("echo")
        return message

    @mcp.tool()
    def read_file(path: str) -> str:
        """Pretend to read a file."""
        _count("read_file")
        return f"contents of {path}"

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        """Pretend to write a file."""
        _count("write_file")
        return f"wrote {len(content)} bytes to {path}"

    @mcp.tool()
    async def slow_tool(delay_seconds: float = 0.3) -> str:
        """A tool that takes a while, for streaming/timeout tests."""
        _count("slow_tool")
        await asyncio.sleep(delay_seconds)
        return "done"

    return mcp


class RunningFastMCPServer:
    def __init__(self, port: int, call_counter: dict[str, int]):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.call_counter = call_counter


@contextlib.asynccontextmanager
async def run_fastmcp_server():
    """Spins up a real FastMCP streamable-http server on an ephemeral port.

    Yields a RunningFastMCPServer with a `call_counter` dict that increments per tool name
    every time the upstream actually executes a tool — used to prove blocked calls never
    reach the upstream.
    """
    port = _free_port()
    call_counter: dict[str, int] = {}
    mcp = build_test_server(call_counter)
    mcp.settings.port = port

    app = mcp.streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("fastmcp test server did not start in time")

        yield RunningFastMCPServer(port=port, call_counter=call_counter)
    finally:
        server.should_exit = True
        try:
            # uvicorn's graceful shutdown waits for in-flight connections to close. In these
            # tests, Acropolis's own HealthPoller runs a real background probe against every
            # registered server on create_app() startup — if that probe happens to be
            # in-flight against THIS fixture exactly at teardown, the connection can be held
            # open (keep-alive) and shutdown hangs indefinitely. force_close cuts it off
            # rather than let a background poller from an unrelated component hang the suite.
            await asyncio.wait_for(task, timeout=5.0)
        except asyncio.TimeoutError:
            server.force_exit = True
            await asyncio.wait_for(task, timeout=5.0)
