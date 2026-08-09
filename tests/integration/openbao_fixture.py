"""A real, disposable Vault-API-speaking dev-mode server, run out-of-process for integration
tests — mirrors tests/integration/fastmcp_fixture.py's pattern (spin up a real thing on an
ephemeral port for the duration of the test, tear it down after) rather than mocking the wire
protocol.

Uses whichever binary is actually available on the box: `bao` (OpenBao) is tried first, then
`vault` (HashiCorp Vault) — dev mode is available on both and speaks the identical KV v2 HTTP
API this client is written against. If NEITHER binary is present, `has_real_server()` returns
False and callers should skip (or fall back to the protocol-shape stub in
tests/unit/test_secrets_openbao_stub.py) rather than silently not testing anything — see that
module's docstring and the PR description for exactly which kind of verification ran in this
environment.

Dev mode auto-unseals, auto-mounts a `secret/` KV v2 backend, and issues a well-known root token
— it is designed exactly for this kind of disposable, no-persistence use and is never suitable
for anything but throwaway local testing (real Vault/OpenBao is never run this way).
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket

import httpx

DEV_ROOT_TOKEN = "acropolis-test-root-token"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _resolve_binary() -> str | None:
    for candidate in ("bao", "vault"):
        path = shutil.which(candidate)
        if path:
            return candidate
    return None


def has_real_server() -> bool:
    return _resolve_binary() is not None


class RunningVaultServer:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token


@contextlib.asynccontextmanager
async def run_dev_server():
    """Starts `bao server -dev` (or `vault server -dev` if bao isn't installed) on an ephemeral
    port, in-memory, auto-unsealed, with a fixed root token. Yields a RunningVaultServer.
    Raises RuntimeError if neither binary is available — callers should check has_real_server()
    first and skip the test instead of hitting this."""
    binary = _resolve_binary()
    if binary is None:
        raise RuntimeError("neither 'bao' nor 'vault' binary found on PATH")

    port = _free_port()
    addr = f"127.0.0.1:{port}"
    proc = await asyncio.create_subprocess_exec(
        binary, "server", "-dev",
        f"-dev-root-token-id={DEV_ROOT_TOKEN}",
        f"-dev-listen-address={addr}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    url = f"http://{addr}"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            started = False
            for _ in range(100):
                try:
                    resp = await client.get(f"{url}/v1/sys/health")
                    if resp.status_code in (200, 429, 472, 473, 501, 503):
                        # Any of these means the HTTP listener is up and answering per Vault's
                        # sys/health status-code contract; dev mode is unsealed almost
                        # immediately so 200 is the expected steady state.
                        started = True
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.05)
            if not started:
                raise RuntimeError(f"{binary} server -dev did not become healthy in time")

        yield RunningVaultServer(url=url, token=DEV_ROOT_TOKEN)
    finally:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
