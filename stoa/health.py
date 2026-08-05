from __future__ import annotations

import asyncio
import json
import logging

import httpx

from argus.upstream import CLIENT_INFO, UpstreamHandshakeCache, UpstreamHandshakeError, parse_sse_body
from db.models import ServerRecord
from db.repo import ServerNotFoundError, ServerRepo

logger = logging.getLogger("stoa.health")

DEFAULT_POLL_INTERVAL_SECONDS = 60.0
# Health probes must never block on the shared http client's generous default timeout (120s,
# sized for real tool calls) — a routine check against a briefly-unreachable or restarting
# upstream should fail fast, not stall the whole poll cycle for every other registered server.
PROBE_TIMEOUT_SECONDS = 10.0


async def probe_server(
    client: httpx.AsyncClient, handshake_cache: UpstreamHandshakeCache, server: ServerRecord
) -> tuple[str, str | None, dict | None]:
    """Probe one server's generation and health.

    Tries `server/discover` first (mandatory RPC for 2026-generation servers per the spec);
    on method-not-found, falls back to the 2025-generation `initialize` handshake. Returns
    (health_status, upstream_protocol, discover_json_dict).
    """
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    # F23 fix (review 2026-08-04): a server with a configured upstream credential needs it on
    # the health probe too, or every registered server requiring auth would show permanently
    # unhealthy regardless of whether tools/call itself works.
    if server.upstream_auth_header:
        headers["Authorization"] = server.upstream_auth_header
    discover_body = {
        "jsonrpc": "2.0", "id": "acropolis-discover", "method": "server/discover",
        "params": {"clientInfo": CLIENT_INFO},
    }

    try:
        resp = await client.post(
            server.upstream_url, json=discover_body, headers=headers, timeout=PROBE_TIMEOUT_SECONDS
        )
    except httpx.HTTPError as e:
        logger.info("probe for '%s' failed to connect: %s", server.slug, e)
        return ("unhealthy", None, None)

    if resp.status_code == 200:
        # F12 fix (review 2026-08-04): json.loads(resp.text) was unguarded — a 200 response
        # with a non-JSON body (e.g. an auth proxy's HTML login page in front of a
        # misconfigured upstream) raised JSONDecodeError here, which escaped probe_server ->
        # _probe_and_store -> poll_once. poll_once iterated servers SERIALLY with no
        # per-server try/except, so this one bad server aborted the whole poll cycle and every
        # server after it in slug order got permanently stale health. Every other parse site
        # in the codebase was already defended; this one wasn't.
        try:
            parsed = (
                parse_sse_body(resp.text)
                if "text/event-stream" in resp.headers.get("content-type", "")
                else (json.loads(resp.text) if resp.text else None)
            )
        except (json.JSONDecodeError, ValueError) as e:
            logger.info("probe for '%s' returned an unparseable 200 response: %s", server.slug, e)
            parsed = None

        if parsed and "result" in parsed:
            # A real server/discover response — this is a 2026-generation server.
            return ("healthy", "2026-07-28", parsed["result"])
        # F12 fix, second half: parsed.get("error", {}) raised AttributeError when "error" was
        # present but explicitly null (dict.get's default only applies when the KEY is absent,
        # not when its value is None) — `(parsed.get("error") or {})` handles both cases.
        error_message = (parsed.get("error") or {}).get("message", "") if parsed else ""
        if "method" in error_message.lower():
            # Method-not-found-shaped error — fall through to the 2025 handshake below.
            pass

    # Either server/discover isn't implemented (2025-generation) or the probe didn't return a
    # clean result — fall back to a real initialize handshake, which every 2025 upstream must
    # support and which also confirms the server is actually reachable and speaking MCP.
    try:
        handshake = await handshake_cache.get_or_handshake(
            server.id, server.upstream_url, timeout=PROBE_TIMEOUT_SECONDS,
            upstream_auth_header=server.upstream_auth_header,
        )
    except UpstreamHandshakeError as e:
        logger.info("probe for '%s' failed initialize fallback: %s", server.slug, e)
        return ("unhealthy", None, None)

    discover_json = {
        "protocolVersion": handshake.protocol_version,
        "serverInfo": handshake.server_info,
        "capabilities": handshake.capabilities,
    }
    return ("healthy", handshake.protocol_version, discover_json)


class HealthPoller:
    """Background task: periodically probes every enabled server and updates its health/
    protocol/discover_json fields via ServerRepo.set_health()."""

    def __init__(
        self,
        server_repo: ServerRepo,
        client: httpx.AsyncClient,
        handshake_cache: UpstreamHandshakeCache,
        interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    ):
        self._repo = server_repo
        self._client = client
        self._handshakes = handshake_cache
        self._interval = interval_seconds
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                # Bounded: cancellation of a task parked in a plain asyncio.sleep() is normally
                # near-instant, but under real ASGI server shutdown (uvicorn + anyio task
                # groups from in-flight MCP sessions) this has been observed to stall well
                # past that. A poller must never be allowed to block app shutdown indefinitely
                # — abandon it after a bounded wait rather than hang the process.
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("health poller task did not stop within 5s; abandoning it")
            self._task = None

    async def poll_once(self) -> None:
        # F12 fix, third half: even with probe_server() itself now fully guarded, wrap each
        # _probe_and_store call individually so a future exception in EITHER the probe or the
        # set_health() write for one server can never abort the whole cycle and leave every
        # server after it in slug order permanently stale — defense in depth on top of the
        # parse-site fix above, not a substitute for it.
        servers = await self._repo.list()
        for server in servers:
            if not server.enabled:
                continue
            try:
                await self._probe_and_store(server)
            except Exception:
                logger.exception("health probe failed for server '%s'", server.slug)

    async def poll_one(self, slug: str) -> None:
        """Probe a single server immediately, outside the normal poll cycle — used right after
        registering a server (so it doesn't sit at 'unknown' for up to a full interval) and for
        an explicit re-probe request from the UI."""
        try:
            server = await self._repo.get(slug)
        except ServerNotFoundError:
            return
        if server.enabled:
            await self._probe_and_store(server)

    async def _probe_and_store(self, server: ServerRecord) -> None:
        health_status, protocol, discover_json = await probe_server(
            self._client, self._handshakes, server
        )
        await self._repo.set_health(
            server.slug, health_status=health_status, upstream_protocol=protocol,
            discover_json=json.dumps(discover_json) if discover_json else None,
        )

    async def _loop(self) -> None:
        while True:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("health poll iteration failed")
            await asyncio.sleep(self._interval)
