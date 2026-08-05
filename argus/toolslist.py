from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from argus.bridge import BridgeError, ProtocolBridge
from argus.policy import tool_is_visible
from db.database import Database, utcnow
from db.models import ServerPolicy

DEFAULT_TTL_MS = 300_000  # 5 minutes — used for 2025-generation upstreams, which carry no ttlMs


class ToolsCache:
    """Cache of each server's tool definitions (tools_cache table), refreshed via the bridge
    and filtered by policy before being handed to a caller. Owned conceptually by Stoa (the
    registry), consumed by Argus (routing/filtering) — see plan's module boundary note."""

    def __init__(self, db: Database, bridge: ProtocolBridge):
        self._db = db
        self._bridge = bridge

    @property
    def _read(self) -> aiosqlite.Connection:
        assert self._db.gateway_read is not None
        self._db.gateway_read.row_factory = aiosqlite.Row
        return self._db.gateway_read

    @property
    def _write(self) -> aiosqlite.Connection:
        assert self._db.gateway is not None
        self._db.gateway.row_factory = aiosqlite.Row
        return self._db.gateway

    async def _cached_rows(self, server_id: int) -> list[aiosqlite.Row]:
        cur = await self._read.execute(
            "SELECT * FROM tools_cache WHERE server_id = ? ORDER BY tool_name", (server_id,)
        )
        return list(await cur.fetchall())

    def _is_fresh(self, fetched_at: str, ttl_ms: Optional[int]) -> bool:
        ttl = ttl_ms if ttl_ms is not None else DEFAULT_TTL_MS
        fetched = datetime.fromisoformat(fetched_at)
        age_ms = (datetime.now(timezone.utc) - fetched).total_seconds() * 1000
        return age_ms < ttl

    async def get_raw_tools(
        self, server_id: int, upstream_url: str, force_refresh: bool = False,
        upstream_auth_header: Optional[str] = None,
    ) -> list[dict]:
        """Returns the server's full (unfiltered) tool list, from cache if fresh or by fetching."""
        rows = await self._cached_rows(server_id)
        if rows and not force_refresh and all(self._is_fresh(r["fetched_at"], r["ttl_ms"]) for r in rows):
            return [json.loads(r["definition_json"]) for r in rows]

        try:
            status, body = await self._bridge.bridge_call(
                server_id=server_id, upstream_url=upstream_url, rpc_method="tools/list",
                rpc_id="acropolis-toolslist", params={},
                upstream_auth_header=upstream_auth_header,
            )
        except BridgeError:
            # Upstream unreachable (connection refused, handshake failed, etc.) — serve stale
            # cache if we have any, rather than propagating a 500 to whoever's asking for the
            # tool list (a data-plane client, or the Archon UI's server-detail page).
            if rows:
                return [json.loads(r["definition_json"]) for r in rows]
            return []

        if status != 200 or "result" not in body:
            # Upstream responded, but not usefully — same fallback as above.
            if rows:
                return [json.loads(r["definition_json"]) for r in rows]
            return []

        tools = body["result"].get("tools", [])
        ttl_ms = body["result"].get("ttlMs")
        cache_scope = body["result"].get("cacheScope")
        await self._store(server_id, tools, ttl_ms, cache_scope)
        return tools

    async def _store(
        self, server_id: int, tools: list[dict], ttl_ms: Optional[int], cache_scope: Optional[str]
    ) -> None:
        # F7: DELETE-then-N-INSERT, same shape as ServerRepo.set_policy — serialize through the
        # write lock + explicit transaction so a concurrent reader (a different connection) never
        # observes the gap. The INSERT-OR-REPLACE + malformed-tool-name hardening this method
        # still needs is tracked as Plan 3 scope (03-reliability-and-ops.md §26); this only
        # closes the same-shape isolation gap F7 targets.
        async with self._db.gateway_write_lock:
            await self._write.execute("BEGIN IMMEDIATE")
            try:
                await self._write.execute("DELETE FROM tools_cache WHERE server_id = ?", (server_id,))
                now = utcnow()
                for tool in tools:
                    await self._write.execute(
                        """INSERT INTO tools_cache (server_id, tool_name, definition_json, ttl_ms, cache_scope, fetched_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (server_id, tool["name"], json.dumps(tool), ttl_ms, cache_scope, now),
                    )
                await self._write.commit()
            except BaseException:
                await self._write.rollback()
                raise

    async def invalidate(self, server_id: int) -> None:
        """Called on policy write — a stale filtered list would otherwise show a tool that
        was just denied, or hide one that was just allowed."""
        async with self._db.gateway_write_lock:
            await self._write.execute("DELETE FROM tools_cache WHERE server_id = ?", (server_id,))
            await self._write.commit()

    async def fetched_at(self, server_id: int) -> Optional[str]:
        """Roadmap #6: the most recent fetched_at across this server's cached tools, so the UI
        can show "updated <relative time>" — or None if nothing has been fetched yet."""
        cur = await self._read.execute(
            "SELECT MAX(fetched_at) AS fetched_at FROM tools_cache WHERE server_id = ?",
            (server_id,),
        )
        row = await cur.fetchone()
        return row["fetched_at"] if row else None

    async def get_filtered_tools(
        self, server_id: int, upstream_url: str, policy: ServerPolicy,
        upstream_auth_header: Optional[str] = None, force_refresh: bool = False,
    ) -> list[dict]:
        """Tool list with policy-denied tools removed — what a client is actually allowed to see."""
        tools = await self.get_raw_tools(
            server_id, upstream_url, force_refresh=force_refresh,
            upstream_auth_header=upstream_auth_header,
        )
        return [t for t in tools if tool_is_visible(t["name"], policy)]
