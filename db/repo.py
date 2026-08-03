from __future__ import annotations

import json
from typing import Optional

import aiosqlite

from .database import Database, utcnow
from .models import ApiKeyRecord, ParamRule, ServerPolicy, ServerRecord


class ServerNotFoundError(Exception):
    pass


class SlugConflictError(Exception):
    pass


def _row_to_server(row: aiosqlite.Row) -> ServerRecord:
    return ServerRecord(
        id=row["id"],
        slug=row["slug"],
        name=row["name"],
        upstream_url=row["upstream_url"],
        enabled=bool(row["enabled"]),
        in_aggregate=bool(row["in_aggregate"]),
        upstream_protocol=row["upstream_protocol"],
        health_status=row["health_status"],
        last_seen_at=row["last_seen_at"],
        discover_json=row["discover_json"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class ServerRepo:
    """CRUD for `servers` + their attached `server_policies` / `tool_policies` / `param_rules`."""

    def __init__(self, db: Database):
        self._db = db

    @property
    def _conn(self) -> aiosqlite.Connection:
        assert self._db.gateway is not None
        self._db.gateway.row_factory = aiosqlite.Row
        return self._db.gateway

    async def list(self) -> list[ServerRecord]:
        cur = await self._conn.execute("SELECT * FROM servers ORDER BY slug")
        rows = await cur.fetchall()
        return [_row_to_server(r) for r in rows]

    async def get(self, slug: str) -> ServerRecord:
        cur = await self._conn.execute("SELECT * FROM servers WHERE slug = ?", (slug,))
        row = await cur.fetchone()
        if row is None:
            raise ServerNotFoundError(slug)
        return _row_to_server(row)

    async def get_by_id(self, server_id: int) -> ServerRecord:
        cur = await self._conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
        row = await cur.fetchone()
        if row is None:
            raise ServerNotFoundError(str(server_id))
        return _row_to_server(row)

    async def create(
        self,
        slug: str,
        name: str,
        upstream_url: str,
        enabled: bool = True,
        in_aggregate: bool = True,
    ) -> ServerRecord:
        existing = await self._conn.execute("SELECT 1 FROM servers WHERE slug = ?", (slug,))
        if await existing.fetchone() is not None:
            raise SlugConflictError(slug)

        now = utcnow()
        cur = await self._conn.execute(
            """INSERT INTO servers
               (slug, name, upstream_url, enabled, in_aggregate, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (slug, name, upstream_url, int(enabled), int(in_aggregate), now, now),
        )
        await self._conn.execute(
            "INSERT INTO server_policies (server_id, mode, updated_at) VALUES (?, 'passthrough', ?)",
            (cur.lastrowid, now),
        )
        await self._conn.commit()
        return await self.get(slug)

    async def update(
        self,
        slug: str,
        name: Optional[str] = None,
        upstream_url: Optional[str] = None,
        enabled: Optional[bool] = None,
        in_aggregate: Optional[bool] = None,
    ) -> ServerRecord:
        current = await self.get(slug)
        fields, values = [], []
        if name is not None:
            fields.append("name = ?")
            values.append(name)
        if upstream_url is not None:
            fields.append("upstream_url = ?")
            values.append(upstream_url)
        if enabled is not None:
            fields.append("enabled = ?")
            values.append(int(enabled))
        if in_aggregate is not None:
            fields.append("in_aggregate = ?")
            values.append(int(in_aggregate))
        if not fields:
            return current
        fields.append("updated_at = ?")
        values.append(utcnow())
        values.append(current.id)
        await self._conn.execute(f"UPDATE servers SET {', '.join(fields)} WHERE id = ?", values)
        await self._conn.commit()
        return await self.get(slug)

    async def delete(self, slug: str) -> None:
        current = await self.get(slug)
        await self._conn.execute("DELETE FROM servers WHERE id = ?", (current.id,))
        await self._conn.commit()

    async def set_health(
        self, slug: str, health_status: str, upstream_protocol: Optional[str] = None,
        discover_json: Optional[str] = None,
    ) -> None:
        current = await self.get(slug)
        await self._conn.execute(
            """UPDATE servers SET health_status = ?, upstream_protocol = COALESCE(?, upstream_protocol),
               discover_json = COALESCE(?, discover_json), last_seen_at = ?, updated_at = ?
               WHERE id = ?""",
            (health_status, upstream_protocol, discover_json, utcnow(), utcnow(), current.id),
        )
        await self._conn.commit()

    async def get_policy(self, server_id: int) -> ServerPolicy:
        cur = await self._conn.execute(
            "SELECT mode, rate_limit FROM server_policies WHERE server_id = ?", (server_id,)
        )
        row = await cur.fetchone()
        mode = row["mode"] if row else "passthrough"
        rate_limit = row["rate_limit"] if row else None

        cur = await self._conn.execute(
            "SELECT tool_name, action FROM tool_policies WHERE server_id = ?", (server_id,)
        )
        rows = await cur.fetchall()
        allowed = [r["tool_name"] for r in rows if r["action"] == "allow"]
        denied = [r["tool_name"] for r in rows if r["action"] == "deny"]

        cur = await self._conn.execute(
            """SELECT tool_name, param_name, max_length, max_value, min_value, denied, block_patterns
               FROM param_rules WHERE server_id = ?""",
            (server_id,),
        )
        rows = await cur.fetchall()
        param_rules: dict[str, dict[str, ParamRule]] = {}
        for r in rows:
            param_rules.setdefault(r["tool_name"], {})[r["param_name"]] = ParamRule(
                max_length=r["max_length"],
                max_value=r["max_value"],
                min_value=r["min_value"],
                denied=bool(r["denied"]),
                block_patterns=json.loads(r["block_patterns"]) if r["block_patterns"] else [],
            )

        return ServerPolicy(
            mode=mode, rate_limit=rate_limit, allowed=allowed, denied=denied, param_rules=param_rules
        )

    async def set_policy(self, server_id: int, policy: ServerPolicy) -> None:
        await self._conn.execute(
            """INSERT INTO server_policies (server_id, mode, rate_limit, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(server_id) DO UPDATE SET mode=excluded.mode,
                   rate_limit=excluded.rate_limit, updated_at=excluded.updated_at""",
            (server_id, policy.mode, policy.rate_limit, utcnow()),
        )
        await self._conn.execute("DELETE FROM tool_policies WHERE server_id = ?", (server_id,))
        for tool_name in policy.allowed:
            await self._conn.execute(
                "INSERT INTO tool_policies (server_id, tool_name, action) VALUES (?, ?, 'allow')",
                (server_id, tool_name),
            )
        for tool_name in policy.denied:
            await self._conn.execute(
                "INSERT INTO tool_policies (server_id, tool_name, action) VALUES (?, ?, 'deny')",
                (server_id, tool_name),
            )
        await self._conn.execute("DELETE FROM param_rules WHERE server_id = ?", (server_id,))
        for tool_name, params in policy.param_rules.items():
            for param_name, rule in params.items():
                await self._conn.execute(
                    """INSERT INTO param_rules
                       (server_id, tool_name, param_name, max_length, max_value, min_value, denied, block_patterns)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        server_id, tool_name, param_name, rule.max_length, rule.max_value,
                        rule.min_value, int(rule.denied), json.dumps(rule.block_patterns),
                    ),
                )
        await self._conn.commit()


class ApiKeyRepo:
    def __init__(self, db: Database):
        self._db = db

    @property
    def _conn(self) -> aiosqlite.Connection:
        assert self._db.gateway is not None
        self._db.gateway.row_factory = aiosqlite.Row
        return self._db.gateway

    async def create(self, name: str, key_hash: str, key_prefix: str,
                      server_scopes: Optional[list[str]] = None) -> ApiKeyRecord:
        now = utcnow()
        cur = await self._conn.execute(
            """INSERT INTO api_keys (name, key_hash, key_prefix, server_scopes, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (name, key_hash, key_prefix, json.dumps(server_scopes) if server_scopes else None, now),
        )
        await self._conn.commit()
        return await self.get_by_id(cur.lastrowid)

    async def get_by_id(self, key_id: int) -> ApiKeyRecord:
        cur = await self._conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,))
        row = await cur.fetchone()
        if row is None:
            raise ServerNotFoundError(str(key_id))
        return self._row_to_record(row)

    async def get_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        cur = await self._conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND enabled = 1", (key_hash,)
        )
        row = await cur.fetchone()
        return self._row_to_record(row) if row else None

    async def list(self) -> list[ApiKeyRecord]:
        cur = await self._conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
        rows = await cur.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def set_enabled(self, key_id: int, enabled: bool) -> None:
        await self._conn.execute("UPDATE api_keys SET enabled = ? WHERE id = ?", (int(enabled), key_id))
        await self._conn.commit()

    async def delete(self, key_id: int) -> None:
        await self._conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        await self._conn.commit()

    async def touch_last_used(self, key_id: int) -> None:
        await self._conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (utcnow(), key_id)
        )
        await self._conn.commit()

    @staticmethod
    def _row_to_record(row: aiosqlite.Row) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"],
            name=row["name"],
            key_prefix=row["key_prefix"],
            enabled=bool(row["enabled"]),
            server_scopes=json.loads(row["server_scopes"]) if row["server_scopes"] else None,
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )


class AuditRepo:
    def __init__(self, db: Database):
        self._db = db

    @property
    def _conn(self) -> aiosqlite.Connection:
        assert self._db.audit is not None
        self._db.audit.row_factory = aiosqlite.Row
        return self._db.audit

    async def insert_many(self, events: list[dict]) -> None:
        if not events:
            return
        await self._conn.executemany(
            """INSERT INTO audit_events
               (ts, server_slug, api_key_id, client_ip, endpoint, rpc_method, tool,
                decision, rule, matched, reason, args_summary, bridged, status_code, latency_ms)
               VALUES (:ts, :server_slug, :api_key_id, :client_ip, :endpoint, :rpc_method, :tool,
                       :decision, :rule, :matched, :reason, :args_summary, :bridged, :status_code, :latency_ms)""",
            events,
        )
        await self._conn.commit()

    async def query(
        self, server_slug: Optional[str] = None, decision: Optional[str] = None,
        tool: Optional[str] = None, before_id: Optional[int] = None, limit: int = 100,
    ) -> list[dict]:
        """Newest-first. `before_id` is keyset pagination — pass the smallest `id` from the
        previous page to fetch the next (older) page, rather than an OFFSET (which re-scans
        and can skip/duplicate rows under concurrent inserts)."""
        clauses, params = [], []
        if server_slug:
            clauses.append("server_slug = ?")
            params.append(server_slug)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        cur = await self._conn.execute(
            f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?", params
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def count_since(self, since_iso: str, decision: Optional[str] = None) -> int:
        clauses, params = ["ts >= ?"], [since_iso]
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        cur = await self._conn.execute(
            f"SELECT COUNT(*) FROM audit_events WHERE {' AND '.join(clauses)}", params
        )
        row = await cur.fetchone()
        return row[0] if row else 0

    async def prune_older_than(self, cutoff_iso: str) -> int:
        cur = await self._conn.execute("DELETE FROM audit_events WHERE ts < ?", (cutoff_iso,))
        await self._conn.commit()
        return cur.rowcount if cur.rowcount is not None else 0


class SettingsRepo:
    """Key-value store for gateway-wide settings (auth_mode, aggregate default, retention,
    admin credentials). Values are stored as plain strings; callers coerce types."""

    def __init__(self, db: Database):
        self._db = db

    @property
    def _conn(self) -> aiosqlite.Connection:
        assert self._db.gateway is not None
        self._db.gateway.row_factory = aiosqlite.Row
        return self._db.gateway

    async def get(self, key: str) -> Optional[str]:
        cur = await self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cur.fetchone()
        return row["value"] if row else None

    async def get_all(self) -> dict[str, str]:
        cur = await self._conn.execute("SELECT key, value FROM settings")
        rows = await cur.fetchall()
        return {r["key"]: r["value"] for r in rows}

    async def set(self, key: str, value: str) -> None:
        await self._conn.execute(
            """INSERT INTO settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )
        await self._conn.commit()

    async def set_many(self, values: dict[str, str]) -> None:
        for key, value in values.items():
            await self.set(key, value)
