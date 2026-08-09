from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import aiosqlite
from pydantic import BaseModel, ValidationError

from .database import Database, utcnow
from .models import (
    ApiKeyRecord,
    DlpCustomPattern,
    ParamRule,
    ProjectMemberRecord,
    ProjectRecord,
    ServerPolicy,
    ServerRecord,
    UserRecord,
)

logger = logging.getLogger("db.repo")

_UNSET = object()  # sentinel: distinguishes "argument omitted" from "argument is None"


# Enterprise #10 (DLP): dlp_detectors + dlp_custom_patterns are stored as ONE JSON TEXT column
# (server_policies.dlp_config, migration 0008_gateway_dlp_config.sql) rather than further
# normalized tables — see that migration's comment for why this departs from the original
# plan doc's "no migration needed" premise, and why JSON-in-a-column (not per-detector rows)
# was the call made here.
def _encode_dlp_config(
    detectors: dict[str, str], custom_patterns: list[DlpCustomPattern]
) -> Optional[str]:
    if not detectors and not custom_patterns:
        # Keep the common (DLP entirely unconfigured) case as a NULL column rather than a
        # literal '{"detectors": {}, "custom_patterns": []}' string — cosmetic, but matches
        # this schema's existing convention of NULL-for-unset over empty-JSON-for-unset
        # (e.g. server_policies.rate_limit, tool_policies.rate_limit).
        return None
    return json.dumps({
        "detectors": detectors,
        "custom_patterns": [p.model_dump() for p in custom_patterns],
    })


def _decode_dlp_config(raw: Optional[str]) -> tuple[dict[str, str], list[DlpCustomPattern]]:
    if not raw:
        return {}, []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("server_policies.dlp_config contained invalid JSON — treating as unset")
        return {}, []
    detectors = data.get("detectors") or {}
    custom_patterns = [DlpCustomPattern(**p) for p in (data.get("custom_patterns") or [])]
    return detectors, custom_patterns


class ServerNotFoundError(Exception):
    pass


class SlugConflictError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class UsernameConflictError(Exception):
    pass


class ProjectNotFoundError(Exception):
    pass


class ProjectSlugConflictError(Exception):
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
        health_reason=row["health_reason"] if "health_reason" in row.keys() else None,
        last_seen_at=row["last_seen_at"],
        discover_json=row["discover_json"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        upstream_auth_header=row["upstream_auth_header"],
        project_id=row["project_id"] if "project_id" in row.keys() else None,
    )


class ServerRepo:
    """CRUD for `servers` + their attached `server_policies` / `tool_policies` / `param_rules`.

    F7: reads and writes go through SEPARATE connections (see Database's docstring) — writes
    additionally serialize through `gateway_write_lock` and use an explicit transaction so a
    multi-statement write (create, set_policy) is atomic from every reader's perspective, not
    just readable-or-not on the writer's own connection."""

    def __init__(self, db: Database):
        self._db = db

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

    async def list(self, project_id: Optional[int] = None) -> list[ServerRecord]:
        # F4 fix (review 2026-08-04): defense-in-depth half. The CREATE path now validates the
        # slug (archon/schemas.py's _validate_slug) so a bad row shouldn't be writable anymore
        # — but this is the method that used to turn any bad row already in the DB (from before
        # the fix, or any path that bypasses the API validator) into a PERMANENT outage: every
        # caller of list() (GET /servers, GET /stats, aggregate tools/list/discover, the health
        # poller) would raise on the Pydantic ValidationError inside _row_to_server, with no way
        # to even see the bad row to delete it. Skip-and-log instead of propagating, so one bad
        # row degrades to "one server invisible" rather than "everything that calls list() is
        # down."
        #
        # Enterprise #4: `project_id=None` means "no project filter" (every existing caller pre-
        # this-feature, and every instance-wide use like the health poller) — NOT "servers with
        # no project". Pass a real project id explicitly to scope.
        if project_id is not None:
            cur = await self._read.execute(
                "SELECT * FROM servers WHERE project_id = ? ORDER BY slug", (project_id,)
            )
        else:
            cur = await self._read.execute("SELECT * FROM servers ORDER BY slug")
        rows = await cur.fetchall()
        result = []
        for r in rows:
            try:
                result.append(_row_to_server(r))
            except ValidationError as e:
                logger.error(
                    "skipping unparseable servers row id=%s slug=%r: %s", r["id"], r["slug"], e
                )
        return result

    async def get(self, slug: str) -> ServerRecord:
        cur = await self._read.execute("SELECT * FROM servers WHERE slug = ?", (slug,))
        row = await cur.fetchone()
        if row is None:
            raise ServerNotFoundError(slug)
        return _row_to_server(row)

    async def get_by_id(self, server_id: int) -> ServerRecord:
        cur = await self._read.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
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
        upstream_auth_header: Optional[str] = None,
        project_id: Optional[int] = None,
    ) -> ServerRecord:
        # F7: two-table write (servers + server_policies) — serialize against other gateway.db
        # writers so a concurrent commit can't land between the INSERT and its paired policy row.
        async with self._db.gateway_write_lock:
            existing = await self._write.execute("SELECT 1 FROM servers WHERE slug = ?", (slug,))
            if await existing.fetchone() is not None:
                raise SlugConflictError(slug)

            await self._write.execute("BEGIN IMMEDIATE")
            try:
                now = utcnow()
                cur = await self._write.execute(
                    """INSERT INTO servers
                       (slug, name, upstream_url, enabled, in_aggregate, upstream_auth_header,
                        created_at, updated_at, project_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (slug, name, upstream_url, int(enabled), int(in_aggregate),
                     upstream_auth_header, now, now, project_id),
                )
                await self._write.execute(
                    "INSERT INTO server_policies (server_id, mode, updated_at) VALUES (?, 'passthrough', ?)",
                    (cur.lastrowid, now),
                )
                await self._write.commit()
            except BaseException:
                await self._write.rollback()
                raise
        return await self.get(slug)

    async def update(
        self,
        slug: str,
        name: Optional[str] = None,
        upstream_url: Optional[str] = None,
        enabled: Optional[bool] = None,
        in_aggregate: Optional[bool] = None,
        upstream_auth_header: object = _UNSET,
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
        if upstream_auth_header is not _UNSET:
            # F23: unlike the other fields, None here is meaningful ("clear the configured
            # credential"), so a sentinel distinguishes "field omitted, don't touch it" from
            # "field explicitly set to null" — the None-means-omitted convention every other
            # field on this method uses would make it impossible to ever clear a credential.
            fields.append("upstream_auth_header = ?")
            values.append(upstream_auth_header)
        if not fields:
            return current
        fields.append("updated_at = ?")
        values.append(utcnow())
        values.append(current.id)
        async with self._db.gateway_write_lock:
            await self._write.execute(f"UPDATE servers SET {', '.join(fields)} WHERE id = ?", values)
            await self._write.commit()
        return await self.get(slug)

    async def delete(self, slug: str) -> None:
        current = await self.get(slug)
        async with self._db.gateway_write_lock:
            await self._write.execute("DELETE FROM servers WHERE id = ?", (current.id,))
            await self._write.commit()

    async def set_project(self, slug: str, project_id: int) -> ServerRecord:
        """Enterprise #4: reassign an EXISTING server to a different project. Deliberately a
        separate, narrow method rather than a field on `update()` — reassignment is rare (config
        import with a changed project_slug, or a future explicit "move server" admin action),
        and keeping it out of update()'s general field list avoids a project_id=None sentinel
        ambiguity (unlike upstream_auth_header, "don't reassign" here is simply "don't call
        this method" — there's no legitimate "clear the project" operation)."""
        current = await self.get(slug)
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE servers SET project_id = ?, updated_at = ? WHERE id = ?",
                (project_id, utcnow(), current.id),
            )
            await self._write.commit()
        return await self.get(slug)

    async def set_health(
        self, slug: str, health_status: str, upstream_protocol: Optional[str] = None,
        discover_json: Optional[str] = None, health_reason: Optional[str] = None,
    ) -> None:
        # Enterprise #5: health_reason is NOT COALESCE'd like upstream_protocol/discover_json
        # above — it must be overwritten with exactly what THIS probe found (None when the
        # cause wasn't a secret-resolution failure), or a stale reason from a previous failed
        # probe would keep showing after the server recovers or the cause changes to a plain
        # network outage.
        current = await self.get(slug)
        async with self._db.gateway_write_lock:
            await self._write.execute(
                """UPDATE servers SET health_status = ?, upstream_protocol = COALESCE(?, upstream_protocol),
                   discover_json = COALESCE(?, discover_json), health_reason = ?,
                   last_seen_at = ?, updated_at = ?
                   WHERE id = ?""",
                (health_status, upstream_protocol, discover_json, health_reason,
                 utcnow(), utcnow(), current.id),
            )
            await self._write.commit()

    async def get_policy(self, server_id: int) -> ServerPolicy:
        cur = await self._read.execute(
            "SELECT mode, rate_limit, dlp_config FROM server_policies WHERE server_id = ?", (server_id,)
        )
        row = await cur.fetchone()
        mode = row["mode"] if row else "passthrough"
        rate_limit = row["rate_limit"] if row else None
        dlp_detectors, dlp_custom_patterns = _decode_dlp_config(row["dlp_config"] if row else None)

        cur = await self._read.execute(
            "SELECT tool_name, action FROM tool_policies WHERE server_id = ?", (server_id,)
        )
        rows = await cur.fetchall()
        allowed = [r["tool_name"] for r in rows if r["action"] == "allow"]
        denied = [r["tool_name"] for r in rows if r["action"] == "deny"]

        cur = await self._read.execute(
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
            mode=mode, rate_limit=rate_limit, allowed=allowed, denied=denied, param_rules=param_rules,
            dlp_detectors=dlp_detectors, dlp_custom_patterns=dlp_custom_patterns,
        )

    async def get_policies_for(self, server_ids: list[int]) -> dict[int, ServerPolicy]:
        """F14 fix (review 2026-08-04): batched version of get_policy for the aggregate
        endpoint, which used to call get_policy() once PER SERVER (3 round-trips each) inside
        a loop — 3N queries for N registered servers. One query per table with
        `WHERE server_id IN (...)`, grouped in Python, returns the same data in 3 queries
        total regardless of how many servers are being fetched. Servers with no policy row yet
        get the same passthrough/no-rate-limit default get_policy() returns."""
        if not server_ids:
            return {}
        placeholders = ",".join("?" for _ in server_ids)

        cur = await self._read.execute(
            f"SELECT server_id, mode, rate_limit, dlp_config FROM server_policies WHERE server_id IN ({placeholders})",
            server_ids,
        )
        policy_rows = {r["server_id"]: r for r in await cur.fetchall()}

        cur = await self._read.execute(
            f"SELECT server_id, tool_name, action FROM tool_policies WHERE server_id IN ({placeholders})",
            server_ids,
        )
        allowed_by_id: dict[int, list[str]] = {sid: [] for sid in server_ids}
        denied_by_id: dict[int, list[str]] = {sid: [] for sid in server_ids}
        for r in await cur.fetchall():
            (allowed_by_id if r["action"] == "allow" else denied_by_id)[r["server_id"]].append(r["tool_name"])

        cur = await self._read.execute(
            f"""SELECT server_id, tool_name, param_name, max_length, max_value, min_value, denied, block_patterns
                FROM param_rules WHERE server_id IN ({placeholders})""",
            server_ids,
        )
        param_rules_by_id: dict[int, dict[str, dict[str, ParamRule]]] = {sid: {} for sid in server_ids}
        for r in await cur.fetchall():
            param_rules_by_id[r["server_id"]].setdefault(r["tool_name"], {})[r["param_name"]] = ParamRule(
                max_length=r["max_length"],
                max_value=r["max_value"],
                min_value=r["min_value"],
                denied=bool(r["denied"]),
                block_patterns=json.loads(r["block_patterns"]) if r["block_patterns"] else [],
            )

        result = {}
        for sid in server_ids:
            row = policy_rows.get(sid)
            dlp_detectors, dlp_custom_patterns = _decode_dlp_config(row["dlp_config"] if row else None)
            result[sid] = ServerPolicy(
                mode=row["mode"] if row else "passthrough",
                rate_limit=row["rate_limit"] if row else None,
                allowed=allowed_by_id[sid],
                denied=denied_by_id[sid],
                param_rules=param_rules_by_id[sid],
                dlp_detectors=dlp_detectors,
                dlp_custom_patterns=dlp_custom_patterns,
            )
        return result

    async def set_policy(self, server_id: int, policy: ServerPolicy) -> None:
        # F7: this is the exact multi-statement write (DELETE-then-reinsert across three
        # tables) that motivated the read/write connection split — see Database's docstring.
        # Readers use a SEPARATE WAL connection, so they only ever see the state before this
        # BEGIN IMMEDIATE or after this COMMIT — never the gap in between.
        async with self._db.gateway_write_lock:
            await self._write.execute("BEGIN IMMEDIATE")
            try:
                dlp_config_json = _encode_dlp_config(policy.dlp_detectors, policy.dlp_custom_patterns)
                await self._write.execute(
                    """INSERT INTO server_policies (server_id, mode, rate_limit, dlp_config, updated_at)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(server_id) DO UPDATE SET mode=excluded.mode,
                           rate_limit=excluded.rate_limit, dlp_config=excluded.dlp_config,
                           updated_at=excluded.updated_at""",
                    (server_id, policy.mode, policy.rate_limit, dlp_config_json, utcnow()),
                )
                await self._write.execute("DELETE FROM tool_policies WHERE server_id = ?", (server_id,))
                for tool_name in policy.allowed:
                    await self._write.execute(
                        "INSERT INTO tool_policies (server_id, tool_name, action) VALUES (?, ?, 'allow')",
                        (server_id, tool_name),
                    )
                for tool_name in policy.denied:
                    await self._write.execute(
                        "INSERT INTO tool_policies (server_id, tool_name, action) VALUES (?, ?, 'deny')",
                        (server_id, tool_name),
                    )
                await self._write.execute("DELETE FROM param_rules WHERE server_id = ?", (server_id,))
                for tool_name, params in policy.param_rules.items():
                    for param_name, rule in params.items():
                        await self._write.execute(
                            """INSERT INTO param_rules
                               (server_id, tool_name, param_name, max_length, max_value, min_value, denied, block_patterns)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                server_id, tool_name, param_name, rule.max_length, rule.max_value,
                                rule.min_value, int(rule.denied), json.dumps(rule.block_patterns),
                            ),
                        )
                await self._write.commit()
            except BaseException:
                await self._write.rollback()
                raise


class ApiKeyRepo:
    # F7: touch_last_used used to commit() on every authenticated data-plane request — a
    # gratuitous disk write on its own, and the specific trigger that made set_policy's
    # DELETE-then-reinsert race real (see Database's docstring). Debounced in-process rather
    # than removed outright, since "last used" is still useful for an operator auditing which
    # keys are stale — freshness within this window is a fine trade for not writing on every
    # single proxied call.
    _TOUCH_DEBOUNCE_SECONDS = 60

    def __init__(self, db: Database):
        self._db = db
        self._last_touch: dict[int, float] = {}

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

    async def create(self, name: str, key_hash: str, key_prefix: str,
                      server_scopes: Optional[list[str]] = None,
                      quota_calls: Optional[int] = None,
                      quota_period: Optional[str] = None,
                      project_id: Optional[int] = None) -> ApiKeyRecord:
        now = utcnow()
        async with self._db.gateway_write_lock:
            cur = await self._write.execute(
                """INSERT INTO api_keys
                   (name, key_hash, key_prefix, server_scopes, created_at, quota_calls, quota_period,
                    project_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, key_hash, key_prefix, json.dumps(server_scopes) if server_scopes else None, now,
                 quota_calls, quota_period, project_id),
            )
            await self._write.commit()
        return await self.get_by_id(cur.lastrowid)

    async def get_by_id(self, key_id: int) -> ApiKeyRecord:
        cur = await self._read.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,))
        row = await cur.fetchone()
        if row is None:
            raise ServerNotFoundError(str(key_id))
        return self._row_to_record(row)

    async def get_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        cur = await self._read.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND enabled = 1", (key_hash,)
        )
        row = await cur.fetchone()
        return self._row_to_record(row) if row else None

    async def list(self, project_id: Optional[int] = None) -> list[ApiKeyRecord]:
        # Enterprise #4: same None-means-unfiltered convention as ServerRepo.list.
        if project_id is not None:
            cur = await self._read.execute(
                "SELECT * FROM api_keys WHERE project_id = ? ORDER BY created_at DESC", (project_id,)
            )
        else:
            cur = await self._read.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
        rows = await cur.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def set_enabled(self, key_id: int, enabled: bool) -> None:
        async with self._db.gateway_write_lock:
            await self._write.execute("UPDATE api_keys SET enabled = ? WHERE id = ?", (int(enabled), key_id))
            await self._write.commit()

    async def set_quota(self, key_id: int, quota_calls: Optional[int], quota_period: Optional[str]) -> None:
        """Both fields are written together, always — a NULL quota_calls with a non-NULL
        quota_period (or vice versa) is a nonsensical half-state, so there is no partial-update
        path here the way ServerRepo.update has per-field optionality. Callers (the PATCH
        /keys/{id} route) pass both, always, even when clearing (None, None)."""
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE api_keys SET quota_calls = ?, quota_period = ? WHERE id = ?",
                (quota_calls, quota_period, key_id),
            )
            await self._write.commit()

    async def delete(self, key_id: int) -> None:
        async with self._db.gateway_write_lock:
            await self._write.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
            await self._write.commit()

    async def touch_last_used(self, key_id: int) -> None:
        now = time.monotonic()
        last = self._last_touch.get(key_id)
        if last is not None and (now - last) < self._TOUCH_DEBOUNCE_SECONDS:
            return
        self._last_touch[key_id] = now
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (utcnow(), key_id)
            )
            await self._write.commit()

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
            quota_calls=row["quota_calls"] if "quota_calls" in row.keys() else None,
            quota_period=row["quota_period"] if "quota_period" in row.keys() else None,
            project_id=row["project_id"] if "project_id" in row.keys() else None,
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
                decision, rule, matched, reason, args_summary, bridged, status_code, latency_ms,
                origin, dlp_detector, dlp_action, dlp_match_count)
               VALUES (:ts, :server_slug, :api_key_id, :client_ip, :endpoint, :rpc_method, :tool,
                       :decision, :rule, :matched, :reason, :args_summary, :bridged, :status_code,
                       :latency_ms, :origin, :dlp_detector, :dlp_action, :dlp_match_count)""",
            events,
        )
        await self._conn.commit()

    async def query(
        self, server_slug: Optional[str] = None, decision: Optional[str] = None,
        tool: Optional[str] = None, before_id: Optional[int] = None, limit: int = 100,
        api_key_id: Optional[int] = None, after: Optional[str] = None,
        before: Optional[str] = None, search: Optional[str] = None,
        origin: object = _UNSET, server_slug_in: Optional[list[str]] = None,
    ) -> list[dict]:
        """Newest-first. `before_id` is keyset pagination — pass the smallest `id` from the
        previous page to fetch the next (older) page, rather than an OFFSET (which re-scans
        and can skip/duplicate rows under concurrent inserts).

        `after`/`before` are inclusive ISO-timestamp bounds on `ts`. `search` matches against
        `reason`, `args_summary`, and `matched`; `%`/`_` in the term are escaped so a literal
        search (e.g. "100%") isn't interpreted as a SQL LIKE wildcard.

        `origin` uses the `_UNSET` sentinel (like `ServerRepo.update`'s `upstream_auth_header`)
        because `None` is a meaningful value here — "give me only normal traffic" — distinct from
        "don't filter on origin at all" (the default, returning both normal and 'test' rows).
        A plain `Optional[str] = None` couldn't express the first case.

        `server_slug_in` (enterprise #4): audit_events lives in audit.db, a SEPARATE SQLite file/
        connection from gateway.db where servers/projects live — there is no SQL JOIN across
        them. Project-scoped callers (archon/api.py's GET /audit etc.) resolve their project's
        server slugs via ServerRepo.list(project_id=...) first, then pass that slug set here as
        an `IN (...)` filter, composing with (not replacing) the single-slug `server_slug` filter
        above. An empty list means "this project has zero servers" and must match ZERO rows, not
        every row — handled explicitly below since `IN ()` is invalid SQL."""
        clauses, params = [], []
        if server_slug:
            clauses.append("server_slug = ?")
            params.append(server_slug)
        if server_slug_in is not None:
            if not server_slug_in:
                # Zero servers in this project -> zero possible audit rows. `1=0` short-circuits
                # without needing special-case Python-side handling of an empty result set.
                clauses.append("1=0")
            else:
                placeholders = ",".join("?" for _ in server_slug_in)
                clauses.append(f"server_slug IN ({placeholders})")
                params.extend(server_slug_in)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        if api_key_id is not None:
            clauses.append("api_key_id = ?")
            params.append(api_key_id)
        if after:
            clauses.append("ts >= ?")
            params.append(after)
        if before:
            clauses.append("ts <= ?")
            params.append(before)
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            clauses.append("(reason LIKE ? ESCAPE '\\' OR args_summary LIKE ? ESCAPE '\\' OR matched LIKE ? ESCAPE '\\')")
            params.extend([like, like, like])
        if origin is not _UNSET:
            if origin is None:
                clauses.append("origin IS NULL")
            else:
                clauses.append("origin = ?")
                params.append(origin)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        cur = await self._conn.execute(
            f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?", params
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def count_since(
        self, since_iso: str, decision: Optional[str] = None,
        server_slug_in: Optional[list[str]] = None,
    ) -> int:
        # Always excludes origin='test' (Try-it calls) — this backs /stats, and a dashboard
        # counter that moves every time an operator tests their own policy would be useless.
        clauses, params = ["ts >= ?", "origin IS NULL"], [since_iso]
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if server_slug_in is not None:
            if not server_slug_in:
                clauses.append("1=0")
            else:
                placeholders = ",".join("?" for _ in server_slug_in)
                clauses.append(f"server_slug IN ({placeholders})")
                params.extend(server_slug_in)
        cur = await self._conn.execute(
            f"SELECT COUNT(*) FROM audit_events WHERE {' AND '.join(clauses)}", params
        )
        row = await cur.fetchone()
        return row[0] if row else 0

    async def prune_older_than(self, cutoff_iso: str, batch_size: int = 5000) -> int:
        # §26 fix (review 2026-08-04): a single unbounded DELETE here could touch an
        # arbitrarily large number of rows in one transaction — e.g. after retention was
        # disabled for a while and a large backlog built up. audit.db has a single connection
        # (AuditLogger's batched flush is its only normal writer), and a long-running DELETE
        # transaction would block that flush loop from persisting new events for however long
        # the DELETE takes. SQLite has no native DELETE ... LIMIT, so batch via rowid subquery
        # instead, committing between batches so the flush loop never waits longer than one
        # batch's worth of work.
        total_deleted = 0
        while True:
            cur = await self._conn.execute(
                "DELETE FROM audit_events WHERE id IN "
                "(SELECT id FROM audit_events WHERE ts < ? LIMIT ?)",
                (cutoff_iso, batch_size),
            )
            await self._conn.commit()
            deleted = cur.rowcount if cur.rowcount is not None else 0
            total_deleted += deleted
            if deleted < batch_size:
                break
        return total_deleted


def _hour_bucket(ts_iso: str) -> str:
    """Truncate an ISO8601 UTC timestamp (the same format AuditLogger/utcnow() produce
    everywhere else in this codebase) down to the top of its hour, in UTC.

    Deliberately parses and re-serializes via datetime rather than string-slicing the ISO text
    (`ts_iso[:13] + ":00:00+00:00"`) — a naive slice breaks the instant a timestamp isn't
    exactly the `+00:00` suffix shape (e.g. a `Z` suffix, or a differing UTC-offset
    representation), which is exactly the class of bug stoa/retention.py's §26 fix (its own
    header comment) had to work around for the same reason. Going through datetime.fromisoformat
    normalizes the input shape before truncation, so this stays correct regardless of which
    valid ISO8601 spelling produced the timestamp."""
    dt = datetime.fromisoformat(ts_iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(minute=0, second=0, microsecond=0).isoformat()


# Sentinel values standing in for NULL on usage_rollups' NOT NULL grouping columns — see
# 0010_usage_rollups.sql's comment on why NULL can't be used here (SQLite's UNIQUE constraint
# treats NULL as never-equal-to-itself, which would silently defeat the upsert). 0 is never a
# real api_keys.id/servers.id (SQLite AUTOINCREMENT starts at 1); '' is never a real tool name
# (argus/policy.py rejects an empty tools/call name before it ever reaches this far). Translated
# at this module boundary only — every OTHER method in this codebase that touches api_key_id/
# tool keeps using Optional[int]/Optional[str] with real None, matching AuditLogger.log's own
# shape, so this repo's public methods take the same Optional types callers already use
# elsewhere and never leak the sentinel outward.
_NO_KEY = 0
_NO_SERVER = 0
_NO_TOOL = ""


def _to_key_sentinel(api_key_id: Optional[int]) -> int:
    return api_key_id if api_key_id is not None else _NO_KEY


def _to_server_sentinel(server_id: Optional[int]) -> int:
    return server_id if server_id is not None else _NO_SERVER


def _to_tool_sentinel(tool: Optional[str]) -> str:
    return tool if tool is not None else _NO_TOOL


class UsageRepo:
    """Enterprise #11 (quotas + usage attribution): durable call-count rollups, one row per
    (UTC hour bucket, api_key_id, server_id, tool).

    Lives in gateway.db, NOT audit.db — see 0010_usage_rollups.sql's header comment for why
    (the short version: AuditRetentionJob prunes audit.db on a rolling window; a usage rollup
    that lived there would lose exactly the history an operator most wants to look back over).

    `increment` is called from the SAME code path that emits the audit event
    (argus/pipeline.py, right where AuditLogger.log() is called for an ALLOWED/BLOCKED
    tools/call), synchronously, so a rollup count can never drift from what the audit log shows
    for the same window — see tests/integration/test_quotas.py's
    TestRollupsMatchAuditRows for the test that proves this by direct comparison.

    Every method here is written to be called from Pipeline's fail-OPEN quota-check wrapper
    (see Pipeline._check_quota) — a DB error surfacing out of increment/total_since is caught
    by the CALLER, not swallowed here, so this class stays a plain, honest repo with no
    fail-open policy baked into it; the policy decision belongs to the enforcement point, not
    the data-access layer.
    """

    def __init__(self, db: Database):
        self._db = db

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

    async def increment(
        self, *, ts_iso: str, api_key_id: Optional[int], server_id: Optional[int],
        tool: Optional[str], amount: int = 1, project_id: Optional[int] = None,
    ) -> None:
        """Increments the (hour bucket, api_key_id, server_id, tool) row by `amount`, creating
        it if it doesn't exist yet. One call per forwarded tools/call — called unconditionally
        (even for a key with no quota configured and even for api_key_id=None under open auth
        mode) so the usage query endpoint has real data to show regardless of whether any quota
        is enforced; enforcement (quota check) and measurement (this rollup) are independent
        concerns, same as how RateLimiterRegistry.check_all and AuditLogger.log are independent
        today.

        UNIQUE(period_start, api_key_id, server_id, tool) plus ON CONFLICT DO UPDATE makes this
        a single atomic upsert rather than a read-then-write race between concurrent requests
        landing in the same hour bucket for the same key/server/tool.

        `project_id` (enterprise #4) is NOT part of the UNIQUE constraint — a given
        (period_start, api_key_id, server_id, tool) combination has exactly one project_id in
        practice (a server belongs to exactly one project), so it rides along as a plain column,
        set on insert and refreshed on conflict via COALESCE so an existing pre-migration row
        (project_id NULL, backfilled separately by 0011_projects.sql) gets populated by the next
        real increment rather than staying NULL forever if the backfill's own UPDATE somehow
        missed it."""
        period_start = _hour_bucket(ts_iso)
        async with self._db.gateway_write_lock:
            await self._write.execute(
                """INSERT INTO usage_rollups
                   (period_start, period_kind, api_key_id, server_id, tool, calls, project_id)
                   VALUES (?, 'hour', ?, ?, ?, ?, ?)
                   ON CONFLICT(period_start, api_key_id, server_id, tool)
                   DO UPDATE SET calls = calls + excluded.calls,
                       project_id = COALESCE(usage_rollups.project_id, excluded.project_id)""",
                (period_start, _to_key_sentinel(api_key_id), _to_server_sentinel(server_id),
                 _to_tool_sentinel(tool), amount, project_id),
            )
            await self._write.commit()

    async def total_since(self, *, api_key_id: int, since_iso: str) -> int:
        """Sum of `calls` across every hour bucket with period_start >= since_iso, for one key
        — the quota-enforcement read. `since_iso` is the caller-computed start of the current
        quota period (start of today or start of this month, in UTC); summing hourly buckets
        rather than storing a running total keeps this correct across period boundaries without
        a separate reset job (see docs/quotas.md's "why hourly buckets" section)."""
        cur = await self._read.execute(
            "SELECT COALESCE(SUM(calls), 0) FROM usage_rollups WHERE api_key_id = ? AND period_start >= ?",
            (api_key_id, since_iso),
        )
        row = await cur.fetchone()
        return row[0] if row else 0

    async def query(
        self, *, api_key_id: Optional[int] = None, server_id: Optional[int] = None,
        tool: Optional[str] = None, since_iso: Optional[str] = None,
        until_iso: Optional[str] = None, project_id: Optional[int] = None,
    ) -> list[dict]:
        """Returns raw hourly-bucket rows matching the given filters, newest first. The
        `/api/v1/usage` route (viewer+) sums these client-side per its `group_by` — kept here
        as raw buckets rather than pre-aggregated SQL per grouping, since the set of useful
        groupings (by key, by server, by tool, by day, by month) is small enough that summing
        in Python over a bounded row set is simpler than N bespoke GROUP BY queries, and this
        table is never expected to hold traffic-log volumes (one row per key/server/tool per
        HOUR, not per call).

        Filters use the SAME sentinel translation as increment — passing api_key_id=None means
        "don't filter on key" (matches every row, sentinel or not), NOT "filter for the
        no-key sentinel"; use api_key_id=0 explicitly (rare, control-plane-only) to query
        specifically the open-auth-mode bucket.

        `project_id` (enterprise #4): filters on the rollup's own project_id column (populated
        at increment-time and by 0011_projects.sql's backfill) — unlike AuditRepo, usage_rollups
        lives in gateway.db alongside servers/projects, so this can be a real column filter
        rather than needing a slug-set IN-list."""
        clauses, params = [], []
        if api_key_id is not None:
            clauses.append("api_key_id = ?")
            params.append(api_key_id)
        if server_id is not None:
            clauses.append("server_id = ?")
            params.append(server_id)
        if tool is not None:
            clauses.append("tool = ?")
            params.append(tool)
        if since_iso is not None:
            clauses.append("period_start >= ?")
            params.append(since_iso)
        if until_iso is not None:
            clauses.append("period_start <= ?")
            params.append(until_iso)
        if project_id is not None:
            clauses.append("project_id = ?")
            params.append(project_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur = await self._read.execute(
            f"""SELECT period_start, api_key_id, server_id, tool, calls
                FROM usage_rollups {where} ORDER BY period_start DESC""",
            params,
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


class SettingsRepo:
    """Key-value store for gateway-wide settings (auth_mode, aggregate default, retention,
    admin credentials). Values are stored as plain strings; callers coerce types."""

    def __init__(self, db: Database):
        self._db = db

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

    async def get(self, key: str) -> Optional[str]:
        cur = await self._read.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cur.fetchone()
        return row["value"] if row else None

    async def get_all(self) -> dict[str, str]:
        cur = await self._read.execute("SELECT key, value FROM settings")
        rows = await cur.fetchall()
        return {r["key"]: r["value"] for r in rows}

    async def set(self, key: str, value: str) -> None:
        async with self._db.gateway_write_lock:
            await self._write.execute(
                """INSERT INTO settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                (key, value),
            )
            await self._write.commit()

    async def set_many(self, values: dict[str, str]) -> None:
        # F7: batch into ONE transaction under the write lock, rather than N separate set()
        # calls each taking/releasing the lock — avoids interleaving another writer's change
        # between two settings that are logically saved together (e.g. the setup wizard writing
        # admin_password_hash + session_secret + auth_mode as one atomic unit).
        async with self._db.gateway_write_lock:
            await self._write.execute("BEGIN IMMEDIATE")
            try:
                for key, value in values.items():
                    await self._write.execute(
                        """INSERT INTO settings (key, value) VALUES (?, ?)
                           ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                        (key, value),
                    )
                await self._write.commit()
            except BaseException:
                await self._write.rollback()
                raise


class AdminEventRecord(BaseModel):
    id: int
    ts: str
    actor: Optional[str] = None  # NULL until identity milestone; 'admin-session' | 'admin-token' | 'cli'
    action: str  # server.create | server.update | server.delete | policy.update | key.create | key.disable | key.delete | settings.update | config.import
    target_type: Optional[str] = None  # 'server' | 'key' | 'settings' | 'config'
    target_id: Optional[str] = None  # slug, key id, or NULL
    before: Optional[str] = None  # JSON, allowlisted fields only, NULL on create
    after: Optional[str] = None  # JSON, allowlisted fields only, NULL on delete
    client_ip: Optional[str] = None
    summary: str  # human-readable, e.g. "mode: allowlist -> passthrough"

    def parse_before(self) -> Optional[dict]:
        """Parse the before JSON into a dict. Returns None if before is NULL."""
        if self.before is None:
            return None
        import json
        return json.loads(self.before)

    def parse_after(self) -> Optional[dict]:
        """Parse the after JSON into a dict. Returns None if after is NULL."""
        if self.after is None:
            return None
        import json
        return json.loads(self.after)


class AdminEventRepo:
    """Control-plane audit log — records administrative actions (server CRUD, policy changes,
    key mint/revoke, settings changes, config imports).

    Distinct from AuditRepo (data-plane traffic log): these are low-volume, high-value events
    that must survive long-term. Stored in gateway.db (not audit.db) so a config restore brings
    its own change history. NEVER pruned by AuditRetentionJob — that job only touches audit.db.
    """

    def __init__(self, db: Database):
        self._db = db

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

    async def insert(
        self,
        *,
        action: str,
        summary: str,
        actor: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        before: Optional[str] = None,
        after: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> int:
        """Insert one admin event. Returns the new row id."""
        async with self._db.gateway_write_lock:
            cur = await self._write.execute(
                """INSERT INTO admin_events (ts, actor, action, target_type, target_id, before, after, client_ip, summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (utcnow(), actor, action, target_type, target_id, before, after, client_ip, summary),
            )
            await self._write.commit()
            return cur.lastrowid

    async def query(
        self,
        *,
        action: Optional[str] = None,
        target_type: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 500,
    ) -> list[AdminEventRecord]:
        """Query admin events with optional filters. Follows AuditRepo.query conventions."""
        clauses = []
        params: list = []

        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if target_type is not None:
            clauses.append("target_type = ?")
            params.append(target_type)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)

        where = " AND ".join(clauses) if clauses else "1=1"
        limit = min(limit, 500)

        cur = await self._read.execute(
            f"""SELECT id, ts, actor, action, target_type, target_id, before, after, client_ip, summary
                FROM admin_events
                WHERE {where}
                ORDER BY ts DESC
                LIMIT ?""",
            (*params, limit),
        )
        rows = await cur.fetchall()
        return [
            AdminEventRecord(
                id=row["id"],
                ts=row["ts"],
                actor=row["actor"],
                action=row["action"],
                target_type=row["target_type"],
                target_id=row["target_id"],
                before=row["before"],
                after=row["after"],
                client_ip=row["client_ip"],
                summary=row["summary"],
            )
            for row in rows
        ]


def _row_to_user(row: aiosqlite.Row) -> UserRecord:
    return UserRecord(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        password_hash=row["password_hash"],
        role=row["role"],
        auth_source=row["auth_source"],
        oidc_subject=row["oidc_subject"],
        enabled=bool(row["enabled"]),
        session_version=row["session_version"],
        created_at=row["created_at"],
        last_login_at=row["last_login_at"],
    )


class UserRepo:
    """CRUD for the `users` table — local + OIDC control-plane principals (enterprise #1/#2).

    F7-style discipline: reads go through the dedicated read connection, writes serialize
    through `gateway_write_lock` on the writer connection, same as every other repo in this
    module — `users` lives in gateway.db alongside servers/keys/settings, not a separate store.
    """

    def __init__(self, db: Database):
        self._db = db

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

    async def count(self) -> int:
        """Used by archon/admin_auth.py to decide whether to fall back to the legacy
        settings-based admin check — an empty/absent `users` table means a partially-applied
        upgrade or a pre-migration database, and must degrade to "still works", not "locked out"."""
        cur = await self._read.execute("SELECT COUNT(*) FROM users")
        row = await cur.fetchone()
        return row[0] if row else 0

    async def get_by_id(self, user_id: int) -> UserRecord:
        cur = await self._read.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone()
        if row is None:
            raise UserNotFoundError(str(user_id))
        return _row_to_user(row)

    async def get_by_username(self, username: str) -> Optional[UserRecord]:
        cur = await self._read.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = await cur.fetchone()
        return _row_to_user(row) if row else None

    async def get_by_subject(self, oidc_subject: str) -> Optional[UserRecord]:
        # Keyed on oidc_subject (IdP 'sub'), never email — see 0007_users.sql's header comment.
        cur = await self._read.execute("SELECT * FROM users WHERE oidc_subject = ?", (oidc_subject,))
        row = await cur.fetchone()
        return _row_to_user(row) if row else None

    async def list(self) -> list[UserRecord]:
        cur = await self._read.execute("SELECT * FROM users ORDER BY username")
        rows = await cur.fetchall()
        return [_row_to_user(r) for r in rows]

    async def create(
        self,
        username: str,
        role: str,
        password_hash: Optional[str] = None,
        email: Optional[str] = None,
        auth_source: str = "local",
        oidc_subject: Optional[str] = None,
        enabled: bool = True,
    ) -> UserRecord:
        # Self-review fix: the pre-flight username check below doesn't (and can't, on its own)
        # rule out a concurrent oidc_subject collision — two simultaneous JIT-provisioning
        # calls for the same brand-new `sub` (e.g. a double-clicked "Sign in with SSO", or two
        # browser tabs) can both pass UserRepo.get_or_create_from_oidc's `existing is None`
        # check before either has committed. The `oidc_subject UNIQUE` constraint in
        # 0007_users.sql is the real backstop; without catching its violation here, the loser of
        # the race got an unhandled aiosqlite.IntegrityError (a 500) instead of a clean outcome.
        # Caught and converted to UsernameConflictError so callers (get_or_create_from_oidc's
        # retry loop, and archon/setup.py's callback handler) have one exception shape to
        # handle regardless of which UNIQUE constraint actually fired.
        async with self._db.gateway_write_lock:
            existing = await self._write.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if await existing.fetchone() is not None:
                raise UsernameConflictError(username)
            now = utcnow()
            try:
                cur = await self._write.execute(
                    """INSERT INTO users
                       (username, email, password_hash, role, auth_source, oidc_subject, enabled, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (username, email, password_hash, role, auth_source, oidc_subject, int(enabled), now),
                )
            except aiosqlite.IntegrityError as e:
                raise UsernameConflictError(username) from e
            await self._write.commit()
            new_id = cur.lastrowid
        return await self.get_by_id(new_id)

    async def update_role(self, user_id: int, role: str) -> UserRecord:
        async with self._db.gateway_write_lock:
            await self._write.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            await self._write.commit()
        return await self.get_by_id(user_id)

    async def set_enabled(self, user_id: int, enabled: bool) -> UserRecord:
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE users SET enabled = ? WHERE id = ?", (int(enabled), user_id)
            )
            await self._write.commit()
        return await self.get_by_id(user_id)

    async def set_password_hash(self, user_id: int, password_hash: str) -> UserRecord:
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
            )
            await self._write.commit()
        return await self.get_by_id(user_id)

    async def touch_last_login(self, user_id: int) -> None:
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?", (utcnow(), user_id)
            )
            await self._write.commit()

    async def bump_session_version(self, user_id: int) -> int:
        """Per-user analogue of the global session_version bump in settings — invalidates every
        outstanding session token for exactly this one user (disable, role change, password
        change, explicit logout-all-for-this-user), without touching anyone else's session."""
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user_id,)
            )
            await self._write.commit()
            cur = await self._write.execute(
                "SELECT session_version FROM users WHERE id = ?", (user_id,)
            )
            row = await cur.fetchone()
            return row["session_version"] if row else 0

    async def get_or_create_from_oidc(
        self,
        *,
        subject: str,
        email: Optional[str],
        default_role: str,
        preferred_username: Optional[str] = None,
    ) -> UserRecord:
        """JIT provisioning (enterprise #1): first successful OIDC login for an unknown `sub`
        creates a user. Callers are responsible for the allowlist check (domain/group) BEFORE
        calling this — this method assumes provisioning has already been authorized and just
        does the DB work. Keyed on subject, never email, so two IdP accounts sharing an email
        address (an IdP misconfiguration, not something this app can prevent) still resolve to
        two distinct local users rather than silently merging."""
        existing = await self.get_by_subject(subject)
        if existing is not None:
            return existing

        # Username must be unique locally; the IdP's preferred_username/email has no such
        # guarantee. Fall back to a subject-derived name and disambiguate on conflict rather
        # than fail JIT provisioning outright.
        base = preferred_username or (email.split("@")[0] if email else None) or f"oidc-{subject[:8]}"
        username = base
        suffix = 0
        while True:
            try:
                return await self.create(
                    username=username, role=default_role, email=email,
                    auth_source="oidc", oidc_subject=subject,
                )
            except UsernameConflictError:
                # Self-review fix: create() now raises this same exception for EITHER a
                # username collision OR a concurrent oidc_subject collision (see its own
                # comment) — the latter happens when two simultaneous logins for the same new
                # `sub` both passed the `existing is None` check above before either committed.
                # Re-checking by subject distinguishes the two cases: if a row for this subject
                # exists now, the other request won the race and this one should simply return
                # its result rather than spin through up to 50 username suffixes for a conflict
                # that was never actually about the username.
                existing = await self.get_by_subject(subject)
                if existing is not None:
                    return existing
                suffix += 1
                username = f"{base}-{suffix}"
                if suffix > 50:
                    # Pathological collision storm — fail loudly rather than loop forever.
                    raise


def _row_to_project(row: aiosqlite.Row) -> ProjectRecord:
    return ProjectRecord(id=row["id"], slug=row["slug"], name=row["name"], created_at=row["created_at"])


class ProjectRepo:
    """CRUD for `projects` (enterprise #4, issue #5). Deliberately thin — no membership logic
    here (see ProjectMemberRepo below); this repo only owns the project row itself."""

    def __init__(self, db: Database):
        self._db = db

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

    async def list(self) -> list[ProjectRecord]:
        cur = await self._read.execute("SELECT * FROM projects ORDER BY slug")
        rows = await cur.fetchall()
        return [_row_to_project(r) for r in rows]

    async def get(self, slug: str) -> ProjectRecord:
        cur = await self._read.execute("SELECT * FROM projects WHERE slug = ?", (slug,))
        row = await cur.fetchone()
        if row is None:
            raise ProjectNotFoundError(slug)
        return _row_to_project(row)

    async def get_by_id(self, project_id: int) -> ProjectRecord:
        cur = await self._read.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        row = await cur.fetchone()
        if row is None:
            raise ProjectNotFoundError(str(project_id))
        return _row_to_project(row)

    async def create(self, slug: str, name: str) -> ProjectRecord:
        async with self._db.gateway_write_lock:
            existing = await self._write.execute("SELECT 1 FROM projects WHERE slug = ?", (slug,))
            if await existing.fetchone() is not None:
                raise ProjectSlugConflictError(slug)
            now = utcnow()
            cur = await self._write.execute(
                "INSERT INTO projects (slug, name, created_at) VALUES (?, ?, ?)",
                (slug, name, now),
            )
            await self._write.commit()
        return await self.get_by_id(cur.lastrowid)

    async def delete(self, slug: str) -> None:
        # ON DELETE CASCADE on project_members handles membership cleanup. Servers/keys are NOT
        # cascade-deleted (no ON DELETE clause on their project_id FK) — deleting a project that
        # still owns servers/keys is refused at the API layer (archon/api.py) with a clear error
        # rather than silently orphaning or cascading away real infrastructure; see that route's
        # own comment for the exact check.
        current = await self.get(slug)
        async with self._db.gateway_write_lock:
            await self._write.execute("DELETE FROM projects WHERE id = ?", (current.id,))
            await self._write.commit()


def _row_to_member(row: aiosqlite.Row) -> ProjectMemberRecord:
    return ProjectMemberRecord(user_id=row["user_id"], project_id=row["project_id"], role=row["role"])


class ProjectMemberRepo:
    """CRUD for `project_members` — the (user_id, project_id) -> role membership table backing
    archon/project_rbac.py's `require_project_role`. Every read here is the DB-is-authoritative
    lookup that dependency performs on every request (no caching), same discipline as
    archon/admin_auth.py's auth_mode/session_version checks."""

    def __init__(self, db: Database):
        self._db = db

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

    async def get_membership(self, *, user_id: int, project_id: int) -> Optional[ProjectMemberRecord]:
        cur = await self._read.execute(
            "SELECT * FROM project_members WHERE user_id = ? AND project_id = ?",
            (user_id, project_id),
        )
        row = await cur.fetchone()
        return _row_to_member(row) if row else None

    async def list_for_project(self, project_id: int) -> list[ProjectMemberRecord]:
        cur = await self._read.execute(
            "SELECT * FROM project_members WHERE project_id = ? ORDER BY user_id", (project_id,)
        )
        rows = await cur.fetchall()
        return [_row_to_member(r) for r in rows]

    async def list_for_user(self, user_id: int) -> list[ProjectMemberRecord]:
        """Every project a user has an explicit membership row in. NOTE: this does NOT include
        projects a global admin can access via the superset short-circuit — that's not a
        membership row, by design (see archon/project_rbac.py's module docstring). A global
        admin calling this sees only their EXPLICIT memberships, if any; callers that need "every
        project this principal can act on" (e.g. the frontend's project switcher) must special-
        case principal.role == 'admin' -> list every project, same as
        resolve_project_role does for a single project."""
        cur = await self._read.execute(
            "SELECT * FROM project_members WHERE user_id = ? ORDER BY project_id", (user_id,)
        )
        rows = await cur.fetchall()
        return [_row_to_member(r) for r in rows]

    async def upsert(self, *, user_id: int, project_id: int, role: str) -> ProjectMemberRecord:
        async with self._db.gateway_write_lock:
            await self._write.execute(
                """INSERT INTO project_members (user_id, project_id, role) VALUES (?, ?, ?)
                   ON CONFLICT(user_id, project_id) DO UPDATE SET role = excluded.role""",
                (user_id, project_id, role),
            )
            await self._write.commit()
        return await self.get_membership(user_id=user_id, project_id=project_id)

    async def remove(self, *, user_id: int, project_id: int) -> None:
        async with self._db.gateway_write_lock:
            await self._write.execute(
                "DELETE FROM project_members WHERE user_id = ? AND project_id = ?",
                (user_id, project_id),
            )
            await self._write.commit()
