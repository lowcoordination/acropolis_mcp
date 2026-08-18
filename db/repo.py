from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from pydantic import ValidationError

from .database import Database, acquire_with_timeout, utcnow
from .models import (
    AdminEventRecord,
    ApiKeyRecord,
    DlpCustomPattern,
    ParamRule,
    ProjectMemberRecord,
    ProjectRecord,
    ProposalRecord,
    ServerPolicy,
    ServerRecord,
    UserRecord,
)

logger = logging.getLogger("db.repo")

_UNSET = object()  # sentinel: distinguishes "argument omitted" from "argument is None"


# ─── gateway_write_lock conversion ───────────────────────────────────────────────────────────
#
# No per-process write lock in this module, deliberately: the old gateway_write_lock existed to
# serialize writes for SQLite's single writer — and being per-process, a second replica would
# not have contended for it, so the invariants it protected would have silently stopped holding
# in a multi-replica deployment. Postgres enforces the same invariants in the database, where
# they hold across processes.
#
# Each write path names the replacement shape in its inline comment: [SINGLE-STATEMENT] (one
# atomic statement), [TRANSACTION] (all-or-nothing multi-statement), [UPSERT] / [ATOMIC-RMW]
# (read-modify-write collapsed into one statement), [FOR UPDATE] (check-then-act across
# statements). Check-slug-then-INSERT paths keep a pre-flight SELECT only for a clean typed
# error — the UNIQUE constraint is what makes them correct, with UniqueViolationError converted
# to the same conflict exception. Race coverage: tests/integration/test_postgres_races.py.
# ──────────────────────────────────────────────────────────────────────────────────────────────


# DLP: dlp_detectors + dlp_custom_patterns are stored as ONE JSON TEXT column
# (server_policies.dlp_config, migration 0008_gateway_dlp_config.sql) rather than further
# normalized tables — see that migration's comment for why JSON-in-a-column (not per-detector
# rows) is the call made here.
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


class ProposalNotFoundError(Exception):
    pass


def _row_to_server(row: asyncpg.Record) -> ServerRecord:
    # The `if "x" in row.keys()` guards the SQLite version carried on health_reason/project_id
    # are gone: they defended against reading a row from a database where a later ALTER TABLE
    # hadn't run yet, which was reachable because some tests built bare connections against a
    # partially-migrated schema. Post-cutover every connection goes through Database.connect(),
    # which applies the full migration set before handing back a pool, so these columns always
    # exist. asyncpg.Record supports `in` via its keys() the same way, so the guard could have
    # been kept — dropped deliberately, because it silently masked "you're talking to an
    # unmigrated database" as "this field is None".
    return ServerRecord(
        id=row["id"],
        slug=row["slug"],
        name=row["name"],
        upstream_url=row["upstream_url"],
        enabled=bool(row["enabled"]),
        in_aggregate=bool(row["in_aggregate"]),
        upstream_protocol=row["upstream_protocol"],
        health_status=row["health_status"],
        health_reason=row["health_reason"],
        last_seen_at=row["last_seen_at"],
        discover_json=row["discover_json"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        upstream_auth_header=row["upstream_auth_header"],
        project_id=row["project_id"],
    )


async def _default_project_id(conn: asyncpg.Connection) -> Optional[int]:
    """Resolves the backfilled 'default' project's id, used by ServerRepo.create/
    ApiKeyRepo.create as the fallback when a caller passes project_id=None (or omits it) —
    NOT left as a literal NULL row. Every server/key created through the real control-plane API
    already resolves an explicit project_id before calling these methods (archon/api.py's
    _resolve_project_id, defaulting to "default" via ServerCreateRequest/KeyCreateRequest's own
    project_slug default) — this fallback exists for every OTHER caller (the CLI import path,
    direct repo access in tests that predate projects, any future internal caller) so a resource
    created without an explicit project_id still lands somewhere real rather than in a NULL-
    project limbo that every project-scoping filter (and the pipeline's key/server agreement
    check) would then treat as "belongs to no project" and silently exclude/refuse.

    Returns None only if 'default' itself doesn't exist yet — unreachable post-migration on any
    real database, since 0010_projects.sql always creates it. Callers treat that None exactly
    like an explicitly-passed None, i.e. the row's project_id stays NULL, consistent with the
    migration's own fail-closed discipline rather than raising.

    The pre-cutover version also caught aiosqlite.OperationalError here, to survive being handed a
    connection whose schema predated the projects migration. That branch is dropped: every
    connection now comes from a pool built by Database.connect(), which applies migrations before
    returning, so a missing `projects` table means something is genuinely wrong and should
    surface rather than be silently absorbed into a NULL project_id.
    """
    return await conn.fetchval("SELECT id FROM projects WHERE slug = 'default'")


class _PoolAccess:
    """Shared pool accessors for every repo in this module.

    Replaces the per-repo `_read`/`_write` properties that each returned one of Database's three
    long-lived aiosqlite connections (and re-set `row_factory` on every access). Reads acquire
    from the reader pool, writes from the writer pool; both are async context managers, so a
    connection is ALWAYS returned to its pool on the way out, including on an exception path —
    which the old shared-connection model had no notion of, because nothing was ever acquired or
    released in the first place.
    """

    def __init__(self, db: Database):
        self._db = db

    def _read(self):
        assert self._db.reader is not None, "Database.connect() not awaited"
        return acquire_with_timeout(self._db.reader, self._db.POOL_ACQUIRE_TIMEOUT)

    def _write(self):
        assert self._db.writer is not None, "Database.connect() not awaited"
        return acquire_with_timeout(self._db.writer, self._db.POOL_ACQUIRE_TIMEOUT)


class _Where:
    """Parameterized WHERE-clause builder shared by this module's query methods.

    Replaces the per-method `clauses, params = [], []` + nested `def _p(value)` closure
    that was copied (with slight variations) into AuditRepo.query / count_since,
    UsageRepo.query, AdminEventRepo.query and ProposalRepo.list. The closure's one job —
    bind a value and return its positional placeholder — is easy to get subtly wrong when
    re-derived per method (a `$N` miscount silently shifts every parameter), and the
    conventions that must stay consistent across methods (None means "don't filter", an
    EMPTY list means "match nothing" via 1=0, every caller-supplied VALUE is a bound
    parameter) are now expressed once, in one place.

    Deliberately tiny: it knows no table or column, only the shapes every WHERE in this
    module actually needs (`column = $n`, `column >= $n`, `column = ANY($n)`), plus a
    raw-clause escape hatch for the few conditions that fit neither (the LIKE-triple in
    AuditRepo.query, the fixed `origin IS NULL` in count_since) and a `bind()` for values
    that appear in a non-filter position (LIMIT) or want one parameter referenced several
    times (AuditRepo.query's LIKE triple binds the same value once and reuses the
    placeholder in all three branches, instead of three identical parameters).
    """

    def __init__(self) -> None:
        self._clauses: list[str] = []
        self._params: list = []

    def eq(self, column: str, value) -> "_Where":
        """`column = $n` — skipped when value is None (None means "don't filter", the
        module-wide convention; it is never a legitimate filter value)."""
        if value is not None:
            self._clauses.append(f"{column} = {self._bind(value)}")
        return self

    def ge(self, column: str, value) -> "_Where":
        """`column >= $n` — the inclusive-lower-bound shape used for `since` filters."""
        if value is not None:
            self._clauses.append(f"{column} >= {self._bind(value)}")
        return self

    def le(self, column: str, value) -> "_Where":
        """`column <= $n` — the inclusive-upper-bound shape used for `until` filters."""
        if value is not None:
            self._clauses.append(f"{column} <= {self._bind(value)}")
        return self

    def lt(self, column: str, value) -> "_Where":
        """`column < $n` — the exclusive-upper-bound shape (audit keyset pagination)."""
        if value is not None:
            self._clauses.append(f"{column} < {self._bind(value)}")
        return self

    def any_of(self, column: str, values) -> "_Where":
        """`column = ANY($n)` with the list bound as one array parameter. An EMPTY list
        becomes `1=0` — "no possible rows" — the convention AuditRepo.query/count_since
        already used for a project with zero servers (an empty IN-list must match nothing,
        not everything)."""
        if not values:
            self._clauses.append("1=0")
        else:
            self._clauses.append(f"{column} = ANY({self._bind(values)})")
        return self

    def is_null(self, column: str) -> "_Where":
        """`column IS NULL` — for filters where NULL is a meaningful value (audit origin)."""
        self._clauses.append(f"{column} IS NULL")
        return self

    def raw(self, clause: str) -> "_Where":
        """Add a pre-built clause with no parameters of its own (e.g. `origin IS NULL`)."""
        self._clauses.append(clause)
        return self

    def bind(self, value) -> str:
        """Bind a value OUTSIDE a clause and return its placeholder — for values that
        appear in a non-filter position (LIMIT) or in a hand-written clause that wants the
        same parameter bound once and referenced several times."""
        return self._bind(value)

    def where_sql(self) -> str:
        """The full `WHERE ...` fragment, or "" when there are no clauses."""
        return f"WHERE {' AND '.join(self._clauses)}" if self._clauses else ""

    @property
    def params(self) -> list:
        return self._params

    def _bind(self, value) -> str:
        self._params.append(value)
        return f"${len(self._params)}"


class ServerRepo(_PoolAccess):
    """CRUD for `servers` + their attached `server_policies` / `tool_policies` / `param_rules`.

    Reads come from the reader pool, writes from the writer pool. Multi-statement writes (create,
    set_policy) run in an explicit transaction so they are atomic and never observable
    half-applied — under SQLite that required the dedicated-writer-connection + WAL arrangement
    the old Database docstring described; under Postgres it is what a transaction already means."""

    async def list(self, project_id: Optional[int] = None) -> list[ServerRecord]:
        # Defense-in-depth: the CREATE path validates the slug (archon/schemas.py's
        # _validate_slug) so a bad row shouldn't be writable anymore — but list() must not turn
        # a bad row already in the DB (from any path that bypasses the API validator) into a
        # PERMANENT outage: every caller of list() (GET /servers, GET /stats, aggregate
        # tools/list/discover, the health poller) would raise on the Pydantic ValidationError
        # inside _row_to_server, with no way to even see the bad row to delete it. Skip-and-log
        # instead of propagating, so one bad row degrades to "one server invisible" rather than
        # "everything that calls list() is down."
        #
        # `project_id=None` means "no project filter" (every existing instance-wide use like the
        # health poller) — NOT "servers with no project". Pass a real project id explicitly to
        # scope.
        async with self._read() as conn:
            if project_id is not None:
                rows = await conn.fetch(
                    "SELECT * FROM servers WHERE project_id = $1 ORDER BY slug", project_id
                )
            else:
                rows = await conn.fetch("SELECT * FROM servers ORDER BY slug")
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
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM servers WHERE slug = $1", slug)
        if row is None:
            raise ServerNotFoundError(slug)
        return _row_to_server(row)

    async def get_by_id(self, server_id: int) -> ServerRecord:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM servers WHERE id = $1", server_id)
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
        # [TRANSACTION + UNIQUE-violation catch] replaces gateway_write_lock.
        #
        # Two things were tangled together under the old lock. The two-table write (servers +
        # its paired server_policies row) needed atomicity — that is the transaction below, and
        # it is a straight translation.
        #
        # The check-slug-then-INSERT was the actual TOCTOU risk, and a lock is the WRONG fix for
        # it even in principle: an asyncio.Lock only excludes other coroutines in THIS process,
        # so it never protected against a second replica (the thing this whole cutover exists to
        # enable). The pre-flight SELECT is kept because it produces a clean typed error for the
        # overwhelmingly common non-racing case without burning a failed INSERT, but it is no
        # longer what makes this correct. `servers.slug UNIQUE` is. The loser of a genuine race
        # gets asyncpg.UniqueViolationError from the INSERT, which is converted to the SAME
        # SlugConflictError the pre-flight check raises — so callers see one error shape whether
        # they lost the race or never entered it. Covered by
        # tests/integration/test_postgres_races.py::TestServerCreateRace.
        async with self._write() as conn:
            async with conn.transaction():
                if await conn.fetchval("SELECT 1 FROM servers WHERE slug = $1", slug):
                    raise SlugConflictError(slug)

                # project_id=None (the default) resolves to the 'default' project rather than
                # staying NULL — see _default_project_id's docstring for why this must not be a
                # NULL row.
                if project_id is None:
                    project_id = await _default_project_id(conn)

                now = utcnow()
                try:
                    server_id = await conn.fetchval(
                        """INSERT INTO servers
                           (slug, name, upstream_url, enabled, in_aggregate, upstream_auth_header,
                            created_at, updated_at, project_id)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                           RETURNING id""",
                        slug, name, upstream_url, enabled, in_aggregate,
                        upstream_auth_header, now, now, project_id,
                    )
                except asyncpg.UniqueViolationError as e:
                    raise SlugConflictError(slug) from e
                # RETURNING id replaces cur.lastrowid, which asyncpg has no equivalent for —
                # and which was never safe under concurrency anyway (it read a connection-wide
                # "last inserted rowid", not this statement's).
                await conn.execute(
                    "INSERT INTO server_policies (server_id, mode, updated_at) "
                    "VALUES ($1, 'passthrough', $2)",
                    server_id, now,
                )
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
        # Placeholders are generated positionally ($1, $2, ...) rather than as literal "?"s. The
        # field NAMES are still hardcoded string literals in this function — never caller input —
        # so this stays parameterized: values only ever reach the database as bound parameters.
        fields, values = [], []

        def _next(column: str, value) -> None:
            values.append(value)
            fields.append(f"{column} = ${len(values)}")

        if name is not None:
            _next("name", name)
        if upstream_url is not None:
            _next("upstream_url", upstream_url)
        if enabled is not None:
            _next("enabled", enabled)
        if in_aggregate is not None:
            _next("in_aggregate", in_aggregate)
        if upstream_auth_header is not _UNSET:
            # Unlike the other fields, None here is meaningful ("clear the configured
            # credential"), so a sentinel distinguishes "field omitted, don't touch it" from
            # "field explicitly set to null" — the None-means-omitted convention every other
            # field on this method uses would make it impossible to ever clear a credential.
            _next("upstream_auth_header", upstream_auth_header)
        if not fields:
            return current
        _next("updated_at", utcnow())
        values.append(current.id)
        # [SINGLE-STATEMENT] replaces gateway_write_lock. One UPDATE against one row, no
        # read-then-write inside the write itself — Postgres makes it atomic on its own, and the
        # row-level lock it takes is exactly as much serialization as this needs. (The get() above
        # is a read for the caller's return value and for the not-found check, not a value this
        # UPDATE derives from — every SET here is a caller-supplied constant, so there is no
        # lost-update hazard for a lock to protect against.)
        async with self._write() as conn:
            await conn.execute(
                f"UPDATE servers SET {', '.join(fields)} WHERE id = ${len(values)}", *values
            )
        return await self.get(slug)

    async def delete(self, slug: str) -> None:
        current = await self.get(slug)
        # [SINGLE-STATEMENT] replaces gateway_write_lock. ON DELETE CASCADE on server_policies /
        # tool_policies / param_rules / tools_cache means this one statement is the whole write;
        # the cascade runs inside its implicit transaction, so there is no window where a server
        # is gone but its policy rows survive.
        async with self._write() as conn:
            await conn.execute("DELETE FROM servers WHERE id = $1", current.id)

    async def set_project(self, slug: str, project_id: int) -> ServerRecord:
        """Reassign an EXISTING server to a different project. Deliberately a
        separate, narrow method rather than a field on `update()` — reassignment is rare (config
        import with a changed project_slug, or a future explicit "move server" admin action),
        and keeping it out of update()'s general field list avoids a project_id=None sentinel
        ambiguity (unlike upstream_auth_header, "don't reassign" here is simply "don't call
        this method" — there's no legitimate "clear the project" operation)."""
        current = await self.get(slug)
        # [SINGLE-STATEMENT] replaces gateway_write_lock — one UPDATE, caller-supplied value.
        async with self._write() as conn:
            await conn.execute(
                "UPDATE servers SET project_id = $1, updated_at = $2 WHERE id = $3",
                project_id, utcnow(), current.id,
            )
        return await self.get(slug)

    async def set_health(
        self, slug: str, health_status: str, upstream_protocol: Optional[str] = None,
        discover_json: Optional[str] = None, health_reason: Optional[str] = None,
    ) -> None:
        # health_reason is NOT COALESCE'd like upstream_protocol/discover_json —
        # it must be overwritten with exactly what THIS probe found (None when the cause wasn't a
        # secret-resolution failure), or a stale reason from a previous failed probe would keep
        # showing after the server recovers or the cause changes to a plain network outage.
        #
        # [ATOMIC-RMW] replaces gateway_write_lock. The COALESCE(?, column) form makes this a
        # read-modify-write — upstream_protocol/discover_json keep their STORED value when the
        # probe passes None. Expressing it as one statement (rather than SELECT-then-UPDATE) is
        # what makes it race-free: the read of the old value happens inside the same statement
        # that writes the new one, under the row lock Postgres takes for the UPDATE, so two
        # concurrent health probes cannot interleave a read and a write. This shape was already
        # correct pre-cutover; removing the lock around it changes nothing about its atomicity.
        # Covered by tests/integration/test_postgres_races.py::TestHealthWriteRace.
        current = await self.get(slug)
        now = utcnow()
        async with self._write() as conn:
            await conn.execute(
                """UPDATE servers SET health_status = $1,
                   upstream_protocol = COALESCE($2, upstream_protocol),
                   discover_json = COALESCE($3, discover_json), health_reason = $4,
                   last_seen_at = $5, updated_at = $6
                   WHERE id = $7""",
                health_status, upstream_protocol, discover_json, health_reason,
                now, now, current.id,
            )

    async def get_policy(self, server_id: int) -> ServerPolicy:
        """Policy for ONE server — a thin delegation to the batched get_policies_for, so
        policy assembly (DLP decode, allowed/denied split, param_rules construction) has a
        single implementation instead of two copies that could drift on enforcement data.

        Keeps the properties callers relied on from the standalone version: the three reads
        (server_policies, tool_policies, param_rules) run on one pooled connection — a
        consistent view under Postgres' default READ COMMITTED — and a server with no
        policy row gets the same passthrough/no-rate-limit default get_policies_for
        returns. The single-element array binds to the same `= ANY($1)` statement the
        batched path uses, so this shares one prepared-statement plan with aggregate calls
        rather than a second, scalar-parameter one."""
        return (await self.get_policies_for([server_id]))[server_id]

    async def get_policies_for(self, server_ids: list[int]) -> dict[int, ServerPolicy]:
        """Batched version of get_policy for the aggregate endpoint: one query per table with
        `WHERE server_id IN (...)`, grouped in Python — 3 queries total regardless of how many
        servers are being fetched, rather than 3 per server (3N for N registered servers).
        Servers with no policy row yet
        get the same passthrough/no-rate-limit default get_policy() returns.

        Postgres port: the three `IN (...)` clauses became `= ANY($1)` with the id list bound as
        a single array parameter, replacing the f-string-built `?,?,?` placeholder run. Besides
        being cleaner, this removes the only place in this module that interpolated a
        caller-length-dependent fragment into SQL text, and it lets these three statements share
        one prepared-statement plan regardless of how many servers are being fetched."""
        if not server_ids:
            return {}

        async with self._read() as conn:
            rows = await conn.fetch(
                "SELECT server_id, mode, rate_limit, dlp_config FROM server_policies "
                "WHERE server_id = ANY($1)",
                server_ids,
            )
            policy_rows = {r["server_id"]: r for r in rows}

            tool_rows = await conn.fetch(
                "SELECT server_id, tool_name, action FROM tool_policies WHERE server_id = ANY($1)",
                server_ids,
            )
            param_rows = await conn.fetch(
                """SELECT server_id, tool_name, param_name, max_length, max_value, min_value,
                          denied, block_patterns
                   FROM param_rules WHERE server_id = ANY($1)""",
                server_ids,
            )

        allowed_by_id: dict[int, list[str]] = {sid: [] for sid in server_ids}
        denied_by_id: dict[int, list[str]] = {sid: [] for sid in server_ids}
        for r in tool_rows:
            (allowed_by_id if r["action"] == "allow" else denied_by_id)[r["server_id"]].append(r["tool_name"])

        param_rules_by_id: dict[int, dict[str, dict[str, ParamRule]]] = {sid: {} for sid in server_ids}
        for r in param_rows:
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
        # [TRANSACTION] replaces gateway_write_lock. This is THE method the old F7 machinery
        # existed for — a DELETE-then-reinsert across three tables, where a reader catching the
        # gap would see an EMPTY denylist and the gateway would transiently fail open on every
        # policy save. SQLite could only prevent that with a dedicated writer connection, WAL
        # mode, and a process-wide lock; Postgres prevents it with the word "transaction". No
        # reader on any connection, in any process, can observe a state between this BEGIN and
        # COMMIT.
        #
        # The explicit rollback-on-BaseException is gone because conn.transaction() is a context
        # manager that rolls back on ANY exception (including CancelledError) by construction —
        # the hand-rolled try/except/rollback it replaces existed only because aiosqlite has no
        # such context manager.
        #
        # Also note the ON CONFLICT clause needed no dialect change: SQLite borrowed upsert
        # syntax from Postgres, so `ON CONFLICT (col) DO UPDATE SET x = excluded.x` is already
        # native here. Only the placeholders changed.
        # Covered by tests/integration/test_postgres_races.py::TestPolicyWriteRace, which asserts
        # a concurrent reader NEVER observes a partially-applied policy.
        dlp_config_json = _encode_dlp_config(policy.dlp_detectors, policy.dlp_custom_patterns)
        async with self._write() as conn:
            async with conn.transaction():
                await conn.execute(
                    """INSERT INTO server_policies (server_id, mode, rate_limit, dlp_config, updated_at)
                       VALUES ($1, $2, $3, $4, $5)
                       ON CONFLICT (server_id) DO UPDATE SET mode = excluded.mode,
                           rate_limit = excluded.rate_limit, dlp_config = excluded.dlp_config,
                           updated_at = excluded.updated_at""",
                    server_id, policy.mode, policy.rate_limit, dlp_config_json, utcnow(),
                )
                await conn.execute("DELETE FROM tool_policies WHERE server_id = $1", server_id)
                # executemany replaces the per-row await loops — one round-trip per table instead
                # of one per tool, inside the same transaction.
                if policy.allowed:
                    await conn.executemany(
                        "INSERT INTO tool_policies (server_id, tool_name, action) "
                        "VALUES ($1, $2, 'allow')",
                        [(server_id, t) for t in policy.allowed],
                    )
                if policy.denied:
                    await conn.executemany(
                        "INSERT INTO tool_policies (server_id, tool_name, action) "
                        "VALUES ($1, $2, 'deny')",
                        [(server_id, t) for t in policy.denied],
                    )
                await conn.execute("DELETE FROM param_rules WHERE server_id = $1", server_id)
                param_rows = [
                    (server_id, tool_name, param_name, rule.max_length, rule.max_value,
                     rule.min_value, rule.denied, json.dumps(rule.block_patterns))
                    for tool_name, params in policy.param_rules.items()
                    for param_name, rule in params.items()
                ]
                if param_rows:
                    await conn.executemany(
                        """INSERT INTO param_rules
                           (server_id, tool_name, param_name, max_length, max_value, min_value,
                            denied, block_patterns)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                        param_rows,
                    )


class ApiKeyRepo(_PoolAccess):
    # touch_last_used is debounced in-process rather than written on every authenticated
    # data-plane request — a gratuitous write on its own, and the specific trigger that made
    # set_policy's DELETE-then-reinsert race real. "last used" is still useful for an operator
    # auditing which keys are stale — freshness within this window is a fine trade for not
    # writing on every single proxied call.
    #
    # Kept post-cutover even though the race it was tuned for is gone: the debounce's OTHER
    # justification (don't issue a write per proxied request) is, if anything, stronger against a
    # networked database than against a local file, since every write is now a round-trip. Note
    # the debounce is per-PROCESS state (`_last_touch`), so N replicas can each write once per
    # window rather than once globally — acceptable for an advisory "last used" timestamp, and
    # called out here so it isn't mistaken for a correctness guarantee.
    _TOUCH_DEBOUNCE_SECONDS = 60

    def __init__(self, db: Database):
        super().__init__(db)
        self._last_touch: dict[int, float] = {}

    async def create(self, name: str, key_hash: str, key_prefix: str,
                      server_scopes: Optional[list[str]] = None,
                      quota_calls: Optional[int] = None,
                      quota_period: Optional[str] = None,
                      project_id: Optional[int] = None) -> ApiKeyRecord:
        now = utcnow()
        # [TRANSACTION] replaces gateway_write_lock. Two statements when project_id must be
        # resolved (SELECT default project, then INSERT) — wrapped so the resolved project can't
        # be deleted between the lookup and the insert (the FK would then reject the INSERT, but
        # inside one transaction the read sees a consistent snapshot and the FK check is against
        # the same one). RETURNING id replaces cur.lastrowid.
        async with self._write() as conn:
            async with conn.transaction():
                # Same 'default'-project fallback as ServerRepo.create — see
                # _default_project_id's docstring.
                if project_id is None:
                    project_id = await _default_project_id(conn)
                key_id = await conn.fetchval(
                    """INSERT INTO api_keys
                       (name, key_hash, key_prefix, server_scopes, created_at, quota_calls,
                        quota_period, project_id)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                       RETURNING id""",
                    name, key_hash, key_prefix,
                    json.dumps(server_scopes) if server_scopes else None, now,
                    quota_calls, quota_period, project_id,
                )
        return await self.get_by_id(key_id)

    async def get_by_id(self, key_id: int) -> ApiKeyRecord:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM api_keys WHERE id = $1", key_id)
        if row is None:
            raise ServerNotFoundError(str(key_id))
        return self._row_to_record(row)

    async def get_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        # `enabled = 1` became `enabled IS TRUE` — the column is a real BOOLEAN now, and Postgres
        # will not implicitly compare boolean to integer.
        async with self._read() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM api_keys WHERE key_hash = $1 AND enabled IS TRUE", key_hash
            )
        return self._row_to_record(row) if row else None

    async def list(self, project_id: Optional[int] = None) -> list[ApiKeyRecord]:
        # Same None-means-unfiltered convention as ServerRepo.list.
        async with self._read() as conn:
            if project_id is not None:
                rows = await conn.fetch(
                    "SELECT * FROM api_keys WHERE project_id = $1 ORDER BY created_at DESC",
                    project_id,
                )
            else:
                rows = await conn.fetch("SELECT * FROM api_keys ORDER BY created_at DESC")
        return [self._row_to_record(r) for r in rows]

    async def set_enabled(self, key_id: int, enabled: bool) -> None:
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            await conn.execute("UPDATE api_keys SET enabled = $1 WHERE id = $2", enabled, key_id)

    async def set_quota(self, key_id: int, quota_calls: Optional[int], quota_period: Optional[str]) -> None:
        """Both fields are written together, always — a NULL quota_calls with a non-NULL
        quota_period (or vice versa) is a nonsensical half-state, so there is no partial-update
        path here the way ServerRepo.update has per-field optionality. Callers (the PATCH
        /keys/{id} route) pass both, always, even when clearing (None, None)."""
        # [SINGLE-STATEMENT] replaces gateway_write_lock. Both columns in one UPDATE, which is
        # what makes the "never a half-state" property above hold — it was never the lock.
        async with self._write() as conn:
            await conn.execute(
                "UPDATE api_keys SET quota_calls = $1, quota_period = $2 WHERE id = $3",
                quota_calls, quota_period, key_id,
            )

    async def delete(self, key_id: int) -> None:
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            await conn.execute("DELETE FROM api_keys WHERE id = $1", key_id)

    async def touch_last_used(self, key_id: int) -> None:
        now = time.monotonic()
        last = self._last_touch.get(key_id)
        if last is not None and (now - last) < self._TOUCH_DEBOUNCE_SECONDS:
            return
        self._last_touch[key_id] = now
        # [SINGLE-STATEMENT] replaces gateway_write_lock. Last-writer-wins on a purely advisory
        # timestamp; concurrent touches racing is not a correctness problem (and never was).
        async with self._write() as conn:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = $1 WHERE id = $2", utcnow(), key_id
            )

    @staticmethod
    def _row_to_record(row: asyncpg.Record) -> ApiKeyRecord:
        return ApiKeyRecord(
            id=row["id"],
            name=row["name"],
            key_prefix=row["key_prefix"],
            enabled=bool(row["enabled"]),
            server_scopes=json.loads(row["server_scopes"]) if row["server_scopes"] else None,
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            quota_calls=row["quota_calls"],
            quota_period=row["quota_period"],
            project_id=row["project_id"],
        )


class AuditRepo(_PoolAccess):
    """The data-plane traffic log.

    Post-cutover this is a TABLE in the main database rather than its own audit.db file, so it
    uses the same reader/writer pools as every other repo instead of the third dedicated
    connection it used to hold. See 0001_init.sql's header for the one-database decision."""

    async def insert_many(self, events: list[dict]) -> None:
        if not events:
            return
        # asyncpg has no named-parameter (:name) binding — it is positional-only. The event dicts
        # produced by AuditLogger are projected into positional tuples in a FIXED column order
        # declared right here, so the mapping stays visible in one place rather than depending on
        # dict ordering.
        #
        # `bridged` is NOT NULL DEFAULT FALSE. A column default only applies when the column is
        # OMITTED from the INSERT — naming it and binding None is an explicit NULL, which the
        # constraint (correctly) rejects. Since this statement names every column, an event dict
        # that omits `bridged` would otherwise fail rather than pick up the default. Defaulted
        # here instead, so a partial event dict behaves the way the schema promises.
        # AuditLogger always supplies it; this covers other callers.
        columns = (
            "ts", "server_slug", "api_key_id", "client_ip", "endpoint", "rpc_method", "tool",
            "decision", "rule", "matched", "reason", "args_summary", "bridged", "status_code",
            "latency_ms", "origin", "dlp_detector", "dlp_action", "dlp_match_count",
        )
        _defaults = {"bridged": False}
        placeholders = ", ".join(f"${i}" for i in range(1, len(columns) + 1))
        rows = [
            tuple(
                e.get(c) if e.get(c) is not None else _defaults.get(c)
                for c in columns
            )
            for e in events
        ]
        async with self._write() as conn:
            await conn.executemany(
                f"INSERT INTO audit_events ({', '.join(columns)}) VALUES ({placeholders})",
                rows,
            )

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

        `server_slug_in` (enterprise #4): project-scoped callers (archon/api.py's GET /audit etc.)
        resolve their project's server slugs via ServerRepo.list(project_id=...) first, then pass
        that slug set here as a filter, composing with (not replacing) the single-slug
        `server_slug` filter above. An empty list means "this project has zero servers" and must
        match ZERO rows, not every row.

        NOTE: this parameter's original reason for existing was a hard SQLite limitation —
        audit_events lived in audit.db, a separate FILE and connection from gateway.db where
        servers/projects live, so there was literally no way to JOIN and the slug set had to be
        resolved in Python. Post-cutover both are tables in one database and a JOIN IS now
        possible. Deliberately NOT rewritten as a join here: the callers, their signatures, and
        their tests are all built around the resolved-slug-set shape, and changing the query
        strategy would be a behavioural refactor riding along inside a storage-engine cutover.
        Recorded as a now-available simplification rather than taken, so the constraint that
        forced this design is not mistaken for a live one."""
        # Placeholders are numbered as clauses are appended. Every caller-supplied VALUE is a
        # bound parameter; only fixed column-name/operator text is ever interpolated.
        w = _Where()
        w.eq("server_slug", server_slug or None)
        if server_slug_in is not None:
            w.any_of("server_slug", server_slug_in)
        w.eq("decision", decision or None)
        w.eq("tool", tool or None)
        w.lt("id", before_id)
        w.eq("api_key_id", api_key_id)
        w.ge("ts", after or None)
        w.le("ts", before or None)
        if search:
            # `%`/`_` in the term are escaped so a literal search (e.g. "100%") isn't interpreted
            # as a LIKE wildcard. The ESCAPE character is written as a doubled backslash in the
            # SQL literal ('\\') because Postgres' standard_conforming_strings is on by default,
            # making '\' a literal backslash — SQLite accepted the single-backslash spelling, and
            # carrying it over verbatim would have made every escaped search silently wrong.
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            # Bound ONCE and referenced in all three branches — the placeholder is a string, so
            # one parameter can appear multiple times (the old per-clause `_p` bound it three
            # times as three identical parameters).
            like_ph = w.bind(like)
            w.raw(
                f"(reason LIKE {like_ph} ESCAPE '\\' "
                f"OR args_summary LIKE {like_ph} ESCAPE '\\' "
                f"OR matched LIKE {like_ph} ESCAPE '\\')"
            )
        if origin is not _UNSET:
            if origin is None:
                w.is_null("origin")
            else:
                w.eq("origin", origin)
        limit_ph = w.bind(limit)
        async with self._read() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM audit_events {w.where_sql()} ORDER BY id DESC LIMIT {limit_ph}",
                *w.params,
            )
        return [dict(r) for r in rows]

    async def count_since(
        self, since_iso: str, decision: Optional[str] = None,
        server_slug_in: Optional[list[str]] = None,
    ) -> int:
        # Always excludes origin='test' (Try-it calls) — this backs /stats, and a dashboard
        # counter that moves every time an operator tests their own policy would be useless.
        w = _Where()
        w.ge("ts", since_iso)
        w.raw("origin IS NULL")
        w.eq("decision", decision or None)
        if server_slug_in is not None:
            w.any_of("server_slug", server_slug_in)
        async with self._read() as conn:
            count = await conn.fetchval(
                f"SELECT COUNT(*) FROM audit_events {w.where_sql()}", *w.params
            )
        return count or 0

    async def prune_older_than(self, cutoff_iso: str, batch_size: int = 5000) -> int:
        # Batching a potentially huge DELETE is kept deliberately: one giant DELETE holds a
        # correspondingly giant transaction open, which bloats WAL, defers autovacuum's ability
        # to reclaim any of the dead tuples until it commits, and takes a long-lived lock set
        # that a rolling upgrade or a pg_dump would then contend with. Committing per batch keeps
        # each transaction short and lets autovacuum reclaim as it goes.
        #
        # Postgres HAS no `DELETE ... LIMIT` either, so the subquery form carries over — now with
        # `ctid IN (SELECT ... LIMIT)` semantics expressed via the primary key, plus `RETURNING`
        # to count rows (asyncpg's execute() returns a status string like "DELETE 5000" rather
        # than a rowcount attribute).
        #
        # Retention no longer runs any VACUUM: reclaiming space is autovacuum's job on Postgres,
        # not something this application should manage (design decision 5 in the plan doc).
        total_deleted = 0
        while True:
            async with self._write() as conn:
                deleted = await conn.fetchval(
                    """WITH doomed AS (
                           SELECT id FROM audit_events WHERE ts < $1 ORDER BY id LIMIT $2
                       ), removed AS (
                           DELETE FROM audit_events WHERE id IN (SELECT id FROM doomed)
                           RETURNING 1
                       )
                       SELECT count(*) FROM removed""",
                    cutoff_iso, batch_size,
                )
            deleted = deleted or 0
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
    representation), which is exactly the class of bug stoa/retention.py had to work around for
    the same reason (see its header comment). Going through datetime.fromisoformat
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


class UsageRepo(_PoolAccess):
    """Quotas + usage attribution: durable call-count rollups, one row per
    (UTC hour bucket, api_key_id, server_id, tool).

    A separate TABLE from audit_events — see 0009_usage_rollups.sql's header comment for why
    (the short version: AuditRetentionJob prunes audit_events on a rolling window; a usage rollup
    subject to that job would lose exactly the history an operator most wants to look back over).

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
        # [UPSERT] replaces gateway_write_lock — and this is the site where the lock's removal
        # matters MOST, because this runs on every single forwarded tools/call.
        #
        # The operation is a read-modify-write ("add `amount` to this bucket's count"), which is
        # the classic lost-update shape. It is race-free WITHOUT any lock because the increment
        # is expressed against the STORED value inside a single statement
        # (`calls = usage_rollups.calls + excluded.calls`), and concurrent callers targeting the
        # same bucket serialize on that row via the UNIQUE index — including callers in DIFFERENT
        # PROCESSES, which the asyncio.Lock never covered. The old lock made concurrent
        # increments correct within one process and did nothing across two; this is correct
        # across any number.
        #
        # The bare `calls + excluded.calls` in the SQLite original is qualified to
        # `usage_rollups.calls` here: Postgres requires the target table be named explicitly in
        # an ON CONFLICT DO UPDATE SET expression, and an unqualified `calls` is ambiguous.
        # Covered by tests/integration/test_postgres_races.py::TestUsageIncrementRace, which
        # fires N concurrent increments at one bucket and asserts the total is exactly N.
        async with self._write() as conn:
            await conn.execute(
                """INSERT INTO usage_rollups
                   (period_start, period_kind, api_key_id, server_id, tool, calls, project_id)
                   VALUES ($1, 'hour', $2, $3, $4, $5, $6)
                   ON CONFLICT (period_start, api_key_id, server_id, tool)
                   DO UPDATE SET calls = usage_rollups.calls + excluded.calls,
                       project_id = COALESCE(usage_rollups.project_id, excluded.project_id)""",
                period_start, _to_key_sentinel(api_key_id), _to_server_sentinel(server_id),
                _to_tool_sentinel(tool), amount, project_id,
            )

    async def total_since(self, *, api_key_id: int, since_iso: str) -> int:
        """Sum of `calls` across every hour bucket with period_start >= since_iso, for one key
        — the quota-enforcement read. `since_iso` is the caller-computed start of the current
        quota period (start of today or start of this month, in UTC); summing hourly buckets
        rather than storing a running total keeps this correct across period boundaries without
        a separate reset job (see docs/quotas.md's "why hourly buckets" section)."""
        async with self._read() as conn:
            total = await conn.fetchval(
                "SELECT COALESCE(SUM(calls), 0) FROM usage_rollups "
                "WHERE api_key_id = $1 AND period_start >= $2",
                api_key_id, since_iso,
            )
        # SUM() returns numeric/Decimal from Postgres where SQLite returned a plain int; the
        # quota comparison and the API response both expect an int.
        return int(total or 0)

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
        w = _Where()
        w.eq("api_key_id", api_key_id)
        w.eq("server_id", server_id)
        w.eq("tool", tool)
        w.ge("period_start", since_iso)
        w.le("period_start", until_iso)
        w.eq("project_id", project_id)
        async with self._read() as conn:
            rows = await conn.fetch(
                f"""SELECT period_start, api_key_id, server_id, tool, calls
                    FROM usage_rollups {w.where_sql()} ORDER BY period_start DESC""",
                *w.params,
            )
        return [dict(r) for r in rows]


class SettingsRepo(_PoolAccess):
    """Key-value store for gateway-wide settings (auth_mode, aggregate default, retention,
    admin credentials). Values are stored as plain strings; callers coerce types."""

    async def get(self, key: str) -> Optional[str]:
        async with self._read() as conn:
            return await conn.fetchval("SELECT value FROM settings WHERE key = $1", key)

    async def get_all(self) -> dict[str, str]:
        async with self._read() as conn:
            rows = await conn.fetch("SELECT key, value FROM settings")
        return {r["key"]: r["value"] for r in rows}

    async def set(self, key: str, value: str) -> None:
        # [UPSERT] replaces gateway_write_lock. One atomic INSERT ... ON CONFLICT DO UPDATE;
        # concurrent writers to the same key serialize on the row, last writer wins — the same
        # outcome the lock produced, without excluding writers to unrelated keys.
        async with self._write() as conn:
            await conn.execute(
                """INSERT INTO settings (key, value) VALUES ($1, $2)
                   ON CONFLICT (key) DO UPDATE SET value = excluded.value""",
                key, value,
            )

    async def set_many(self, values: dict[str, str]) -> None:
        # [TRANSACTION] replaces gateway_write_lock. The reason this method exists at all is
        # atomicity ACROSS KEYS — the setup wizard writes admin_password_hash + session_secret +
        # auth_mode as one unit, and a reader (or a crash) must never catch a state where the
        # password is set but the session secret isn't. The lock gave that within one process; a
        # real transaction gives it across all of them, and also makes it crash-safe, which the
        # lock never did.
        # Covered by tests/integration/test_postgres_races.py::TestSettingsAtomicity.
        if not values:
            return
        async with self._write() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """INSERT INTO settings (key, value) VALUES ($1, $2)
                       ON CONFLICT (key) DO UPDATE SET value = excluded.value""",
                    list(values.items()),
                )


class AdminEventRepo(_PoolAccess):
    """Control-plane audit log — records administrative actions (server CRUD, policy changes,
    key mint/revoke, settings changes, config imports).

    Distinct from AuditRepo (data-plane traffic log): these are low-volume, high-value events
    that must survive long-term. NEVER pruned by AuditRetentionJob — that job only ever DELETEs
    from audit_events, which is what has always kept these rows safe (the pre-cutover phrasing
    was "stored in gateway.db, not audit.db"; post-cutover both are tables in one database, and
    the invariant is unchanged because it was always about table identity, not file identity).
    """

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
        """Insert one admin event. Returns the new row id.

        `before`/`after` arrive as JSON STRINGS (callers json.dumps their allowlisted field dict)
        and land in JSONB columns. The identity JSON codec registered in db/database.py means the
        string is passed through to Postgres as-is and parsed there — so an invalid JSON string
        now fails loudly at insert instead of being stored as opaque TEXT the way SQLite did."""
        # [SINGLE-STATEMENT] replaces gateway_write_lock. One INSERT; RETURNING id replaces
        # cur.lastrowid (which read a connection-wide value, not this statement's, and was never
        # concurrency-safe — it merely happened to be correct while the lock serialized writes).
        async with self._write() as conn:
            return await conn.fetchval(
                """INSERT INTO admin_events
                   (ts, actor, action, target_type, target_id, before, after, client_ip, summary)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                   RETURNING id""",
                utcnow(), actor, action, target_type, target_id, before, after, client_ip, summary,
            )

    async def query(
        self,
        *,
        action: Optional[str] = None,
        target_type: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 500,
    ) -> list[AdminEventRecord]:
        """Query admin events with optional filters. Follows AuditRepo.query conventions."""
        w = _Where()
        w.eq("action", action)
        w.eq("target_type", target_type)
        w.ge("ts", since)
        limit = min(limit, 500)
        limit_ph = w.bind(limit)

        async with self._read() as conn:
            rows = await conn.fetch(
                f"""SELECT id, ts, actor, action, target_type, target_id, before, after,
                           client_ip, summary
                    FROM admin_events {w.where_sql()}
                    ORDER BY ts DESC
                    LIMIT {limit_ph}""",
                *w.params,
            )
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


def _row_to_user(row: asyncpg.Record) -> UserRecord:
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


class UserRepo(_PoolAccess):
    """CRUD for the `users` table — local + OIDC control-plane principals (enterprise #1/#2).

    Same discipline as every other repo here: reads from the reader pool, writes from the writer
    pool, multi-statement writes in an explicit transaction."""

    async def count(self) -> int:
        """Used by archon/admin_auth.py to decide whether to fall back to the legacy
        settings-based admin check — an empty `users` table means a partially-applied
        upgrade or a pre-migration database, and must degrade to "still works", not "locked out"."""
        async with self._read() as conn:
            return await conn.fetchval("SELECT COUNT(*) FROM users") or 0

    async def get_by_id(self, user_id: int) -> UserRecord:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        if row is None:
            raise UserNotFoundError(str(user_id))
        return _row_to_user(row)

    async def get_by_username(self, username: str) -> Optional[UserRecord]:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE username = $1", username)
        return _row_to_user(row) if row else None

    async def get_by_subject(self, oidc_subject: str) -> Optional[UserRecord]:
        # Keyed on oidc_subject (IdP 'sub'), never email — see 0006_users.sql's header comment.
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE oidc_subject = $1", oidc_subject)
        return _row_to_user(row) if row else None

    async def list(self) -> list[UserRecord]:
        async with self._read() as conn:
            rows = await conn.fetch("SELECT * FROM users ORDER BY username")
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
        # Self-review fix (pre-cutover, still load-bearing): the pre-flight username check below
        # doesn't (and can't, on its own) rule out a concurrent oidc_subject collision — two
        # simultaneous JIT-provisioning calls for the same brand-new `sub` (a double-clicked
        # "Sign in with SSO", or two browser tabs) can both pass
        # UserRepo.get_or_create_from_oidc's `existing is None` check before either has
        # committed. The `oidc_subject UNIQUE` constraint is the real backstop; without catching
        # its violation here the loser of the race got an unhandled driver IntegrityError (a 500)
        # instead of a clean outcome.
        #
        # [TRANSACTION + UNIQUE-violation catch] replaces gateway_write_lock. This site is the
        # clearest illustration of why the lock was never the guarantee: the comment above
        # already described a race the lock did NOT close (it closed the username half within one
        # process and nothing across processes), and the fix even then was catching the UNIQUE
        # violation. Removing the lock doesn't widen the race — it removes a partial mitigation
        # that the constraint already fully covers. asyncpg.UniqueViolationError replaces
        # aiosqlite.IntegrityError and is still converted to UsernameConflictError so callers
        # have ONE exception shape regardless of which UNIQUE constraint (username or
        # oidc_subject) actually fired.
        # Covered by tests/integration/test_postgres_races.py::TestUserCreateRace.
        async with self._write() as conn:
            async with conn.transaction():
                if await conn.fetchval("SELECT 1 FROM users WHERE username = $1", username):
                    raise UsernameConflictError(username)
                now = utcnow()
                try:
                    new_id = await conn.fetchval(
                        """INSERT INTO users
                           (username, email, password_hash, role, auth_source, oidc_subject,
                            enabled, created_at)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                           RETURNING id""",
                        username, email, password_hash, role, auth_source, oidc_subject,
                        enabled, now,
                    )
                except asyncpg.UniqueViolationError as e:
                    raise UsernameConflictError(username) from e
        return await self.get_by_id(new_id)

    async def update_role(self, user_id: int, role: str) -> UserRecord:
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            await conn.execute("UPDATE users SET role = $1 WHERE id = $2", role, user_id)
        return await self.get_by_id(user_id)

    async def set_enabled(self, user_id: int, enabled: bool) -> UserRecord:
        # [SINGLE-STATEMENT] replaces gateway_write_lock. `enabled` is a real BOOLEAN column
        # now, so the int() coercion the SQLite schema needed is gone.
        async with self._write() as conn:
            await conn.execute("UPDATE users SET enabled = $1 WHERE id = $2", enabled, user_id)
        return await self.get_by_id(user_id)

    async def set_password_hash(self, user_id: int, password_hash: str) -> UserRecord:
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2", password_hash, user_id
            )
        return await self.get_by_id(user_id)

    async def touch_last_login(self, user_id: int) -> None:
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            await conn.execute(
                "UPDATE users SET last_login_at = $1 WHERE id = $2", utcnow(), user_id
            )

    async def bump_session_version(self, user_id: int) -> int:
        """Per-user analogue of the global session_version bump in settings — invalidates every
        outstanding session token for exactly this one user (disable, role change, password
        change, explicit logout-all-for-this-user), without touching anyone else's session."""
        # [ATOMIC-RMW] replaces gateway_write_lock — and this was a REAL lost-update risk, not a
        # nominal one. The old shape was UPDATE ... SET v = v + 1, COMMIT, then a SEPARATE SELECT
        # to read the new value back, with the lock as the only thing preventing a second bumper
        # from committing in between and making this caller return the OTHER caller's version
        # number. Returning a stale/foreign session_version here is a security-relevant bug: it
        # is the value written into the freshly-issued session token, so a token could be minted
        # carrying a version that is already invalid (locking the user out) or, worse, the
        # caller's own revocation could appear to have taken effect at a version that other
        # still-live tokens also satisfy.
        #
        # RETURNING collapses the increment and the read-back into ONE statement, so the value
        # returned is definitionally the one this statement wrote. No lock, no window.
        # Covered by tests/integration/test_postgres_races.py::TestSessionVersionRace, which
        # bumps concurrently from two tasks and asserts the returned versions are distinct and
        # the final stored value equals the number of bumps.
        async with self._write() as conn:
            version = await conn.fetchval(
                "UPDATE users SET session_version = session_version + 1 WHERE id = $1 "
                "RETURNING session_version",
                user_id,
            )
        return version if version is not None else 0

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


def _row_to_project(row: asyncpg.Record) -> ProjectRecord:
    return ProjectRecord(id=row["id"], slug=row["slug"], name=row["name"], created_at=row["created_at"])


class ProjectRepo(_PoolAccess):
    """CRUD for `projects`. Deliberately thin — no membership logic
    here (see ProjectMemberRepo below); this repo only owns the project row itself."""

    async def list(self) -> list[ProjectRecord]:
        async with self._read() as conn:
            rows = await conn.fetch("SELECT * FROM projects ORDER BY slug")
        return [_row_to_project(r) for r in rows]

    async def get(self, slug: str) -> ProjectRecord:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM projects WHERE slug = $1", slug)
        if row is None:
            raise ProjectNotFoundError(slug)
        return _row_to_project(row)

    async def get_by_id(self, project_id: int) -> ProjectRecord:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM projects WHERE id = $1", project_id)
        if row is None:
            raise ProjectNotFoundError(str(project_id))
        return _row_to_project(row)

    async def create(self, slug: str, name: str) -> ProjectRecord:
        # [TRANSACTION + UNIQUE-violation catch] replaces gateway_write_lock — identical shape
        # and reasoning to ServerRepo.create: the pre-flight SELECT gives a clean typed error on
        # the common path, `projects.slug UNIQUE` is what actually makes it correct, and the
        # loser of a real race is converted to the same ProjectSlugConflictError rather than
        # surfacing a driver exception.
        # Covered by tests/integration/test_postgres_races.py::TestProjectCreateRace.
        async with self._write() as conn:
            async with conn.transaction():
                if await conn.fetchval("SELECT 1 FROM projects WHERE slug = $1", slug):
                    raise ProjectSlugConflictError(slug)
                try:
                    project_id = await conn.fetchval(
                        "INSERT INTO projects (slug, name, created_at) VALUES ($1, $2, $3) "
                        "RETURNING id",
                        slug, name, utcnow(),
                    )
                except asyncpg.UniqueViolationError as e:
                    raise ProjectSlugConflictError(slug) from e
        return await self.get_by_id(project_id)

    async def delete(self, slug: str) -> None:
        # ON DELETE CASCADE on project_members handles membership cleanup. Servers/keys are NOT
        # cascade-deleted (no ON DELETE clause on their project_id FK) — deleting a project that
        # still owns servers/keys is refused at the API layer (archon/api.py) with a clear error
        # rather than silently orphaning or cascading away real infrastructure; see that route's
        # own comment for the exact check.
        current = await self.get(slug)
        # [SINGLE-STATEMENT] replaces gateway_write_lock. project_members cascades; servers/keys
        # deliberately do NOT (their project_id FK has no ON DELETE clause), so if any still
        # reference this project the FK rejects the DELETE — which is a stronger guarantee than
        # the API-layer pre-check described above, and now actually enforced rather than merely
        # checked-then-hoped under a per-process lock.
        async with self._write() as conn:
            await conn.execute("DELETE FROM projects WHERE id = $1", current.id)


def _row_to_member(row: asyncpg.Record) -> ProjectMemberRecord:
    return ProjectMemberRecord(user_id=row["user_id"], project_id=row["project_id"], role=row["role"])


class ProjectMemberRepo(_PoolAccess):
    """CRUD for `project_members` — the (user_id, project_id) -> role membership table backing
    archon/project_rbac.py's `require_project_role`. Every read here is the DB-is-authoritative
    lookup that dependency performs on every request (no caching), same discipline as
    archon/admin_auth.py's auth_mode/session_version checks."""

    async def get_membership(self, *, user_id: int, project_id: int) -> Optional[ProjectMemberRecord]:
        async with self._read() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM project_members WHERE user_id = $1 AND project_id = $2",
                user_id, project_id,
            )
        return _row_to_member(row) if row else None

    async def list_for_project(self, project_id: int) -> list[ProjectMemberRecord]:
        async with self._read() as conn:
            rows = await conn.fetch(
                "SELECT * FROM project_members WHERE project_id = $1 ORDER BY user_id", project_id
            )
        return [_row_to_member(r) for r in rows]

    async def list_for_user(self, user_id: int) -> list[ProjectMemberRecord]:
        """Every project a user has an explicit membership row in. NOTE: this does NOT include
        projects a global admin can access via the superset short-circuit — that's not a
        membership row, by design (see archon/project_rbac.py's module docstring). A global
        admin calling this sees only their EXPLICIT memberships, if any; callers that need "every
        project this principal can act on" (e.g. the frontend's project switcher) must special-
        case principal.role == 'admin' -> list every project, same as
        resolve_project_role does for a single project."""
        async with self._read() as conn:
            rows = await conn.fetch(
                "SELECT * FROM project_members WHERE user_id = $1 ORDER BY project_id", user_id
            )
        return [_row_to_member(r) for r in rows]

    async def upsert(self, *, user_id: int, project_id: int, role: str) -> ProjectMemberRecord:
        # [UPSERT] replaces gateway_write_lock. Single atomic INSERT ... ON CONFLICT DO UPDATE;
        # two concurrent role changes for the same (user, project) serialize on the row and the
        # last one wins, which is the same outcome the lock produced. RETURNING the row directly
        # would save a round-trip, but the follow-up get_membership() read is kept so the
        # returned record comes from the same read path every other method uses.
        # Covered by tests/integration/test_postgres_races.py::TestMembershipRace.
        async with self._write() as conn:
            await conn.execute(
                """INSERT INTO project_members (user_id, project_id, role) VALUES ($1, $2, $3)
                   ON CONFLICT (user_id, project_id) DO UPDATE SET role = excluded.role""",
                user_id, project_id, role,
            )
        return await self.get_membership(user_id=user_id, project_id=project_id)

    async def remove(self, *, user_id: int, project_id: int) -> None:
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            await conn.execute(
                "DELETE FROM project_members WHERE user_id = $1 AND project_id = $2",
                user_id, project_id,
            )


def _row_to_proposal(row: asyncpg.Record) -> ProposalRecord:
    return ProposalRecord(
        id=row["id"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        payload=row["payload"],
        proposer_user_id=row["proposer_user_id"],
        proposer=row["proposer"],
        state=row["state"],
        created_at=row["created_at"],
        resolved_at=row["resolved_at"],
        resolver_user_id=row["resolver_user_id"],
        resolver=row["resolver"],
        resolution_reason=row["resolution_reason"],
        project_id=row["project_id"],
    )


class ProposalRepo(_PoolAccess):
    """Approval-workflow proposals.

    The state transition out of 'pending' is the one place this class needs real care: resolve()
    is a compare-and-swap (UPDATE ... WHERE state = 'pending' ... RETURNING) so that two
    concurrent approvers cannot both resolve the same proposal — the first commit wins, the
    second's UPDATE matches zero rows and it sees None. Everything else is a single statement.

    No rows are ever written through the disabled path: the API layer checks the
    `approvals_enabled` setting before calling create(), so a gateway with approvals off has an
    empty table forever (the feature's byte-identical-when-disabled guarantee, per the plan).
    """

    async def create(
        self,
        *,
        target_type: str,
        target_id: str,
        payload: str,
        proposer_user_id: Optional[int],
        proposer: str,
        project_id: Optional[int] = None,
    ) -> ProposalRecord:
        """Insert one pending proposal. `payload` must already be a JSON string.

        `project_id` (0012_proposals_project_scope.sql): the caller
        (ApprovalService) is responsible for resolving this — None for a 'config_import'
        proposal (instance-wide, by design), the target server's project_id for a
        'server_policy' proposal. This repo just stores whatever it's given; it has no opinion
        on the target_type/project_id relationship, same as it has no opinion on any other
        payload shape."""
        # [SINGLE-STATEMENT] replaces gateway_write_lock. One INSERT; RETURNING id replaces
        # lastrowid exactly as AdminEventRepo.insert does.
        async with self._write() as conn:
            row = await conn.fetchrow(
                """INSERT INTO proposals
                   (target_type, target_id, payload, proposer_user_id, proposer, created_at,
                    project_id)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   RETURNING *""",
                target_type, target_id, payload, proposer_user_id, proposer, utcnow(), project_id,
            )
        return _row_to_proposal(row)

    async def get(self, proposal_id: int) -> ProposalRecord:
        async with self._read() as conn:
            row = await conn.fetchrow("SELECT * FROM proposals WHERE id = $1", proposal_id)
        if row is None:
            raise ProposalNotFoundError(str(proposal_id))
        return _row_to_proposal(row)

    async def list(
        self, *, state: Optional[str] = None, project_id: Optional[int] = None, limit: int = 200
    ) -> list[ProposalRecord]:
        """List proposals, newest first. `state` filters to a single state (None = all).

        `project_id` filters to one project's proposals —
        used by GET /proposals when the caller is a project admin, not a global admin, mirroring
        GET /keys's own project_id query-param branch. None means "no project filter" (the
        global-admin default), NOT "only proposals with no project" — a caller who wants only
        the instance-wide config_import proposals has no query-param spelling for that today,
        since nothing has needed it yet."""
        w = _Where()
        w.eq("state", state)
        w.eq("project_id", project_id)
        limit_ph = w.bind(limit)
        async with self._read() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM proposals {w.where_sql()} "
                f"ORDER BY created_at DESC, id DESC LIMIT {limit_ph}",
                *w.params,
            )
        return [_row_to_proposal(r) for r in rows]

    async def resolve(
        self,
        proposal_id: int,
        *,
        state: str,  # 'approved' | 'rejected' | 'expired'
        resolver_user_id: Optional[int],
        resolver: Optional[str],
        resolution_reason: Optional[str],
    ) -> Optional[ProposalRecord]:
        """Transition a proposal out of 'pending'. Returns the updated row, or None if the
        proposal was already resolved (or never existed) — the compare-and-swap makes this safe
        under concurrency: exactly one caller can win the transition, matching the "two admins
        both click approve" case the plan names. Callers raise a clear error on None.

        `resolver` is Optional only for the expiry sweep (no human actor — it passes
        resolver='expiry-sweep', resolver_user_id=None and a NULL reason).
        """
        # [SINGLE-STATEMENT] replaces gateway_write_lock — the WHERE state = 'pending' clause IS
        # the concurrency control, an atomic compare-and-swap the old process-wide lock existed
        # to emulate for SQLite's single-writer model.
        async with self._write() as conn:
            row = await conn.fetchrow(
                """UPDATE proposals SET state = $2, resolved_at = $3,
                       resolver_user_id = $4, resolver = $5, resolution_reason = $6
                   WHERE id = $1 AND state = 'pending'
                   RETURNING *""",
                proposal_id, state, utcnow(), resolver_user_id, resolver, resolution_reason,
            )
        return _row_to_proposal(row) if row is not None else None

    async def expire_due(self, cutoff_iso: str) -> int:
        """Expire every pending proposal created before `cutoff_iso` (the TTL sweep). Returns
        how many were expired. `resolver` labels the sweep as the resolver so the transition is
        still attributable in the audit trail, same shape as AuditRetentionJob's pruning."""
        # [SINGLE-STATEMENT] replaces gateway_write_lock.
        async with self._write() as conn:
            rows = await conn.fetch(
                """UPDATE proposals SET state = 'expired', resolved_at = $1,
                       resolver = 'expiry-sweep'
                   WHERE state = 'pending' AND created_at < $2
                   RETURNING id""",
                utcnow(), cutoff_iso,
            )
        return len(rows)
