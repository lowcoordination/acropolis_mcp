from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Optional

from db.models import ApiKeyRecord, ServerRecord
from db.repo import ApiKeyRepo, ServerNotFoundError

KEY_PREFIX = "acropolis_"
KEY_RANDOM_BYTES = 32
DISPLAY_PREFIX_LEN = 16  # "acropolis_" + 6 chars, enough to identify a key in the UI without revealing it


@dataclass
class GeneratedKey:
    record: ApiKeyRecord
    plaintext: str  # shown to the caller exactly once, never persisted or logged


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _generate_plaintext() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(KEY_RANDOM_BYTES)


def key_scope_violation(
    api_keys: "ApiKeyService", record: ApiKeyRecord, slug: str, server: ServerRecord
) -> Optional[str]:
    """The two per-server scope checks, as a pure predicate: returns None when the key may
    reach this server, or a caller-safe reason string when it may not.

    Lives here rather than on Pipeline because it now has TWO consumers with two different
    error shapes — the data plane raises RoutingError with a JSON-RPC body
    (Pipeline._check_key_scope), and POST /api/v1/policy/evaluate raises HTTPException with a
    REST body (argus/policy_api.py). The checks themselves are a security invariant that must
    not fork between them, so the logic lives in one place and each caller supplies only its
    own way of raising.

    Called by _authenticate (after a fresh verify) and by handle()'s pre_authenticated
    re-dispatch (#111), where the aggregate has already verified the key this request and only
    these checks still need to run. Both are pure Python over the record and the server — no
    DB — so the pre-authenticated path pays nothing for keeping them.

    The first check is key_permits_server — server_scopes is an operator-configured allowlist
    of slugs (may be None = "any server"). The second is the project-agreement invariant that
    must hold regardless: a key minted in project A must never reach a server in project B,
    even if server_scopes was (mis)configured to name that server by slug. The two checks
    COMPOSE (both must pass), neither replaces the other. Deliberately does NOT consult any
    notion of "global admin" — there is no Principal/session on the data plane, only a key;
    the global-admin-superset rule is a CONTROL-plane (session-based) concept in
    archon/project_rbac.py and must never leak into this purely key-vs-server check. That
    holds for the /api/v1 consumer too: POST /api/v1/policy/evaluate authenticates with an API
    key precisely so its project scoping is the key's, not its owner's session role.

    Explicit `is None` check rather than relying on `!=` alone: `None != None` is False in
    Python, so a bare `record.project_id != server.project_id` would treat a project-less KEY
    and a project-less SERVER as matching. Currently unreachable (0010_projects.sql backfills
    every existing row to 'default', and both ApiKeyRepo.create/ServerRepo.create resolve an
    explicit project_id at write time — see that migration's header), but this is the one
    project-boundary check in the codebase that must fail closed on NULL the way
    archon/project_rbac.py's resolvers all deliberately do, even if that invariant is ever
    violated by a future code path.

    The returned string is deliberately identical for both failures — a caller learns only
    that the key is not scoped for the server, never which of the two checks rejected it.
    """
    if not api_keys.key_permits_server(record, slug):
        return f"key not scoped for server '{slug}'"
    if record.project_id is None or record.project_id != server.project_id:
        return f"key not scoped for server '{slug}'"
    return None


class ApiKeyService:
    def __init__(self, repo: ApiKeyRepo):
        self._repo = repo

    async def create(
        self, name: str, server_scopes: Optional[list[str]] = None,
        quota_calls: Optional[int] = None, quota_period: Optional[str] = None,
        project_id: Optional[int] = None,
    ) -> GeneratedKey:
        plaintext = _generate_plaintext()
        key_hash = _hash_key(plaintext)
        display_prefix = plaintext[:DISPLAY_PREFIX_LEN]
        record = await self._repo.create(
            name=name, key_hash=key_hash, key_prefix=display_prefix, server_scopes=server_scopes,
            quota_calls=quota_calls, quota_period=quota_period, project_id=project_id,
        )
        return GeneratedKey(record=record, plaintext=plaintext)

    async def verify(self, plaintext: str) -> Optional[ApiKeyRecord]:
        """Constant-time-safe verify: we hash the presented key and look up by hash equality
        (SQLite equality on the hash column), rather than comparing plaintexts directly."""
        # §26 fix (review 2026-08-04): hmac.compare_digest raises TypeError on a `str` argument
        # containing non-ASCII characters — a bearer token with e.g. a stray unicode character
        # (attacker-controlled, since this is straight off the Authorization header) used to
        # crash this call outright rather than simply failing auth. A malformed/adversarial
        # token must fail closed (401 via the None return below), not blow up the request.
        if not plaintext or not plaintext[: len(KEY_PREFIX)].isascii():
            return None
        if not hmac.compare_digest(plaintext[: len(KEY_PREFIX)], KEY_PREFIX):
            return None
        key_hash = _hash_key(plaintext)
        record = await self._repo.get_by_hash(key_hash)
        if record is not None:
            await self._repo.touch_last_used(record.id)
        return record

    def key_permits_server(self, record: ApiKeyRecord, slug: str) -> bool:
        if record.server_scopes is None:
            return True  # no scopes recorded = access to all servers
        return slug in record.server_scopes

    async def list(self, project_id: Optional[int] = None) -> list[ApiKeyRecord]:
        return await self._repo.list(project_id=project_id)

    async def get(self, key_id: int) -> Optional[ApiKeyRecord]:
        """Get a key by ID, or None if not found. Used by admin_audit for before/after diff."""
        try:
            return await self._repo.get_by_id(key_id)
        except ServerNotFoundError:
            return None

    async def disable(self, key_id: int) -> None:
        await self._repo.set_enabled(key_id, False)

    async def enable(self, key_id: int) -> None:
        await self._repo.set_enabled(key_id, True)

    async def set_quota(self, key_id: int, quota_calls: Optional[int], quota_period: Optional[str]) -> None:
        await self._repo.set_quota(key_id, quota_calls, quota_period)

    async def delete(self, key_id: int) -> None:
        await self._repo.delete(key_id)
