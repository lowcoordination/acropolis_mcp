from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Optional

from db.models import ApiKeyRecord
from db.repo import ApiKeyRepo

KEY_PREFIX = "argus_"
KEY_RANDOM_BYTES = 32
DISPLAY_PREFIX_LEN = 12  # "argus_" + 6 chars, enough to identify a key in the UI without revealing it


@dataclass
class GeneratedKey:
    record: ApiKeyRecord
    plaintext: str  # shown to the caller exactly once, never persisted or logged


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _generate_plaintext() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(KEY_RANDOM_BYTES)


class ApiKeyService:
    def __init__(self, repo: ApiKeyRepo):
        self._repo = repo

    async def create(self, name: str, server_scopes: Optional[list[str]] = None) -> GeneratedKey:
        plaintext = _generate_plaintext()
        key_hash = _hash_key(plaintext)
        display_prefix = plaintext[:DISPLAY_PREFIX_LEN]
        record = await self._repo.create(
            name=name, key_hash=key_hash, key_prefix=display_prefix, server_scopes=server_scopes
        )
        return GeneratedKey(record=record, plaintext=plaintext)

    async def verify(self, plaintext: str) -> Optional[ApiKeyRecord]:
        """Constant-time-safe verify: we hash the presented key and look up by hash equality
        (SQLite equality on the hash column), rather than comparing plaintexts directly."""
        if not plaintext or not hmac.compare_digest(plaintext[: len(KEY_PREFIX)], KEY_PREFIX):
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

    async def list(self) -> list[ApiKeyRecord]:
        return await self._repo.list()

    async def disable(self, key_id: int) -> None:
        await self._repo.set_enabled(key_id, False)

    async def enable(self, key_id: int) -> None:
        await self._repo.set_enabled(key_id, True)

    async def delete(self, key_id: int) -> None:
        await self._repo.delete(key_id)
