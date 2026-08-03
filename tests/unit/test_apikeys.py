from __future__ import annotations

from pathlib import Path

import pytest

from archon.auth.apikeys import ApiKeyService, KEY_PREFIX
from db.database import Database
from db.repo import ApiKeyRepo


@pytest.fixture
async def service(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield ApiKeyService(ApiKeyRepo(database))
    await database.close()


async def test_create_returns_plaintext_once(service):
    generated = await service.create("test-key")
    assert generated.plaintext.startswith(KEY_PREFIX)
    assert generated.record.name == "test-key"
    assert generated.record.key_prefix == generated.plaintext[:12]


async def test_verify_accepts_correct_plaintext(service):
    generated = await service.create("test-key")
    record = await service.verify(generated.plaintext)
    assert record is not None
    assert record.id == generated.record.id


async def test_verify_rejects_wrong_key(service):
    await service.create("test-key")
    record = await service.verify("argus_totally-wrong-key")
    assert record is None


async def test_verify_rejects_malformed_key(service):
    record = await service.verify("not-even-prefixed")
    assert record is None


async def test_verify_rejects_empty_string(service):
    assert await service.verify("") is None


async def test_disabled_key_fails_verify(service):
    generated = await service.create("test-key")
    await service.disable(generated.record.id)
    record = await service.verify(generated.plaintext)
    assert record is None


async def test_key_permits_server_no_scopes_means_all(service):
    generated = await service.create("test-key")
    assert service.key_permits_server(generated.record, "any-server") is True


async def test_key_permits_server_scoped(service):
    generated = await service.create("test-key", server_scopes=["shell", "fetch"])
    assert service.key_permits_server(generated.record, "shell") is True
    assert service.key_permits_server(generated.record, "github") is False


async def test_verify_touches_last_used(service):
    generated = await service.create("test-key")
    assert generated.record.last_used_at is None
    await service.verify(generated.plaintext)
    updated = await service.list()
    assert updated[0].last_used_at is not None


async def test_two_keys_have_different_hashes(service):
    a = await service.create("a")
    b = await service.create("b")
    assert a.plaintext != b.plaintext
    # verifying one must not match the other
    assert (await service.verify(a.plaintext)).id != (await service.verify(b.plaintext)).id
