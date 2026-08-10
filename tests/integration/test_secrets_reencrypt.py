"""Integration tests for the R2 re-encryption walk (argus/reencrypt.py, issue #29).

The walk is the operator-facing half of key rotation: with the NEW key active at the front of
the ring, it rewrites every stored `enc:v1:` credential under that active key so the OLD key
can then be dropped. These tests prove the full rotation sequence against a real database:
seed under the old key → dry run reports without writing → apply rewrites → the new key alone
resolves and the old key alone no longer does, with literals/vault refs skipped and failed
resolutions reported with their rows left untouched.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from archon.secrets import SecretResolutionError
from archon.secrets.encrypted import EncryptedSecretProvider, KeyRing, _parse_key_material
from argus.reencrypt import reencrypt_credentials
from db.database import Database
from db.repo import ServerRepo


def _hex_key() -> str:
    return os.urandom(32).hex()


def _provider(hexes: list[str]) -> EncryptedSecretProvider:
    return EncryptedSecretProvider(key_ring=KeyRing([_parse_key_material(k) for k in hexes]))


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path)
    await database.connect()
    yield database
    await database.close()


async def test_full_rotation_sequence(db):
    """Seed under the old key → dry-run preview → apply → new key alone resolves, old key
    alone no longer does. Literals, vault refs, and no-credential servers are skipped."""
    old_k, new_k = _hex_key(), _hex_key()
    secret = "Bearer sk-rotation-e2e"
    old_ref = await _provider([old_k]).store("seed", secret)

    server_repo = ServerRepo(db)
    await server_repo.create(
        slug="s1", name="S1", upstream_url="http://localhost:9000/mcp",
        upstream_auth_header=old_ref,
    )
    await server_repo.create(
        slug="s2", name="S2", upstream_url="http://localhost:9001/mcp",
        upstream_auth_header="Bearer literal-credential",
    )
    await server_repo.create(
        slug="s3", name="S3", upstream_url="http://localhost:9002/mcp",
    )
    await server_repo.create(
        slug="s4", name="S4", upstream_url="http://localhost:9003/mcp",
        upstream_auth_header="vault://kv/data/upstream#key",
    )

    ring = _provider([new_k, old_k])  # new active, old retained for decryption

    # Dry run: reports exactly the one enc:v1: credential, writes NOTHING.
    preview = await reencrypt_credentials(ring, server_repo, dry_run=True)
    assert preview.scanned == 4
    assert preview.reencrypted == 1
    assert preview.skipped == 3
    assert preview.failed == []
    assert (await server_repo.get("s1")).upstream_auth_header == old_ref  # untouched

    # Apply: rewrites it.
    result = await reencrypt_credentials(ring, server_repo, dry_run=False)
    assert result.reencrypted == 1
    assert result.failed == []

    stored = (await server_repo.get("s1")).upstream_auth_header
    assert stored != old_ref

    # Rotation complete: the NEW key alone resolves; the OLD key alone cannot anymore.
    assert await _provider([new_k]).resolve(stored) == secret
    with pytest.raises(SecretResolutionError):
        await _provider([old_k]).resolve(stored)

    # Idempotent: a second apply rewrites the already-active ciphertext under the same active
    # key (different nonce, same plaintext) and still succeeds.
    again = await reencrypt_credentials(ring, server_repo, dry_run=False)
    assert again.reencrypted == 1
    assert await _provider([new_k]).resolve((await server_repo.get("s1")).upstream_auth_header) == secret


async def test_failed_resolution_reported_and_row_left_untouched(db):
    """A credential whose key is NOT in the ring (dropped before re-encryption, or corrupted)
    is reported by slug, its row keeps its old ciphertext, and the walk still completes the
    rest — nothing is ever half-applied or lost."""
    foreign_k = _hex_key()
    new_k = _hex_key()
    secret = "Bearer sk-orphaned"
    foreign_ref = await _provider([foreign_k]).store("seed", secret)

    server_repo = ServerRepo(db)
    await server_repo.create(
        slug="orphan", name="Orphan", upstream_url="http://localhost:9000/mcp",
        upstream_auth_header=foreign_ref,
    )
    await server_repo.create(
        slug="healthy", name="Healthy", upstream_url="http://localhost:9001/mcp",
        upstream_auth_header=await _provider([new_k]).store("seed", "Bearer sk-healthy"),
    )

    # The ring does NOT contain foreign_k — orphan's credential cannot be resolved.
    ring = _provider([new_k])
    result = await reencrypt_credentials(ring, server_repo, dry_run=False)

    assert len(result.failed) == 1
    assert result.failed[0][0] == "orphan"
    assert "decryption failed" in result.failed[0][1]
    assert result.reencrypted == 1  # healthy still got rewritten

    # The orphan row keeps its original ciphertext — no data loss.
    orphan_row = await server_repo.get("orphan")
    assert orphan_row.upstream_auth_header == foreign_ref
