"""Unit coverage for record_secret_reference_change (archon/admin_audit.py) — the enterprise #5
control-plane audit event for a credential change. Exercises every branch (configure / clear /
externalize / replace-with-literal / value-changed / unchanged) directly against a fake repo,
asserting on exactly what gets passed to AdminEventRepo.insert — the value must never appear,
only a shape classification.
"""
from __future__ import annotations

import json

import pytest

from archon.admin_audit import record_secret_reference_change


class _FakeAdminEventRepo:
    def __init__(self):
        self.calls: list[dict] = []

    async def insert(self, **kwargs):
        self.calls.append(kwargs)
        return len(self.calls)


@pytest.mark.asyncio
async def test_unchanged_records_nothing():
    repo = _FakeAdminEventRepo()
    result = await record_secret_reference_change(
        repo, server_slug="s", before_value="Bearer x", after_value="Bearer x",
    )
    assert result is None
    assert repo.calls == []


@pytest.mark.asyncio
async def test_both_none_records_nothing():
    repo = _FakeAdminEventRepo()
    result = await record_secret_reference_change(
        repo, server_slug="s", before_value=None, after_value=None,
    )
    assert result is None
    assert repo.calls == []


@pytest.mark.asyncio
async def test_configuring_a_literal_records_shape_not_value():
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s", before_value=None, after_value="Bearer sk-super-secret-value",
    )
    assert len(repo.calls) == 1
    call = repo.calls[0]
    assert call["action"] == "server.secret_reference_change"
    assert call["target_id"] == "s"
    assert "sk-super-secret-value" not in json.dumps(call)
    after = json.loads(call["after"])
    assert after["upstream_auth_header"] == {"configured": True, "is_reference": False}
    assert call["before"] is None or json.loads(call["before"])["upstream_auth_header"]["configured"] is False


@pytest.mark.asyncio
async def test_configuring_a_reference_records_is_reference_true():
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s", before_value=None, after_value="vault://secret/x#y",
    )
    call = repo.calls[0]
    assert "vault://secret/x#y" not in json.dumps(call)
    after = json.loads(call["after"])
    assert after["upstream_auth_header"] == {"configured": True, "is_reference": True}
    assert "reference" in call["summary"].lower()


@pytest.mark.asyncio
async def test_clearing_records_configured_false():
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s", before_value="Bearer sk-old-secret-value", after_value=None,
    )
    call = repo.calls[0]
    assert "sk-old-secret-value" not in json.dumps(call)
    after = json.loads(call["after"])
    assert after["upstream_auth_header"]["configured"] is False
    assert "cleared" in call["summary"].lower()


@pytest.mark.asyncio
async def test_externalizing_a_literal_to_a_reference_records_the_transition():
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s",
        before_value="Bearer sk-literal-secret-value",
        after_value="vault://secret/x#y",
    )
    call = repo.calls[0]
    joined = json.dumps(call)
    assert "sk-literal-secret-value" not in joined
    assert "vault://secret/x#y" not in joined
    before = json.loads(call["before"])
    after = json.loads(call["after"])
    assert before["upstream_auth_header"] == {"configured": True, "is_reference": False}
    assert after["upstream_auth_header"] == {"configured": True, "is_reference": True}
    assert "externalized" in call["summary"].lower()


@pytest.mark.asyncio
async def test_replacing_a_reference_with_a_literal_records_the_transition():
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s",
        before_value="vault://secret/x#y",
        after_value="Bearer sk-new-literal-secret",
    )
    call = repo.calls[0]
    assert "sk-new-literal-secret" not in json.dumps(call)
    assert "literal" in call["summary"].lower()


@pytest.mark.asyncio
async def test_value_changed_same_shape_records_generic_summary():
    """Two literals, or two references, that differ — the shape classification alone can't say
    WHAT changed (that would require comparing values, which must never happen), so this falls
    back to a generic 'credential value changed' summary. Still never the value."""
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s",
        before_value="Bearer sk-old-value", after_value="Bearer sk-new-value",
    )
    call = repo.calls[0]
    joined = json.dumps(call)
    assert "sk-old-value" not in joined
    assert "sk-new-value" not in joined
    assert call["summary"] == "credential value changed"


@pytest.mark.asyncio
async def test_two_references_to_different_paths_records_generic_summary():
    repo = _FakeAdminEventRepo()
    await record_secret_reference_change(
        repo, server_slug="s",
        before_value="vault://secret/a#x", after_value="vault://secret/b#y",
    )
    call = repo.calls[0]
    joined = json.dumps(call)
    assert "vault://secret/a#x" not in joined
    assert "vault://secret/b#y" not in joined
    assert call["summary"] == "credential value changed"


@pytest.mark.asyncio
async def test_ciphertext_before_after_never_appears_either():
    """The encrypted tier's ciphertext must be withheld exactly like a literal or a reference —
    it's classified as 'not a reference' (is_reference only recognizes vault:// and enc:v1: —
    wait, enc:v1: IS recognized) — confirms enc:v1: ciphertext is treated as a reference shape,
    consistent with config export's treatment of it, and never appears in the audit row."""
    repo = _FakeAdminEventRepo()
    ciphertext = "enc:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    await record_secret_reference_change(
        repo, server_slug="s", before_value=None, after_value=ciphertext,
    )
    call = repo.calls[0]
    assert ciphertext not in json.dumps(call)
    after = json.loads(call["after"])
    assert after["upstream_auth_header"] == {"configured": True, "is_reference": True}
