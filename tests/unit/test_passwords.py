from __future__ import annotations

from archon.passwords import hash_password, verify_password


def test_hash_and_verify_roundtrip():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)


def test_verify_rejects_wrong_password():
    stored = hash_password("correct-password")
    assert not verify_password("wrong-password", stored)


def test_two_hashes_of_same_password_differ():
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a != b  # different random salts


def test_verify_rejects_malformed_hash():
    assert not verify_password("anything", "not-a-valid-hash")


def test_verify_rejects_unknown_algorithm():
    assert not verify_password("x", "bcrypt$12$salt$hash")
