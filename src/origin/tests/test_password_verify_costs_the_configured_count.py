"""A failed password verify costs at least the configured derivation count, whatever the hash.

Timing a failed sign-in must not tell a caller which accounts carry a hash written at a lower
count, in an unknown format, or unparseable: each of those would otherwise derive less than
`dummy_verify_password` does for an unknown account.
"""

from __future__ import annotations

import pytest

from origin.services import auth_service


@pytest.fixture()
def counted(monkeypatch):
    """Record the iteration count of every derivation, running each at a tiny real cost."""
    real = auth_service._pbkdf2_sha256
    counts = []

    def fake(password, salt, iters):
        counts.append(iters)
        return real(password, salt, 1)

    monkeypatch.setattr(auth_service, "_configured_iters", lambda: 1000)
    monkeypatch.setattr(auth_service, "_pbkdf2_sha256", fake)
    return counts


def _hash_at(iters, monkeypatch):
    monkeypatch.setattr(auth_service, "_configured_iters", lambda: iters)
    h = auth_service.hash_password("correct horse")
    monkeypatch.setattr(auth_service, "_configured_iters", lambda: 1000)
    return h


def test_the_dummy_costs_the_configured_count(counted):
    auth_service.dummy_verify_password("guess")
    assert sum(counted) == 1000


@pytest.mark.parametrize("password", ["guess", "correct horse"])
def test_a_stale_hash_costs_the_configured_count(counted, monkeypatch, password):
    stale = _hash_at(100, monkeypatch)
    counted.clear()
    ok = auth_service.verify_password(password, stale)
    assert ok is (password == "correct horse")
    assert sum(counted) == 1000, counted


def test_a_current_hash_costs_the_configured_count_once(counted, monkeypatch):
    current = _hash_at(1000, monkeypatch)
    counted.clear()
    assert auth_service.verify_password("guess", current) is False
    assert counted == [1000]


@pytest.mark.parametrize("stored", ["bcrypt$12$abc$def", "not-a-hash", "pbkdf2_sha256$x$y$z"])
def test_an_unreadable_hash_costs_the_configured_count(counted, stored):
    assert auth_service.verify_password("guess", stored) is False
    assert sum(counted) == 1000, counted
