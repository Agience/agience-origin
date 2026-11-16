"""Two entries submitted at once read the same ledger head and choose the same seq. The one whose
row lands second loses the race. Origin then rolls back, reads the head again and decides again,
whether the clash surfaces at the commit or at an earlier flush while the entry is applied (a new
root's node is flushed). The caller gets a receipt, never a 500."""
from __future__ import annotations

from origin.services import authority_ledger as ledger
from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


def _stale_once(monkeypatch):
    """The next head read that chooses a seq answers as it stood one entry ago, as a concurrent
    append sees it."""
    import sys

    real = ledger.head
    state = {"stale": True}

    def head(db):
        last, prev = real(db)
        if state["stale"] and last > 0 and sys._getframe(1).f_code.co_name == "append":
            state["stale"] = False
            return last - 1, prev
        return last, prev

    monkeypatch.setattr(ledger, "head", head)


def test_a_root_that_loses_the_seq_race_is_appended_at_the_next_seq(custody_client, monkeypatch):
    c = custody_client
    _, alice = af.person("alice", email="alice@team.test")
    first = af.ok(af.submit(c, alice, af.root("W")))
    _stale_once(monkeypatch)
    r = af.ok(af.submit(c, alice, af.root("W2")))
    assert r["outcome"] == "appended"
    assert r["seq"] == first["seq"] + 1


def test_a_grant_that_loses_the_seq_race_is_appended_at_the_next_seq(custody_client, monkeypatch):
    c = custody_client
    p, alice = af.person("alice", email="alice@team.test")
    first = af.ok(af.submit(c, alice, af.root("W")))
    _stale_once(monkeypatch)
    r = af.ok(af.submit(c, alice, af.grant("g-aw", p, "W", ["read"])))
    assert r["outcome"] == "appended"
    assert r["seq"] == first["seq"] + 1
