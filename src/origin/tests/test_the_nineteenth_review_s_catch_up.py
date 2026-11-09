# ruff: noqa: F811
"""Review 19, M2: the catch-up reads the ledger to its head and takes each row's latest change
over the whole ledger, whatever its kind, so a change Mantle made itself after the cursor is never
undone. It runs under `ledger:catchup-review19`, so a store an earlier run marked is redone, and a
failure inside it never stalls the feed: the feed's own pass goes on, the catch-up stays undone,
and an ALARM is raised.

Runs Origin's real routes and feed and Mantle's real `apply_remote` / `catch_up_skipped`.
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, world)

pytest.importorskip("mantle", reason="a cross-repository case: it reads Mantle's own code, which the sovereign CI's workspace has and a lone checkout of Origin does not")

custody_client = _shares.custody_client


class _RealFeed:
    def ledger_feed(self, after):
        from origin.db.session import SessionLocal
        from origin.routers import authority_router
        real = authority_router.bound_call
        authority_router.bound_call = lambda *a, **k: ""
        try:
            with SessionLocal() as db:
                return authority_router.ledger_feed(None, after=after, db=db, auth=None)
        finally:
            authority_router.bound_call = real


@pytest.fixture
def mantle_store(tmp_path, monkeypatch):
    from jose import jwk
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    from origin.key_manager import get_key_id, get_public_key_pem
    key = jwk.construct(get_public_key_pem(), "RS256")
    monkeypatch.setattr(mantle_ledger, "_origin_keys", lambda: {get_key_id(): key})
    return la.LatticeDatabase(str(tmp_path / "m.db"), origin="m")


def _entries(after=0):
    out, feed = [], _RealFeed()
    while True:
        page = [e for e in feed.ledger_feed(after).get("entries") or [] if int(e["seq"]) > after]
        if not page:
            return out
        out += page
        after = max(int(e["seq"]) for e in page)


def _mantle_writes_its_own(store, after=0):
    """What Mantle wrote itself (its submissions), as its store holds them."""
    from mantle.db import reach_journal
    from mantle.services import authority_ledger as ml
    for e in _entries(after):
        if e.get("credential_kind") not in ml.MANTLE_APPLIES:
            with reach_journal.suspended():
                ml._apply_session(store, e)


def _edge(store, src, dst):
    return store.graph.db.read().execute(
        "SELECT 1 FROM edge WHERE src = ? AND dst = ? AND label = 'contains'",
        (src, dst)).fetchone() is not None


def test_a_link_mantle_removed_after_the_cursor_stays_removed(
        custody_client, world, mantle_store, monkeypatch):
    from mantle.services import authority_ledger as ml
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEdge
    from origin.services.authority_digest import replica_digest

    c, a, alice = custody_client, world["alice"][1], world["alice"][0]
    for coll in ("C", "C2"):
        af.ok(af.submit(c, a, af.edge("W", coll)))
    # Alice links C -> C2 in her session.
    r = af.session_submit(c, alice, af.edge("C", "C2", origin=False, propagate=None))
    print(f"\nsession link: {r.status_code} {r.text[:120]}")
    af.ok(r)
    _mantle_writes_its_own(mantle_store)

    # An older Mantle's pass: session entries skipped, cursor to the head.
    monkeypatch.setattr(ml, "MANTLE_APPLIES", frozenset({"origin_page", "operator"}))
    monkeypatch.setattr(ml, "catch_up_skipped", lambda *a, **k: 0)
    ml.apply_remote(mantle_store, _RealFeed())
    cursor = mantle_store.graph.db.read().execute(
        "SELECT seq FROM authority_receipt WHERE subject = 'ledger:applied'").fetchone()[0]
    assert not _edge(mantle_store, "C", "C2")

    # Mantle removes the link on Alice's own token (its own submission) and in its store.
    r = af.submit(c, a, af.unedge("C", "C2"), via_session=False)
    print(f"Mantle-submitted removal: {r.status_code} {r.text[:160]}")
    af.ok(r)
    with SessionLocal() as db:
        assert db.get(AuthorityEdge, ("C", "C2")) is None             # Origin: no link
    _mantle_writes_its_own(mantle_store, after=cursor)

    # The upgraded Mantle's first pass.
    monkeypatch.undo()
    from jose import jwk
    from origin.key_manager import get_key_id, get_public_key_pem
    key = jwk.construct(get_public_key_pem(), "RS256")
    monkeypatch.setattr(ml, "_origin_keys", lambda: {get_key_id(): key})
    ml.apply_remote(mantle_store, _RealFeed())

    assert not _edge(mantle_store, "C", "C2"), "the catch-up put back what Mantle removed"
    mine = ml.reach_digest(mantle_store)
    with SessionLocal() as db:
        theirs = replica_digest(db)
    assert mine["digest"] == theirs["digest"]
    assert ml.catch_up_skipped(mantle_store, _RealFeed()) == 0         # recorded done


def _older_mantle_pass(store, monkeypatch):
    from mantle.services import authority_ledger as ml
    with monkeypatch.context() as m:
        m.setattr(ml, "MANTLE_APPLIES", frozenset({"origin_page", "operator"}))
        m.setattr(ml, "catch_up_skipped", lambda *a, **k: 0)
        ml.apply_remote(store, _RealFeed())
    return store.graph.db.read().execute(
        "SELECT seq FROM authority_receipt WHERE subject = 'ledger:applied'").fetchone()[0]


def test_a_grant_mantle_retired_after_the_cursor_stays_retired(custody_client, world,
                                                                mantle_store, monkeypatch):
    """A session grant before the cursor; after it, Alice's token (which Mantle holds) deletes
    the grant's resource and retires the grant with it. The catch-up writes the latest change,
    Mantle's own retirement, not the session's grant."""
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as ml
    c, a, alice_id = custody_client, world["alice"][1], world["alice"][0]
    carol_id = world["carol"][0]
    af.ok(af.submit(c, a, af.edge("W", "S"), batch="mk", via_session=False))
    af.ok(af.submit(c, a, af.grant("g-as", alice_id, "S", ALL), batch="mk", via_session=False))
    af.ok(af.session_submit(c, alice_id, af.grant("g-cs", carol_id, "S", ["read"])))
    _mantle_writes_its_own(mantle_store)
    cursor = _older_mantle_pass(mantle_store, monkeypatch)
    af.ok(af.submit(c, a, af.unedge("W", "S"), batch="del", via_session=False))
    af.ok(af.submit(c, a, af.grant("g-cs", carol_id, "S", ["read"], state="deleted"),
                    batch="del", via_session=False))
    _mantle_writes_its_own(mantle_store, after=cursor)
    assert la.get_grant_by_id(mantle_store, "g-cs").state == "deleted"
    ml.apply_remote(mantle_store, _RealFeed())
    assert la.get_grant_by_id(mantle_store, "g-cs").state == "deleted"


def test_a_background_withdrawal_after_the_cursor_stands(custody_client, world, mantle_store,
                                                         monkeypatch):
    """A session link before the cursor; after it, Mantle unlinks and links again on Alice's
    token, and the system principal's retry withdraws that last link (a background entry). The
    catch-up writes the latest, the background withdrawal: no link."""
    from mantle.services import authority_ledger as ml
    from origin import service_identity
    from origin.services import authority_ledger as origin_ledger
    c, a, alice_id = custody_client, world["alice"][1], world["alice"][0]
    for coll in ("C", "C2"):
        af.ok(af.submit(c, a, af.edge("W", coll)))
    af.ok(af.session_submit(c, alice_id, af.edge("C", "C2", origin=False, propagate=None)))
    _mantle_writes_its_own(mantle_store)
    cursor = _older_mantle_pass(mantle_store, monkeypatch)
    af.ok(af.submit(c, a, af.unedge("C", "C2"), via_session=False))
    again = af.ok(af.submit(c, a, af.edge("C", "C2", origin=False), via_session=False))
    sys_id = "00000000-0000-0000-0000-00000000aaaa"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: sys_id)
    monkeypatch.setattr(origin_ledger, "COMPENSATION_WINDOW_SECONDS", -1)
    bg = af.background(sys_id, job="ledger.retry", collections=("C",))
    af.ok(af.submit(c, bg, af.unedge("C", "C2"), compensates=again["seq"]))
    _mantle_writes_its_own(mantle_store, after=cursor)
    assert not _edge(mantle_store, "C", "C2")
    ml.apply_remote(mantle_store, _RealFeed())
    assert not _edge(mantle_store, "C", "C2")


def test_a_store_an_earlier_catch_up_marked_is_redone(custody_client, world, mantle_store,
                                                     monkeypatch):
    from mantle.services import authority_ledger as ml
    assert ml._CATCHUP == "ledger:catchup-review19"
    with mantle_store.graph.db.write() as cur:
        for old in ("ledger:catchup-review17", "ledger:catchup-review18"):
            cur.execute("INSERT OR REPLACE INTO authority_receipt(subject, kind, seq, entry_hash) "
                        "VALUES(?, 'catchup', 1, NULL)", (old,))
    c, alice_id = custody_client, world["alice"][0]
    af.ok(af.session_submit(c, alice_id, af.grant("g-cu", world["carol"][0], "W", ["update"])))
    _older_mantle_pass(mantle_store, monkeypatch)
    ml.apply_remote(mantle_store, _RealFeed())
    from mantle.db import lattice_api as la
    assert la.get_grant_by_id(mantle_store, "g-cu") is not None


def test_a_failing_catch_up_never_stalls_the_feed(custody_client, world, mantle_store,
                                                 monkeypatch, caplog):
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as ml
    c, alice_id = custody_client, world["alice"][0]
    _older_mantle_pass(mantle_store, monkeypatch)
    af.ok(af.session_submit(c, alice_id, af.grant("g-new", world["carol"][0], "W", ["update"])))

    def boom(*a, **k):
        raise RuntimeError("the catch-up broke")
    monkeypatch.setattr(ml, "_read_ledger", boom)
    ml.apply_remote(mantle_store, _RealFeed())
    assert la.get_grant_by_id(mantle_store, "g-new") is not None          # the feed went on
    assert any("ALARM" in r.getMessage() and "catch-up" in r.getMessage()
               for r in caplog.records)
    row = mantle_store.graph.db.read().execute(
        "SELECT seq FROM authority_receipt WHERE subject = ?", (ml._CATCHUP,)).fetchone()
    assert row is None                                                    # still undone
