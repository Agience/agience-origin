"""Review 19, M1: Mantle's and Origin's digests of reach, over real stores of one scenario, see
drift in every field that could widen reach: a grant's actions, effect and state, its canonical UTC
expiry, an invite's target (kind and digest) and claim limit, and an edge's creation flag and mask.
Both canonical forms are `prism.trust.ledger.canonical_reach`.

Origin's real ledger builds Origin's replica; Mantle's real store is built by Mantle's real
`apply_remote` over Origin's real feed, plus Mantle's own writes of the entries it submitted
itself. The scenario deletes a node at Origin (a creation edge removed), so a gone node is in it.
"""
# ruff: noqa: F811
from __future__ import annotations

import tempfile
import time
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, world)

custody_client = _shares.custody_client


class _RealFeed:
    def ledger_feed(self, after):
        from origin.db.session import SessionLocal
        from origin.routers import authority_router
        real = authority_router.bound_call
        authority_router.bound_call = lambda *a, **k: ""     # the service-token check only
        try:
            with SessionLocal() as db:
                return authority_router.ledger_feed(None, after=after, db=db, auth=None)
        finally:
            authority_router.bound_call = real


@pytest.fixture
def keys(monkeypatch):
    from jose import jwk
    from mantle.services import authority_ledger as mantle_ledger
    from origin.key_manager import get_key_id, get_public_key_pem
    key = jwk.construct(get_public_key_pem(), "RS256")
    monkeypatch.setattr(mantle_ledger, "_origin_keys", lambda: {get_key_id(): key})


def _scenario(c, world):
    alice, bob, carol = world["alice"][0], world["bob"][0], world["carol"][0]
    soon = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    later = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    af.ok(af.session_submit(c, alice, af.grant("g-exp", carol, "W", ["read"], expires_at=soon)))
    af.ok(af.session_submit(c, alice, af.grant("g-day", carol, "W", ["update"],
                                               expires_at=later)))
    af.ok(af.session_submit(c, alice, af.grant("g-rev", carol, "W", ["delete"])))
    af.ok(af.session_submit(c, alice, af.grant("g-rev", carol, "W", ["delete"],
                                               state="revoked")))
    af.ok(af.session_submit(c, alice, af.invite("g-inv", "tok-1", "W", ["read"],
                                                target=("email", "dana@team.test"),
                                                max_claims=1, expires_at=later)))
    af.ok(af.session_submit(c, alice, af.grant("g-deny", bob, "W", ["share"], effect="deny")))
    a = world["alice"][1]
    for coll in ("C", "C2"):
        af.ok(af.submit(c, a, af.edge("W", coll), batch=f"mk-{coll}"))   # creation edges
        af.ok(af.submit(c, a, af.grant(f"g-a-{coll}", alice, coll, ALL), batch=f"mk-{coll}"))
    af.ok(af.submit(c, a, af.edge("C", "C2", origin=False, propagate=["update"])))  # narrowed
    af.ok(af.session_submit(c, alice, af.grant("g-deny-c2", carol, "C2", ["read"],
                                               effect="deny")))
    af.ok(af.session_submit(c, alice, af.unedge("W", "C2")))       # C2 deleted at Origin, with
    #                                                                a deny on it still held
    time.sleep(2.5)                          # g-exp is now past, still `active` in both stores


def _mantle_catches_up(store):
    from mantle.db import reach_journal
    from mantle.services import authority_ledger as ml
    feed = _RealFeed()
    after, entries = 0, []
    while True:
        page = [e for e in feed.ledger_feed(after).get("entries") or []
                if int(e["seq"]) > after]
        if not page:
            break
        entries += page
        after = max(int(e["seq"]) for e in page)
    for e in entries:
        if e.get("credential_kind") not in ml.MANTLE_APPLIES:
            with reach_journal.suspended():
                ml._apply_session(store, e)
    ml.apply_remote(store, feed)


def _digests(store):
    from mantle.services import authority_ledger as ml
    from origin.db.session import SessionLocal
    from origin.services.authority_digest import replica_digest
    with SessionLocal() as db:
        theirs = replica_digest(db)
    return ml.reach_digest(store), theirs


def _fresh_store():
    from mantle.db import lattice_api as la
    tmp = tempfile.mkdtemp()
    store = la.LatticeDatabase(tmp + "/m.db", origin="m")
    _mantle_catches_up(store)
    return store


def _drift(store, gid, change):
    doc = store.artifacts.get_artifact(gid)
    store.artifacts.put_artifact({**{k: v for k, v in doc.items() if not k.startswith("_")},
                                  **change})


def test_digests_agree_on_one_scenario(custody_client, world, keys):
    _scenario(custody_client, world)
    mine, theirs = _digests(_fresh_store())
    assert mine == theirs


@pytest.mark.parametrize("gid,change", [
    ("g-exp", {"expires_at": None}),                       # an expired Read lives for ever
    ("g-day", {"expires_at": None}),
    ("g-inv", {"max_claims": None}),                       # an invite claimed any number of times
    ("g-inv", {"target_digest": "0" * 64}),                # for anyone
    ("g-inv", {"target_entity_type": "domain"}),
    ("g-day", {"can_admin": True}),                        # the control: actions were always seen
])
def test_each_drift_that_could_widen_reach_is_seen(custody_client, world, keys, gid, change):
    _scenario(custody_client, world)
    store = _fresh_store()
    mine, theirs = _digests(store)
    assert mine == theirs
    _drift(store, gid, change)
    mine, theirs = _digests(store)
    assert mine["digest"] != theirs["digest"], (gid, change)
