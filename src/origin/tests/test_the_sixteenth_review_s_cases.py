"""Review 16.

H1: no edge change lifts an ancestor deny at release: a deny anywhere up a node's creation chain
holds whatever each edge on the way conducts. And a background delegation (the system principal's
`ledger.retry` job) changes nothing new: it never narrows a mask, demotes or removes a creation
edge, or retires a grant. It only restates what Origin already holds, or re-submits a withdrawal
of a secondary edge within the collections its job grant lists. Anything else it would withdraw is
the operator's to resolve.
"""
# ruff: noqa: F811
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, _edge_row, world)

custody_client = _shares.custody_client
SYS = "00000000-0000-0000-0000-00000000aaaa"


@pytest.fixture
def system(monkeypatch):
    from origin import service_identity
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: SYS)


def _retry(collections=("platform-only",)):
    """The retry job's delegation, its grant listing `collections` (one grant per list: the
    fixture keeps one grant per job name)."""
    return af.background(SYS, job="ledger.retry." + "-".join(collections) if collections != (
        "platform-only",) else "ledger.retry", collections=collections)


def _c_under_a_deny(c, world):
    alice_id, alice = world["alice"]
    carol_id, _carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "C"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-ac", alice_id, "C", ALL), batch="mk",
                    via_session=False))
    af.ok(af.session_submit(c, alice_id, af.grant("g-cc", carol_id, "C", ["read"])))
    af.ok(af.session_submit(c, alice_id, af.grant("g-deny-cw", carol_id, "W", ["read"],
                                                  effect="deny")))
    af.store_share(c, "ck:C")


def test_a_background_delegation_narrows_no_edge(custody_client, world, system):
    c = custody_client
    _c_under_a_deny(c, world)
    for coll in (("platform-only",), ("W",), ("W", "C")):
        r = af.submit(c, _retry(coll), af.edge("W", "C", propagate=["create"]), batch=None,
                      via_session=False)
        assert r.status_code == 403, (coll, r.text)
    assert _edge_row("W", "C").propagate is None
    assert af.release(c, "ck:C", world["carol"][1], collection="C").status_code == 403


def test_an_ancestor_deny_holds_whatever_the_edges_below_it_conduct(custody_client, world):
    """Alice herself narrows W -> C (Admin's to do): the deny on W still holds at release."""
    c = custody_client
    _c_under_a_deny(c, world)
    af.ok(af.session_submit(c, world["alice"][0], af.edge("W", "C", propagate=["create"])))
    assert _edge_row("W", "C").propagate is not None
    assert af.release(c, "ck:C", world["carol"][1], collection="C").status_code == 403


def test_a_background_delegation_demotes_removes_or_retires_nothing(custody_client, world,
                                                                     system):
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.edge("W", "D"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-ad", alice_id, "D", ALL), batch="mk",
                    via_session=False))
    for entry in (af.edge("W", "D", origin=False), af.unedge("W", "D"),
                  af.grant("g-ad", alice_id, "D", ALL, state="retired")):
        r = af.submit(c, _retry(("W", "D")), entry, batch=None, via_session=False)
        assert r.status_code == 403, (entry, r.text)
    af.store_share(c, "ck:D")
    assert af.release(c, "ck:D", alice, collection="D").status_code == 200


def test_a_background_delegation_restates_what_origin_holds(custody_client, world, system):
    c = custody_client
    af.ok(af.submit(c, world["alice"][1], af.edge("W", "E"), batch="mk", via_session=False))
    r = af.submit(c, _retry(), af.edge("W", "E"), batch=None, via_session=False)
    assert r.status_code == 200 and r.json()["outcome"] == "unchanged", r.text


def test_a_retried_withdrawal_is_taken_only_within_the_job_s_collections(custody_client, world,
                                                                         system, monkeypatch):
    """Mantle's outstanding withdrawal of Alice's secondary edge, retried by the system principal:
    taken only when the job grant lists the collection, and never for a creation edge."""
    from origin.services import authority_ledger
    c = custody_client
    _alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.root("Y"), batch="y", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-ay", world["alice"][0], "Y", ALL), batch="y",
                    via_session=False))
    secondary = af.ok(af.submit(c, alice, af.edge("W", "Y", origin=False), batch="s",
                                via_session=False))
    creation = af.ok(af.submit(c, alice, af.edge("W", "F"), batch="f", via_session=False))
    monkeypatch.setattr(authority_ledger, "COMPENSATION_WINDOW_SECONDS", -1)
    r = af.submit(c, _retry(("platform-only",)), af.unedge("W", "Y"),
                  compensates=secondary["seq"])
    assert r.status_code == 403, r.text
    r = af.submit(c, _retry(("W",)), af.unedge("W", "F"), compensates=creation["seq"])
    assert r.status_code == 403, r.text
    af.ok(af.submit(c, _retry(("W",)), af.unedge("W", "Y"), compensates=secondary["seq"]))


# -- John's decision (2026-11-03): "It's not a drop key. It's a grant with Add rights and nothing
# else." Write-without-read is an Add grant at Origin; sealing what is added is Mantle's key
# material, never an authority object -------------------------------------------------------------

PUB = "A" * 43 + "="


def test_origin_takes_no_drop_key_entry(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    r = af.submit(c, alice, {"kind": "drop_key", "collection_id": "W", "public": PUB},
                  batch=None, via_session=False)
    assert r.status_code == 400 and "Add" in r.text, r.text


def test_origin_holds_no_drop_key_and_serves_none(custody_client):
    from origin.db.base import Base
    from origin.main import app
    assert "authority_drop_keys" not in Base.metadata.tables
    paths = {getattr(r, "path", "") for r in app.routes}
    assert not [p for p in paths if "drop-key" in p], paths
    from origin.services import authority_ledger, authority_reach
    assert not hasattr(authority_ledger, "replace_drop_key")
    assert not hasattr(authority_reach.MemoryReplica(), "drop_keys")


def test_an_add_only_writer_is_authorized_by_an_add_grant(custody_client, world):
    """What lets a sender write into an inbox without reading it is an Add grant, decided at
    Origin like any action."""
    c = custody_client
    alice_id, alice = world["alice"]
    sam_id, sam = af.person("sam", email="sam@team.test")
    af.ok(af.session_submit(c, alice_id, af.grant("g-sam", sam_id, "W", ["add"])))
    from origin.db.session import SessionLocal
    from origin.services.authority_ledger import reach
    with SessionLocal() as db:
        rc = reach(db)
        assert rc.reaches(sam_id, "W", "add") and not rc.reaches(sam_id, "W", "read")
    af.store_share(c, "ck:W")
    assert af.release(c, "ck:W", sam, collection="W").status_code == 403


# -- I4: retire_root owns everything of the id, its key shares included -------------------------

def test_retiring_a_root_takes_its_key_shares_so_a_recreated_id_inherits_nothing(custody_client,
                                                                                 world):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyShare
    from origin.services import authority_ledger
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.root("R"), batch="r", via_session=False))
    af.store_share(c, "ck:R")
    with SessionLocal() as db:
        assert db.get(KeyCustodyShare, "ck:R") is not None
        authority_ledger.retire_root(db, "R", "operator-1", "retire-R")
        assert db.get(KeyCustodyShare, "ck:R") is None


# -- I5: a gone node is not registered as a root --------------------------------------------------

def test_a_node_deleted_at_origin_is_not_registered_as_a_root(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.edge("W", "G"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-ag", alice_id, "G", ALL), batch="mk",
                    via_session=False))
    af.ok(af.submit(c, alice, af.unedge("W", "G"), batch="del", via_session=False))
    r = af.submit(c, alice, af.root("G"), batch="again", via_session=False)
    assert r.status_code in (403, 409), r.text
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:                              # by bootstrap either
        rc = authority_ledger.reach(db)
        ctx = authority_ledger.Context(actor="", kind="bootstrap", bootstrap=True)
        import pytest as _pytest
        with _pytest.raises(authority_ledger.EntryRefused, match="deleted"):
            authority_ledger._decide_root(rc, ctx, {"principal_id": "G", "root_id": "G"})


# -- L3: the preview names each parent's creator and creation date -------------------------------

def test_the_preview_names_each_parent_s_creator_and_its_creation_date(custody_client, world):
    """Origin holds no item names, so next to each parent id it shows what a person recognizes:
    who brought it into being (their display name at Origin) and when."""
    from origin.tests.test_the_thirteenth_review_s_session_cases import BASE, _as, _hdr
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.edge("W", "S"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-as", alice_id, "S", ALL), batch="mk",
                    via_session=False))
    _as(c, alice_id)
    body = c.post(f"{BASE}/preview", json={"resource_id": "S"}, headers=_hdr()).json()
    assert body["parents"] == ["W"]
    (w,) = body["parent_details"]
    assert w["id"] == "W" and w["creator"] == "alice" and w["created_at"][:4].isdigit()
