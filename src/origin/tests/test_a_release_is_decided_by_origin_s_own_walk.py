"""Origin releases a key share only when the credential's subject reaches the key, by Origin's own
walk over its replica of the authority ledger.

Every collection's content is keyed under its own collection key (`ck:<collection>`, John,
2026-10-31). Its share is released to a subject whose walk reaches that collection for `read`
(grants walked up the origin chain, deny nearer first, each edge's `propagate` mask attenuating),
or reaches an artifact created in it. A principal's master key is released to that principal alone:
reach to a collection under it opens that collection's key, never the master, and never a sibling's.

The replica in each test is built the way production builds it: co-signed entries submitted over
`POST /internal/authority/entries` on the acting person's own credential.
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


@pytest.fixture
def world(custody_client):
    """Alice's workspace `W` holds collections `C` and `C3` (her creator grants on each); `C`
    holds `C2` through an edge that does not conduct `read`. Bob reads `C`. Dave owns `D`. Carol
    holds nothing."""
    c = custody_client
    people = {n: af.person(n) for n in ("alice", "bob", "carol", "dave")}
    a = people["alice"][1]
    every = ["read", "share", "admin", "create", "add"]
    af.ok(af.submit(c, a, af.root("W")))
    af.ok(af.submit(c, a, af.grant("g-aw", people["alice"][0], "W", every)))
    for coll in ("C", "C3"):
        af.ok(af.submit(c, a, af.edge("W", coll)))
        af.ok(af.submit(c, a, af.grant(f"g-a{coll}", people["alice"][0], coll, every)))
    af.ok(af.submit(c, a, af.edge("C", "C2", propagate=["update"])))
    af.ok(af.submit(c, a, af.grant("g-bc", people["bob"][0], "C")))
    d = people["dave"][1]
    af.ok(af.submit(c, d, af.root("D")))
    af.ok(af.submit(c, d, af.grant("g-dd", people["dave"][0], "D", ["read", "admin"])))
    for key in ("W", "D", "ck:W", "ck:C", "ck:C2", "ck:C3", "ck:D"):
        af.store_share(c, key)
    return people


def _tok(world, who):
    return world[who][1]


def test_a_grantee_reaching_the_collection_opens_its_collection_key(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyRelease

    r = af.release(custody_client, "ck:C", _tok(world, "bob"))
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        rec = db.query(KeyCustodyRelease).one()
    assert (rec.principal_id, rec.subject) == ("ck:C", world["bob"][0])


def test_a_grantee_on_one_collection_cannot_open_a_sibling_or_the_master(custody_client, world):
    """Bob reads `C`. `C3` is its sibling under the same workspace; `W` is the workspace's
    master key. Neither opens for him."""
    bob = _tok(world, "bob")
    assert af.release(custody_client, "ck:C3", bob).status_code == 403
    assert af.release(custody_client, "ck:W", bob).status_code == 403
    r = af.release(custody_client, "W", bob, collection="C")
    assert r.status_code == 403 and "own principal" in r.json()["detail"]


def test_the_master_key_opens_for_its_own_principal_alone(custody_client, world):
    """Not even for the person holding every right on the workspace."""
    assert af.release(custody_client, "W", _tok(world, "alice")).status_code == 403
    own = _shares.own_credential("W")
    assert af.release(custody_client, "W", own).status_code == 200


def test_a_person_who_reaches_nothing_is_refused(custody_client, world):
    r = af.release(custody_client, "ck:C", _tok(world, "carol"))
    assert r.status_code == 403 and "does not reach" in r.json()["detail"]


def test_reach_elsewhere_opens_nothing_here(custody_client, world):
    assert af.release(custody_client, "ck:C", _tok(world, "dave")).status_code == 403
    assert af.release(custody_client, "ck:D", _tok(world, "dave")).status_code == 200


def test_a_grant_does_not_conduct_through_an_edge_that_attenuates_read(custody_client, world):
    assert af.release(custody_client, "ck:C2", _tok(world, "bob")).status_code == 403


def test_a_deny_nearer_the_collection_refuses_what_an_allow_above_it_gives(custody_client, world):
    alice = _tok(world, "alice")
    af.ok(af.submit(custody_client, alice, af.grant("g-bw", world["bob"][0], "W")))
    af.ok(af.submit(custody_client, alice, af.grant("g-bc", world["bob"][0], "C", effect="deny")))
    assert af.release(custody_client, "ck:C", _tok(world, "bob")).status_code == 403
    assert af.release(custody_client, "ck:C3", _tok(world, "bob")).status_code == 200


def test_a_revoked_grant_stops_the_next_release(custody_client, world):
    assert af.release(custody_client, "ck:C", _tok(world, "bob")).status_code == 200
    af.ok(af.submit(custody_client, _tok(world, "alice"),
                    af.grant("g-bc", world["bob"][0], "C", state="revoked")))
    assert af.release(custody_client, "ck:C", _tok(world, "bob")).status_code == 403


def test_an_expired_grant_reaches_nothing(custody_client, world):
    af.ok(af.submit(custody_client, _tok(world, "alice"),
                    af.grant("g-bc", world["bob"][0], "C", expires_at="2000-01-01T00:00:00Z")))
    assert af.release(custody_client, "ck:C", _tok(world, "bob")).status_code == 403


def test_a_grant_on_the_artifact_alone_opens_the_key_it_is_written_under(custody_client, world):
    alice = _tok(world, "alice")
    af.ok(af.submit(custody_client, alice, af.edge("C", "card-1")))
    # Mantle's write path gives the creator an owner grant on what they create; Origin records
    # it because she reaches all of it through `C`.
    af.ok(af.submit(custody_client, alice, af.grant("g-own", world["alice"][0], "card-1",
                                                    ["read", "share", "admin"])))
    af.ok(af.submit(custody_client, alice, af.grant("g-card", world["carol"][0], "card-1")))
    carol = _tok(world, "carol")
    assert af.release(custody_client, "ck:C", carol, artifact="card-1").status_code == 200
    assert af.release(custody_client, "ck:C", carol).status_code == 403
    assert af.release(custody_client, "ck:C3", carol, artifact="card-1").status_code == 403


def test_a_principal_opens_its_own_key(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityRoot

    pid, tok = world["carol"]
    af.ok(af.submit(custody_client, tok, af.root(pid)))
    af.store_share(custody_client, pid)
    assert af.release(custody_client, pid, tok).status_code == 200
    with SessionLocal() as db:
        assert db.get(AuthorityRoot, pid).registered_by == pid


def test_a_key_origin_s_replica_does_not_know_is_refused(custody_client, world):
    """No share can be stored for a key Origin's replica does not know, so none is released."""
    alice = _tok(world, "alice")
    for key in ("unknown-key", "ck:nowhere"):
        r = af.store_share(custody_client, key, alice)
        assert r.status_code == 403 and "does not know" in r.json()["detail"]
        assert af.release(custody_client, key, alice).status_code == 404


def test_the_scope_is_bound_in_the_service_token(custody_client, world):
    """A token signed for one scope does not open the key for another."""
    tok = _shares._token("GET", "ck:C", artifact_id="card-1")
    r = custody_client.get("/internal/key-shares/ck:C", params={"artifact_id": "card-2"},
                           headers={"Authorization": f"Bearer {tok}",
                                    "X-Acting-Credential": _tok(world, "bob")})
    assert r.status_code == 401
    tok = _shares._token("GET", "ck:C")
    r = custody_client.get("/internal/key-shares/ck:C", params={"artifact_id": "card-1"},
                           headers={"Authorization": f"Bearer {tok}",
                                    "X-Acting-Credential": _tok(world, "bob")})
    assert r.status_code == 401


def test_an_absent_share_is_reported_for_a_key_origin_knows_nothing_of(custody_client, world):
    """Mantle asks before it mints a first key, when the replica cannot know it yet."""
    r = af.release(custody_client, "never-stored", _tok(world, "carol"))
    assert r.status_code == 404 and r.json()["absent"] is True


def test_for_a_known_key_reach_is_asked_before_absence_is_told(custody_client, world):
    """Whether a known key has a share here is told only to someone who reaches it."""
    af.ok(af.submit(custody_client, _tok(world, "alice"), af.edge("W", "K2")))
    assert af.release(custody_client, "ck:K2", _tok(world, "carol")).status_code == 403
    assert af.release(custody_client, "ck:K2", _tok(world, "alice")).status_code == 404


def test_replacing_a_share_needs_a_credential_that_reaches_the_key(custody_client, world):
    """Superseding Origin's share is as strong as releasing it; the creator of a collection may
    re-store its first key."""
    from origin.tests.test_a_key_share_is_released_only_to_mantle import KCV_B, OTHER_Y

    body = {"y": OTHER_Y, "kcv": KCV_B, "supersedes": "a" * 32}
    assert af.store_share(custody_client, "ck:C", None, **body).status_code == 401
    assert af.store_share(custody_client, "ck:C", _tok(world, "carol"), **body).status_code == 403
    r = af.store_share(custody_client, "ck:C", _tok(world, "alice"), **body)
    assert r.status_code == 200, r.text


def test_a_background_delegation_is_minted_for_a_collection_key_it_knows(custody_client, world):
    own = _shares.own_credential("ck:C")
    assert af.release(custody_client, "ck:C", own).status_code == 200
    assert af.release(custody_client, "ck:C3", own).status_code == 403
