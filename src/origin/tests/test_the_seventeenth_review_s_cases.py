"""Review 17, H1: every authority change made in a person's Origin session reaches Mantle.

Origin records a session entry with credential kind `origin_session`. Mantle's feed applies the
kinds `prism.trust.ledger.MANTLE_APPLIES` names (the person's own at Origin's page or session, and
the operator's), and nothing else: the rest are Mantle's own submissions, already in its store.
Both repos read that one list. These tests build the entries through Origin's real session routes,
take them as `/internal/authority/feed` serves them, signed by Origin's real key, and run them
through Mantle's real `apply_remote`. A store whose cursor had already moved past session entries
catches up on them once, each only while it is still the latest change to its row.
"""
# ruff: noqa: F811
from __future__ import annotations

import json

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, world)
from origin.tests.test_the_thirteenth_review_s_session_cases import (  # noqa: F401
    BASE, _as, _hdr, _seen, mail)

custody_client = _shares.custody_client


def _feed_rows():
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    with SessionLocal() as db:
        return [{"seq": r.seq, "kind": r.kind, "body": json.loads(r.body), "actor": r.actor,
                 "credential_kind": r.credential_kind, "credential_ref": r.credential_ref,
                 "bootstrap": bool(r.bootstrap), "compensates": r.compensates,
                 "claimed_from": r.claimed_from, "submitted_by": r.submitted_by,
                 "prev_hash": r.prev_hash, "entry_hash": r.entry_hash, "signature": r.signature,
                 "kid": r.kid}
                for r in db.query(AuthorityEntry).order_by(AuthorityEntry.seq)]


class _Feed:
    """Origin's feed as it answers: `FEED_PAGE` entries after `after`, and the head (review 18)."""

    def __init__(self, rows):
        self.rows = rows

    def ledger_feed(self, after):
        from origin.routers.authority_router import FEED_PAGE
        rest = [e for e in self.rows if e["seq"] > after]
        return {"entries": rest[:FEED_PAGE],
                "head": self.rows[-1]["seq"] if self.rows else 0}


@pytest.fixture
def mantle_store(tmp_path, monkeypatch):
    pytest.importorskip("mantle", reason="a cross-repository case: it reads Mantle's own code, which the sovereign CI's workspace has and a lone checkout of Origin does not")
    from jose import jwk
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    from origin.key_manager import get_key_id, get_public_key_pem

    key = jwk.construct(get_public_key_pem(), "RS256")
    monkeypatch.setattr(mantle_ledger, "_origin_keys", lambda: {get_key_id(): key})
    return la.LatticeDatabase(str(tmp_path / "m.db"), origin="m")


def _mantle_holds_bob(store, alice_id, bob_id):
    from mantle.attenuation import ACTIONS
    from mantle.db import lattice_api as la
    from mantle.db import reach_journal
    from mantle.entities.grant import Grant
    with reach_journal.suspended():
        la.create_grant(store, Grant(
            id="g-bw", resource_id="W", grantee_type="user", grantee_id=bob_id,
            granted_by=alice_id, **{f"can_{a}": a in ("read", "share") for a in ACTIONS}))


def _session_changes(c, world, mail):
    """In her Origin session Alice revokes Bob, denies Carol Read, grants Carol Update, invites
    Dave (who claims it) and hangs a root of hers in W by a secondary edge."""
    alice_id, alice = world["alice"]
    bob_id, _bob = world["bob"]
    carol_id, _carol = world["carol"]
    dave_id, _dave = af.person("dave", email="dave@team.test")
    af.ok(af.session_submit(c, alice_id, af.grant("g-bw", bob_id, "W", ["read", "share"],
                                                  state="revoked")))
    af.ok(af.session_submit(c, alice_id, af.grant("g-deny-cw", carol_id, "W", ["read"],
                                                  effect="deny")))
    af.ok(af.session_submit(c, alice_id, af.grant("g-cu", carol_id, "W", ["update"])))
    _as(c, alice_id)
    af.ok(c.post(f"{BASE}/invites", json={"resource_id": "W", "actions": ["read"],
                                          "email": "dave@team.test", "preview": _seen(c, "W")},
                 headers=_hdr()))
    token = mail[-1][1].rsplit("/invite/", 1)[1]
    _as(c, dave_id)
    claim = af.ok(c.post(f"{BASE}/claim", json={"token": token}, headers=_hdr()))
    af.ok(af.submit(c, alice, af.root("Y"), batch="y", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-ay", alice_id, "Y", ALL), batch="y",
                    via_session=False))
    af.ok(af.session_submit(c, alice_id, af.edge("W", "Y", origin=False)))
    return dave_id, claim


def _held(store, gid):
    from mantle.db import lattice_api as la
    return la.get_grant_by_id(store, gid)


def test_every_session_change_lands_in_mantle_s_store(custody_client, world, mantle_store, mail):
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    c = custody_client
    _mantle_holds_bob(mantle_store, world["alice"][0], world["bob"][0])
    dave_id, _claim = _session_changes(c, world, mail)
    rows = _feed_rows()
    assert "origin_session" in {r["credential_kind"] for r in rows}
    assert mantle_ledger.apply_remote(mantle_store, _Feed(rows)) >= 6
    assert _held(mantle_store, "g-bw").state == "revoked"                       # a revoke
    assert _held(mantle_store, "g-deny-cw").effect == "deny"                    # a deny
    assert _held(mantle_store, "g-cu").can_update                              # a grant
    claimed = [g for g in la.get_grants_for_collection(mantle_store, "W")
               if g.grantee_id == dave_id]
    assert claimed and claimed[0].can_read                                       # a claim
    assert la.get_edge(mantle_store, "W", "Y")                                  # an edge


def test_a_store_that_skipped_them_catches_up_once(custody_client, world, mantle_store, mail,
                                                   monkeypatch):
    """A cursor an older Mantle moved past session entries is replayed once from the start of the
    ledger: each skipped session entry is applied while it is still the latest change to its row,
    and never applied over a later change."""
    from mantle.services import authority_ledger as mantle_ledger
    c = custody_client
    _mantle_holds_bob(mantle_store, world["alice"][0], world["bob"][0])
    _session_changes(c, world, mail)
    # Carol's update grant is changed again later (by the session, then applied normally).
    rows = _feed_rows()
    # What an older Mantle did: walked the whole feed applying none of the session's entries.
    monkeypatch.setattr(mantle_ledger, "MANTLE_APPLIES", frozenset({"origin_page", "operator"}))
    monkeypatch.setattr(mantle_ledger, "catch_up_skipped", lambda *a, **k: 0)   # it had none
    mantle_ledger.apply_remote(mantle_store, _Feed(rows))
    assert _held(mantle_store, "g-bw").state == "active"                       # skipped
    monkeypatch.undo()
    from jose import jwk
    from origin.key_manager import get_key_id, get_public_key_pem
    monkeypatch.setattr(mantle_ledger, "_origin_keys",
                        lambda: {get_key_id(): jwk.construct(get_public_key_pem(), "RS256")})
    # A later session change to g-cu: the catch-up must not put the earlier one back over it.
    af.ok(af.session_submit(c, world["alice"][0], af.grant("g-cu", world["carol"][0], "W",
                                                           ["update"], state="revoked")))
    rows = _feed_rows()
    mantle_ledger.apply_remote(mantle_store, _Feed(rows))
    assert _held(mantle_store, "g-bw").state == "revoked"                       # caught up
    assert _held(mantle_store, "g-deny-cw").effect == "deny"
    assert _held(mantle_store, "g-cu").state == "revoked"                       # the latest
    # Once: a second pass replays nothing.
    assert mantle_ledger.catch_up_skipped(mantle_store, _Feed(rows)) == 0


def test_both_repos_read_one_list_of_credential_kinds():
    """The kinds Origin writes, and which of them Mantle applies, are written once, in prism, and
    each repo's own names are that list's (review 17)."""
    pytest.importorskip("mantle", reason="a cross-repository case: it reads Mantle's own code, which the sovereign CI's workspace has and a lone checkout of Origin does not")
    from mantle.services import authority_ledger as mantle_ledger
    from origin.services import authority_ledger as origin_ledger
    from prism.trust import ledger as shared

    assert origin_ledger.ORIGIN_SESSION in shared.CREDENTIAL_KINDS
    assert origin_ledger.ORIGIN_PAGE in shared.CREDENTIAL_KINDS
    assert set(origin_ledger.MANTLE_HELD) <= shared.CREDENTIAL_KINDS
    assert mantle_ledger.MANTLE_APPLIES == shared.MANTLE_APPLIES
    assert {"origin_session", "origin_page", "operator"} == set(shared.MANTLE_APPLIES)
    # Every other label one repo matches against the other's literal.
    assert mantle_ledger.GENESIS == origin_ledger.GENESIS == shared.GENESIS
    assert mantle_ledger.LEDGER_VERSION == shared.LEDGER_VERSION
    assert set(origin_ledger.KINDS) == set(shared.ENTRY_KINDS)
    from mantle.search.mantle import oracle
    from origin.services.authority_reach import COLLECTION_KEY_PREFIX
    assert COLLECTION_KEY_PREFIX == shared.COLLECTION_KEY_PREFIX
    assert oracle.collection_key_id("C") == shared.COLLECTION_KEY_PREFIX + "C"


def test_the_invite_target_digest_is_one_function():
    """Origin, Mantle and Facet digest an invite's target the same way; Origin and Mantle read
    prism's, and Facet's is pinned to the same vector (`review17SharedNames.test.ts`)."""
    pytest.importorskip("mantle", reason="a cross-repository case: it reads Mantle's own code, which the sovereign CI's workspace has and a lone checkout of Origin does not")
    from mantle.db import reach_journal
    from origin.services import authority_ledger as origin_ledger
    from prism.trust import ledger as shared
    for kind, value in (("email", " Bob@Team.Test "), ("domain", "Team.test"), ("user_id", "u-1")):
        want = shared.target_digest(kind, value)
        assert origin_ledger.target_digest(kind, value) == want
        assert reach_journal.target_digest(kind, value) == want
    assert shared.target_digest("email", "bob@team.test") == (
        "119b27ebfd594700fbe4cf024fb3346e93a9153dbc55ef20ea0716a8da345da7")


def test_both_sides_digest_reach_in_one_canonical_form():
    pytest.importorskip("mantle", reason="a cross-repository case: it reads Mantle's own code, which the sovereign CI's workspace has and a lone checkout of Origin does not")
    from mantle.services import authority_ledger as mantle_ledger
    from origin.services import authority_digest
    grants = [("g-1", "bob", "user", "W", ["share", "read"], "allow", "active")]
    edges = [("W", "C", True, None), ("W", "Y", False, '["read"]')]
    origin_text = authority_digest.canonical(grants, edges)
    mantle_text = mantle_ledger.canonical_reach(
        [{"grant_id": g[0], "grantee_id": g[1], "grantee_type": g[2], "resource_id": g[3],
          "actions": g[4], "effect": g[5], "state": g[6]} for g in grants],
        [(e[0], e[1], e[2], json.loads(e[3]) if e[3] else None) for e in edges])
    assert origin_text == mantle_text


# -- L1: the preview describes the resource itself too ---------------------------------------------

def test_the_preview_describes_the_resource_itself(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.edge("W", "M1"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.edge("W", "M2"), batch="mk", via_session=False))
    _as(c, alice_id)
    body = c.post(f"{BASE}/preview", json={"resource_id": "W"}, headers=_hdr()).json()
    me = body["resource_detail"]
    assert me["id"] == "W" and me["creator"] == "alice" and me["created_at"][:4].isdigit()
    assert me["members"] == 2 and me["grantees"] == 2          # g-aw (Alice) and g-bw (Bob)
