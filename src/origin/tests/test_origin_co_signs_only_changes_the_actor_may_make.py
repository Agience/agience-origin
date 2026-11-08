"""Origin co-signs a change to reach only after checking, against its own replica, that the acting
person may make it; then it appends the entry, hash-chained, and applies it.

Each rule is Mantle's (`grant_service.can_share` / `can_admin` / `clamp_grant_to_issuer` for a
grant, `check_access` create/add for an edge, evict/delete for a removal), checked here by Origin
over the replica only co-signed entries built, plus what Origin needs and Mantle does not: ids come
into being only by their own creation, an invite claim carries proof Origin verifies itself, a
background delegation never widens, and a bootstrap needs a credential good for nothing else. A
refusal appends nothing and changes nothing.
"""
from __future__ import annotations

import json

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]


@pytest.fixture
def world(custody_client):
    """Alice brought workspace `W` into being and holds every action on it; Bob holds `read` and
    `share` on it; Carol holds nothing."""
    c = custody_client
    people = {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob", "carol")}
    a = people["alice"][1]
    af.ok(af.submit(c, a, af.root("W")))
    af.ok(af.submit(c, a, af.grant("g-aw", people["alice"][0], "W", ALL)))
    af.ok(af.submit(c, a, af.grant("g-bw", people["bob"][0], "W", ["read", "share"])))
    return people


def _count():
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry

    with SessionLocal() as db:
        return db.query(AuthorityEntry).count()


def _grant_row(gid):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant

    with SessionLocal() as db:
        return db.get(AuthorityGrant, gid)


def _edge_row(src, dst):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEdge

    with SessionLocal() as db:
        return db.get(AuthorityEdge, (src, dst))


# -- the positive control, and what an entry is --------------------------------------------------

def test_an_admin_s_grant_is_co_signed_chained_and_applied(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.key_manager import get_key_id, get_public_key_pem
    from origin.models.authority_ledger import AuthorityEntry
    from origin.services import authority_ledger

    before = _count()
    receipt = af.ok(af.submit(custody_client, world["alice"][1],
                              af.grant("g-cw", world["carol"][0], "W")))
    assert receipt["outcome"] == "appended" and receipt["seq"] == before + 1
    assert receipt["kid"] == get_key_id()
    assert authority_ledger.verify_cosignature(receipt["entry_hash"], receipt["signature"],
                                               get_public_key_pem())
    with SessionLocal() as db:
        row = db.get(AuthorityEntry, receipt["seq"])
        prev = db.get(AuthorityEntry, receipt["seq"] - 1)
        assert row.prev_hash == prev.entry_hash and row.actor == world["alice"][0]
        assert world["alice"][1] not in row.body and "name" not in json.loads(row.body)
        assert len(row.submitted_jti) >= 8 and len(row.body_sha256) == 64
        assert authority_ledger.verify_chain(db)[0]
    assert _grant_row("g-cw").grantee_id == world["carol"][0]


def test_resubmitting_the_same_state_appends_nothing(custody_client, world):
    first = af.ok(af.submit(custody_client, world["alice"][1],
                            af.grant("g-cw", world["carol"][0], "W")))
    n = _count()
    again = af.ok(af.submit(custody_client, world["alice"][1],
                            af.grant("g-cw", world["carol"][0], "W")))
    assert again["outcome"] == "unchanged" and again["seq"] == first["seq"] and _count() == n


def test_an_entry_carries_structure_only(custody_client, world):
    entry = {**af.grant("g-x", world["carol"][0], "W"), "name": "Carol's access"}
    r = af.submit(custody_client, world["alice"][1], entry, digest="0" * 64)
    assert r.status_code == 400 and "name" in r.json()["detail"]


def test_the_service_token_names_the_body_it_was_signed_for(custody_client, world):
    from origin.services.authority_ledger import body_digest

    other = body_digest(af.grant("g-other", world["carol"][0], "W"))
    r = af.submit(custody_client, world["alice"][1], af.grant("g-cw", world["carol"][0], "W"),
                  digest=other)
    assert r.status_code == 401


def test_a_submission_needs_an_acting_credential(custody_client, world):
    r = af.submit(custody_client, "", af.grant("g-cw", world["carol"][0], "W"))
    assert r.status_code == 401


# -- grants ----------------------------------------------------------------------------------------

def test_a_person_without_share_or_admin_cannot_grant(custody_client, world):
    n = _count()
    r = af.submit(custody_client, world["carol"][1], af.grant("g-c", world["carol"][0], "W"))
    assert r.status_code == 403 and _count() == n and _grant_row("g-c") is None


def test_share_invites_no_more_than_the_sharer_holds(custody_client, world):
    """Bob holds read and share on `W`: he may invite for read, and not for admin."""
    bob = world["bob"][1]
    af.ok(af.submit(custody_client, bob, af.invite("inv-b", "t1", "W")))
    r = af.submit(custody_client, bob, af.invite("inv-b2", "t2", "W", ["read", "admin"]))
    assert r.status_code == 403 and "admin" in r.json()["detail"]


def test_share_alone_makes_no_direct_grant(custody_client, world):
    """`grants_router`: a direct user grant, or a change to one, needs admin."""
    bob, carol = world["bob"][1], world["carol"][0]
    assert af.submit(custody_client, bob, af.grant("g-bc", carol, "W")).status_code == 403
    af.ok(af.submit(custody_client, world["alice"][1], af.grant("g-ac", carol, "W")))
    assert af.submit(custody_client, bob,
                     af.grant("g-ac", carol, "W", state="revoked")).status_code == 403


def test_a_grant_s_resource_and_grantee_do_not_change(custody_client, world):
    alice = world["alice"][1]
    r = af.submit(custody_client, alice, af.grant("g-bw", world["carol"][0], "W", ["read"]))
    assert r.status_code == 409


def test_the_grantee_may_give_up_their_own_grant(custody_client, world):
    r = af.submit(custody_client, world["bob"][1],
                  af.grant("g-bw", world["bob"][0], "W", ["read", "share"], state="revoked"))
    assert r.status_code == 200 and _grant_row("g-bw").state == "revoked"


def test_someone_else_cannot_revoke_a_grant_they_do_not_manage(custody_client, world):
    r = af.submit(custody_client, world["carol"][1],
                  af.grant("g-bw", world["bob"][0], "W", ["read", "share"], state="revoked"))
    assert r.status_code == 403 and _grant_row("g-bw").state == "active"


def test_the_creator_sets_up_a_new_resource_and_no_one_else_may(custody_client, world):
    carol, bob = world["carol"], world["bob"]
    af.ok(af.submit(custody_client, carol[1], af.root("K")))
    assert af.submit(custody_client, bob[1],
                     af.grant("g-bk", bob[0], "K", ["admin"])).status_code == 403
    af.ok(af.submit(custody_client, carol[1], af.grant("g-ck", carol[0], "K", ["admin", "read"])))
    af.ok(af.submit(custody_client, carol[1], af.grant("g-ck2", bob[0], "K", ["read"])))


# -- ids Origin has not seen -----------------------------------------------------------------------

def test_a_grant_on_an_id_origin_has_not_seen_is_refused(custody_client, world):
    """An unseen id comes into being only by its own root or creation edge, so the first grant on
    it cannot be what claims it."""
    r = af.submit(custody_client, world["carol"][1], af.grant("g-x", world["carol"][0], "fresh"))
    assert r.status_code == 403 and "unknown" in r.json()["detail"]


def test_an_edge_naming_an_unseen_collection_or_member_is_refused(custody_client, world):
    alice = world["alice"][1]
    assert af.submit(custody_client, alice, af.edge("nowhere", "m-1")).status_code == 403
    assert af.submit(custody_client, alice,
                     af.edge("W", "never-made", origin=False)).status_code == 403


def test_a_person_s_id_is_brought_into_being_only_by_that_person(custody_client, world):
    alice, carol = world["alice"], world["carol"]
    r = af.submit(custody_client, alice[1], af.root(carol[0]))
    assert r.status_code == 403 and "only by that person" in r.json()["detail"]
    af.ok(af.submit(custody_client, carol[1], af.root(carol[0])))


def test_a_creation_edge_cannot_claim_a_person_s_id(custody_client, world):
    r = af.submit(custody_client, world["alice"][1], af.edge("W", world["carol"][0]))
    assert r.status_code == 403 and "person" in r.json()["detail"]


def test_a_creation_edge_cannot_claim_an_id_someone_else_made(custody_client, world):
    """Carol's own key principal placed under Alice's `W` would make Alice's grantees reach it."""
    carol = world["carol"]
    af.ok(af.submit(custody_client, carol[1], af.root("K")))
    r = af.submit(custody_client, world["alice"][1], af.edge("W", "K"))
    assert r.status_code == 403


# -- invites ---------------------------------------------------------------------------------------

def test_a_claim_needs_the_invite_s_token(custody_client, world):
    alice, carol = world["alice"][1], world["carol"]
    af.ok(af.submit(custody_client, alice, af.invite("inv-1", "the-token", "W")))
    claim = af.grant("g-claim", carol[0], "W")
    assert af.submit(custody_client, carol[1], claim).status_code == 403          # no proof
    r = af.submit(custody_client, carol[1], claim, proof={"invite_id": "inv-1", "token": "guess"})
    assert r.status_code == 403 and "token" in r.json()["detail"]
    af.ok(af.submit(custody_client, carol[1], claim,
                    proof={"invite_id": "inv-1", "token": "the-token"}))
    assert _grant_row("g-claim").claimed_from == "inv-1"


def test_an_invite_claim_takes_no_more_than_the_invite(custody_client, world):
    alice, carol = world["alice"][1], world["carol"]
    af.ok(af.submit(custody_client, alice, af.invite("inv-1", "tok", "W")))
    proof = {"invite_id": "inv-1", "token": "tok"}
    r = af.submit(custody_client, carol[1], af.grant("g-claim", carol[0], "W", ["read", "update"]),
                  proof=proof)
    assert r.status_code == 403


@pytest.mark.parametrize("target,ok", [
    (("email", "carol@team.test"), True), (("email", "someone@team.test"), False),
    (("domain", "team.test"), True), (("domain", "other.test"), False),
])
def test_an_invite_s_target_is_checked_against_the_claimant_s_verified_identity(
        custody_client, world, target, ok):
    alice, carol = world["alice"][1], world["carol"]
    af.ok(af.submit(custody_client, alice, af.invite("inv-t", "tok", "W", target=target)))
    r = af.submit(custody_client, carol[1], af.grant("g-claim", carol[0], "W"),
                  proof={"invite_id": "inv-t", "token": "tok"})
    assert (r.status_code == 200) is ok, r.text


def test_an_email_invite_needs_a_verified_address(custody_client, world):
    unverified = af.person("dan", email="dan@team.test", verified=False)
    af.ok(af.submit(custody_client, world["alice"][1],
                    af.invite("inv-d", "tok", "W", target=("email", "dan@team.test"))))
    r = af.submit(custody_client, unverified[1], af.grant("g-claim", unverified[0], "W"),
                  proof={"invite_id": "inv-d", "token": "tok"})
    assert r.status_code == 403 and "verified" in r.json()["detail"]


def test_a_user_id_invite_opens_for_that_person_alone(custody_client, world):
    alice, bob, carol = world["alice"][1], world["bob"], world["carol"]
    af.ok(af.submit(custody_client, alice,
                    af.invite("inv-u", "tok", "W", target=("user_id", carol[0]))))
    proof = {"invite_id": "inv-u", "token": "tok"}
    assert af.submit(custody_client, bob[1], af.grant("g-b", bob[0], "W"),
                     proof=proof).status_code == 403
    af.ok(af.submit(custody_client, carol[1], af.grant("g-c", carol[0], "W"), proof=proof))


def test_the_claim_limit_is_counted_in_origin_s_replica(custody_client, world):
    alice, bob, carol = world["alice"][1], world["bob"], world["carol"]
    af.ok(af.submit(custody_client, alice, af.invite("inv-1", "tok", "W", max_claims=1)))
    proof = {"invite_id": "inv-1", "token": "tok"}
    af.ok(af.submit(custody_client, carol[1], af.grant("g-c", carol[0], "W"), proof=proof))
    r = af.submit(custody_client, bob[1], af.grant("g-b2", bob[0], "W"), proof=proof)
    assert r.status_code == 403 and "claim limit" in r.json()["detail"]


def test_an_expired_invite_is_claimed_by_no_one(custody_client, world):
    alice, carol = world["alice"][1], world["carol"]
    af.ok(af.submit(custody_client, alice,
                    af.invite("inv-old", "tok", "W", expires_at="2000-01-01T00:00:00Z")))
    r = af.submit(custody_client, carol[1],
                  af.grant("g-claim", carol[0], "W", expires_at="2000-01-01T00:00:00Z"),
                  proof={"invite_id": "inv-old", "token": "tok"})
    assert r.status_code == 403


def test_a_claim_keeps_the_invite_s_expiry(custody_client, world):
    alice, carol = world["alice"][1], world["carol"]
    af.ok(af.submit(custody_client, alice,
                    af.invite("inv-t", "tok", "W", expires_at="2999-01-01T00:00:00Z")))
    proof = {"invite_id": "inv-t", "token": "tok"}
    assert af.submit(custody_client, carol[1], af.grant("g-claim", carol[0], "W"),
                     proof=proof).status_code == 403
    af.ok(af.submit(custody_client, carol[1],
                    af.grant("g-claim", carol[0], "W", expires_at="2999-01-01T00:00:00Z"),
                    proof=proof))


def test_only_the_issuer_or_an_admin_closes_an_invite(custody_client, world):
    """A claimant does not close a live invite; once Origin's count shows it spent, the
    claimant's close records what Origin already enforces."""
    alice, bob, carol = world["alice"][1], world["bob"], world["carol"]
    af.ok(af.submit(custody_client, bob[1], af.invite("inv-1", "tok", "W", max_claims=2)))
    closed = af.invite("inv-1", "tok", "W", max_claims=2, state="revoked")
    proof = {"invite_id": "inv-1", "token": "tok"}
    af.ok(af.submit(custody_client, carol[1], af.grant("g-c", carol[0], "W"), proof=proof))
    assert af.submit(custody_client, carol[1], closed).status_code == 403
    af.ok(af.submit(custody_client, bob[1], closed))                       # the issuer
    af.ok(af.submit(custody_client, alice, af.invite("inv-2", "t2", "W")))
    af.ok(af.submit(custody_client, alice, af.invite("inv-2", "t2", "W", state="revoked")))


def test_a_spent_invite_may_be_closed_by_its_claimant(custody_client, world):
    alice, carol = world["alice"][1], world["carol"]
    af.ok(af.submit(custody_client, alice, af.invite("inv-1", "tok", "W", max_claims=1)))
    af.ok(af.submit(custody_client, carol[1], af.grant("g-c", carol[0], "W"),
                    proof={"invite_id": "inv-1", "token": "tok"}))
    af.ok(af.submit(custody_client, carol[1],
                    af.invite("inv-1", "tok", "W", max_claims=1, state="revoked")))


def test_an_invite_s_target_and_limit_do_not_change(custody_client, world):
    alice = world["alice"][1]
    af.ok(af.submit(custody_client, alice,
                    af.invite("inv-1", "tok", "W", target=("domain", "team.test"), max_claims=1)))
    assert af.submit(custody_client, alice, af.invite("inv-1", "tok", "W", max_claims=1)
                     ).status_code == 409
    assert af.submit(custody_client, alice, af.invite(
        "inv-1", "tok", "W", target=("domain", "team.test"), max_claims=5)).status_code == 409


# -- edges -----------------------------------------------------------------------------------------

def test_an_edge_needs_create_or_add_reaching_the_collection(custody_client, world):
    assert af.submit(custody_client, world["carol"][1], af.edge("W", "m-1")).status_code == 403
    assert af.submit(custody_client, world["bob"][1], af.edge("W", "m-1")).status_code == 403
    af.ok(af.submit(custody_client, world["alice"][1], af.edge("W", "m-1")))


def test_a_member_has_one_creation_edge(custody_client, world):
    alice = world["alice"][1]
    af.ok(af.submit(custody_client, alice, af.edge("W", "m-1")))
    af.ok(af.submit(custody_client, alice, af.edge("W", "m-2")))
    assert af.submit(custody_client, alice, af.edge("m-2", "m-1")).status_code == 409
    af.ok(af.submit(custody_client, alice, af.edge("m-2", "m-1", origin=False)))
    assert af.submit(custody_client, alice, af.edge("m-2", "m-1")).status_code == 409


def test_changing_what_an_edge_conducts_needs_admin(custody_client, world):
    """Architecture §51: Add is intake and Evict removes the edge; neither rewrites a member's
    mask. Widening or narrowing what an existing edge conducts changes who reaches everything
    below it, so either needs Admin on the collection. Restating it is unchanged."""
    alice, carol = world["alice"], world["carol"]
    af.ok(af.submit(custody_client, alice[1], af.edge("W", "m-1", propagate=["read"])))
    af.ok(af.submit(custody_client, alice[1], af.grant("g-cw", carol[0], "W",
                                                       ["create", "read", "add"])))
    for mask in (None, []):
        r = af.submit(custody_client, carol[1], af.edge("W", "m-1", propagate=mask))
        assert r.status_code == 403 and "admin" in r.json()["detail"]
    af.ok(af.submit(custody_client, alice[1], af.edge("W", "m-1", propagate=[])))
    af.ok(af.submit(custody_client, alice[1], af.edge("W", "m-1", propagate=None)))
    full = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]
    assert af.ok(af.submit(custody_client, carol[1], af.edge("W", "m-1", propagate=full))
                 )["outcome"] == "unchanged"                     # the same mask, spelled out


def test_removing_an_edge_needs_evict_or_delete(custody_client, world):
    alice, bob = world["alice"][1], world["bob"][1]
    af.ok(af.submit(custody_client, alice, af.edge("W", "m-1")))
    assert af.submit(custody_client, bob, af.unedge("W", "m-1")).status_code == 403
    af.ok(af.submit(custody_client, alice, af.unedge("W", "m-1")))
    assert af.ok(af.submit(custody_client, alice, af.unedge("W", "m-1")))["outcome"] == "unchanged"


# -- roots -----------------------------------------------------------------------------------------

def test_a_root_must_be_the_one_origin_walks_to(custody_client, world):
    alice = world["alice"][1]
    af.ok(af.submit(custody_client, alice, af.edge("W", "m-1")))
    assert af.submit(custody_client, alice, af.root("m-1")).status_code == 409
    assert af.submit(custody_client, alice, af.root("W", "elsewhere")).status_code == 409


# -- background work -------------------------------------------------------------------------------

@pytest.fixture
def system(custody_client, monkeypatch):
    """The platform system principal, with a background delegation minted for it."""
    from origin import service_identity

    sys_id = "00000000-0000-0000-0000-00000000aaaa"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: sys_id)
    # Its job grant lists W: a background retry acts only within those collections (review 16).
    return sys_id, af.background(sys_id, collections=("W",))


def test_a_background_delegation_never_issues_or_widens(custody_client, world, system):
    sys_id, tok = system
    alice = world["alice"][1]
    af.ok(af.submit(custody_client, alice, af.grant("g-sw", sys_id, "W", ALL)))   # it holds admin
    r = af.submit(custody_client, tok, af.grant("g-new", world["carol"][0], "W"))
    assert r.status_code == 403 and "background" in r.json()["detail"]
    assert af.submit(custody_client, tok, af.edge("W", "m-9")).status_code == 403
    # Nor does it narrow (review 16): it retires no grant and removes no edge of its own.
    af.ok(af.submit(custody_client, alice, af.edge("W", "m-1")))
    assert af.submit(custody_client, tok, af.unedge("W", "m-1")).status_code == 403
    assert af.submit(custody_client, tok, af.grant(
        "g-bw", world["bob"][0], "W", ["read", "share"], state="deleted")).status_code == 403


def test_a_background_delegation_changes_reach_only_as_the_system_principal(
        custody_client, world, system):
    """Minted for a person's own key, it opens that key; it cannot act as the person."""

    alice_id = world["alice"][0]
    af.ok(af.submit(custody_client, world["alice"][1], af.root(alice_id)))
    tok = af.background(alice_id)
    r = af.submit(custody_client, tok, af.unedge("W", "x"))
    assert r.status_code == 403 and "system principal" in r.json()["detail"]


# -- compensation ----------------------------------------------------------------------------------

def test_a_write_that_did_not_commit_is_withdrawn_by_its_actor(custody_client, world):
    alice, carol = world["alice"][1], world["carol"][1]
    added = af.ok(af.submit(custody_client, alice, af.edge("W", "m-1")))
    assert af.submit(custody_client, carol, af.unedge("W", "m-1"),
                     compensates=added["seq"]).status_code == 403      # not carol's entry
    af.ok(af.submit(custody_client, alice, af.unedge("W", "m-1"), compensates=added["seq"]))
    assert _edge_row("W", "m-1") is None
    # A grant is made in the person's Origin session (review 12): Origin's own write, confirmed
    # when appended, so nothing withdraws it by compensation.
    put = af.ok(af.submit(custody_client, alice, af.grant("g-cw", world["carol"][0], "W")))
    r = af.submit(custody_client, alice, af.grant("g-cw", world["carol"][0], "W", state="retired"),
                  compensates=put["seq"])
    assert r.status_code == 403 and "confirmed" in r.text
    again = af.ok(af.submit(custody_client, alice, af.edge("W", "m-2")))
    # A change since (a narrowing of what the creation edge conducts; a creation edge is never
    # demoted, review 30).
    af.ok(af.submit(custody_client, alice, af.edge("W", "m-2", propagate=["read"])))
    r = af.submit(custody_client, alice, af.unedge("W", "m-2"), compensates=again["seq"])
    assert r.status_code in (403, 409)                                   # changed since


# -- the bootstrap ---------------------------------------------------------------------------------

def test_a_bootstrap_needs_the_operator_s_bootstrap_credential(custody_client, world, monkeypatch):
    """A bootstrap states what Mantle held before the ledger, for ids Origin has not seen. The
    world already has ordinary entries, so the operator re-opens it for a stated list."""
    op = af.operator(monkeypatch)
    entry = af.grant("g-boot", world["carol"][0], "Old", ["admin"])
    assert af.submit(custody_client, world["alice"][1], entry, bootstrap=True).status_code == 403
    r = af.submit(custody_client, op, entry, bootstrap=True)
    assert r.status_code == 403 and "bootstrap credential" in r.json()["detail"]
    boot = af.open_bootstrap(custody_client, op, ids=["g-boot", "Old"])
    receipt = af.ok(af.submit(custody_client, boot, entry, bootstrap=True))
    assert receipt["outcome"] == "appended" and _grant_row("g-boot").created_by == ""


def test_the_bootstrap_credential_is_no_ordinary_acting_credential(custody_client, world,
                                                                  monkeypatch):
    boot = af.open_bootstrap(custody_client, af.operator(monkeypatch))
    assert af.submit(custody_client, boot, af.grant("g-x", world["carol"][0], "W")
                     ).status_code == 403
    af.store_share(custody_client, "W")
    assert af.release(custody_client, "W", boot).status_code == 403


def test_a_withdrawn_bootstrap_credential_is_refused(custody_client, world, monkeypatch):
    op = af.operator(monkeypatch)
    boot = af.open_bootstrap(custody_client, op)
    assert oc.call(custody_client, "DELETE", "/oracle/authority-ledger/bootstrap"
                   ).json()["closed"] == 1
    r = af.submit(custody_client, boot, af.grant("g-b", world["carol"][0], "W"), bootstrap=True)
    assert r.status_code == 403


def test_a_bootstrapped_resource_opens_no_creator_s_base_case(custody_client, world, monkeypatch):
    op = af.operator(monkeypatch)
    boot = af.open_bootstrap(custody_client, op, ids=["B", "g-b"])
    af.ok(af.submit(custody_client, boot, af.root("B"), bootstrap=True))
    af.ok(af.submit(custody_client, boot, af.grant("g-b", world["bob"][0], "B"), bootstrap=True))
    assert af.submit(custody_client, op, af.grant("g-b2", af.OPERATOR, "B", ["admin"])
                     ).status_code == 403


# -- verification ----------------------------------------------------------------------------------

def _verify(c, op):
    return oc.call(c, "GET", "/oracle/authority-ledger/verify").json()


def test_the_operator_s_verify_finds_a_tampered_entry(custody_client, world, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry

    op = af.operator(monkeypatch)
    assert _verify(custody_client, op)["ok"]
    with SessionLocal() as db:
        row = db.get(AuthorityEntry, 3)
        body = json.loads(row.body)
        body["actions"] = ["admin", "read"]
        row.body = json.dumps(body, sort_keys=True, separators=(",", ":"))
        db.commit()
    v = _verify(custody_client, op)
    assert not v["ok"] and "entry 3" in v["detail"]


def test_verify_replays_the_chain_against_the_replica(custody_client, world, monkeypatch):
    """A replica row changed outside the ledger is found: the replay does not produce it."""
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant

    op = af.operator(monkeypatch)
    with SessionLocal() as db:
        db.get(AuthorityGrant, "g-bw").actions = "read,share,admin"
        db.commit()
    v = _verify(custody_client, op)
    assert not v["ok"] and "grants" in v["detail"]


def test_verify_survives_a_key_rotation_and_names_an_unknown_key(custody_client, world,
                                                               monkeypatch):
    """Every key that co-signed is kept by kid, so entries signed before a rotation verify."""
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry, AuthoritySigningKey
    from origin.services import authority_ledger

    op = af.operator(monkeypatch)
    monkeypatch.setattr(authority_ledger, "current_kid", lambda: "rotated-key")
    assert _verify(custody_client, op)["ok"]                 # old entries: their recorded key
    with SessionLocal() as db:
        db.query(AuthoritySigningKey).delete()
        db.commit()
        assert db.query(AuthorityEntry).count() > 0
    v = _verify(custody_client, op)
    assert not v["ok"] and "no recorded key" in v["detail"]


# -- operator-signed seeds -------------------------------------------------------------------------

def _seed(c, op, minutes=10, plan=()):
    """The operator's seed credential, minted with the digests of the entries its pass makes
    (review 25)."""
    from origin.services.authority_ledger import body_digest
    r = oc.call(c, "POST", "/oracle/seed-credential",
                json={"minutes": minutes, "plan": [body_digest(e) for e in plan]})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_seed_that_grants_runs_on_the_operator_s_seed_credential(custody_client, world, system,
                                                                   monkeypatch):
    """The background delegation that cannot widen; the operator's seed credential, minted for
    the pass, can, as the system principal and under the same rules."""
    sys_id, background = system
    alice = world["alice"][1]
    af.ok(af.submit(custody_client, alice, af.grant("g-sw", sys_id, "W", ALL)))
    entry = af.grant("g-seeded", world["carol"][0], "W")
    assert af.submit(custody_client, background, entry).status_code == 403
    seed = _seed(custody_client, af.operator(monkeypatch), plan=[entry])
    from jose import jwt as jose_jwt
    claims = jose_jwt.get_unverified_claims(seed["token"])
    assert claims["sub"] == sys_id and claims["exp"] - claims["iat"] <= 600
    af.ok(af.submit(custody_client, seed["token"], entry))
    assert _grant_row("g-seeded").created_by == sys_id


def test_a_seed_credential_is_bounded_by_the_system_principal_s_own_rights(custody_client, world,
                                                                          system, monkeypatch):
    entry = af.grant("g-x", world["carol"][0], "W")
    seed = _seed(custody_client, af.operator(monkeypatch), plan=[entry])["token"]
    r = af.submit(custody_client, seed, entry)
    assert r.status_code == 403                                  # the system holds nothing on W


def test_only_the_operator_mints_a_seed_credential_and_revoking_it_stops_it(custody_client, world,
                                                                          system, monkeypatch):
    sys_id, _bg = system
    other = {"Authorization": f"Bearer {world['alice'][1]}"}
    assert custody_client.post("/oracle/seed-credential", json={}, headers=other
                               ).status_code == 403
    op = af.operator(monkeypatch)
    af.ok(af.submit(custody_client, world["alice"][1], af.grant("g-sw", sys_id, "W", ALL)))
    seed = _seed(custody_client, op)
    assert oc.call(custody_client, "DELETE", f"/oracle/seed-credential/{seed['jti']}"
                   ).status_code == 200
    r = af.submit(custody_client, seed["token"], af.grant("g-late", world["carol"][0], "W"))
    assert r.status_code == 403 and "revoked" in r.json()["detail"]


def test_a_seed_credential_living_over_ten_minutes_is_refused(custody_client, world, system,
                                                             monkeypatch):
    """Even recorded, a seed credential is minutes long or it is refused."""
    import secrets
    from datetime import datetime, timedelta, timezone

    from origin.db.session import SessionLocal
    from origin.models.key_custody import SeedCredential
    from origin.services.auth_service import issue_system_delegation_token

    from origin.services import auth_service
    sys_id, _bg = system
    af.ok(af.submit(custody_client, world["alice"][1], af.grant("g-sw", sys_id, "W", ALL)))
    # The issuer caps every system delegation at 300 s (review 15); lifted here so the ledger's
    # own check is what refuses.
    monkeypatch.setattr(auth_service, "SYSTEM_DELEGATION_MAX_TTL", 3600)
    jti = secrets.token_hex(16)
    tok = issue_system_delegation_token(sys_id, actor=af.OPERATOR, scope="authority.seed",
                                        audience="origin", ttl_seconds=3600, jti=jti)
    with SessionLocal() as db:
        db.add(SeedCredential(jti=jti, subject=sys_id, issued_by=af.OPERATOR,
                              expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        db.commit()
    r = af.submit(custody_client, tok, af.grant("g-long", world["carol"][0], "W"))
    assert r.status_code == 403 and "600" in r.json()["detail"]
