"""Each change Origin co-signs is admitted by a named rule, and the edges of those rules hold.

A creation does not make a member's creator its owner beyond what they reach; a compensation
withdraws only the actor's own fresh entry and never a deny; the system principal's narrowings
land; a bootstrap states only ids Origin has not seen, once; a new key principal comes with its
creation; expiry is compared as time; an issuer cannot turn a grant into a deny; the replay checks
every replica table; the person-delegation exchange takes a person's own access token only; and a
seed credential serves one pass.

Each test runs against the real Origin app (`custody_client`), with no rule replaced.
"""
# ruff: noqa: F811 — `world` and `system` are pytest fixtures, imported and named as parameters
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, _edge_row, _grant_row, system, world)

custody_client = _shares.custody_client


def _later(minutes):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


# -- 1. a create-only member does not become the owner of what they create --------------------

def test_a_create_only_member_cannot_open_the_collection_key(custody_client, world):
    c = custody_client
    alice = world["alice"][1]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "C")))
    af.ok(af.submit(c, alice, af.grant("g-ac", world["alice"][0], "C", ALL)))   # her owner grant
    af.ok(af.submit(c, alice, af.grant("g-cc", carol_id, "C", ["create"])))
    af.store_share(c, "ck:C")
    assert af.release(c, "ck:C", carol, collection="C").status_code == 403
    af.ok(af.submit(c, carol, af.edge("C", "X1")))                     # create: hers to make
    r = af.submit(c, carol, af.grant("g-cx", carol_id, "X1", ["read"]))
    assert r.status_code == 403
    assert af.release(c, "ck:C", carol, collection="C", artifact="X1").status_code == 403


def test_a_member_s_creator_records_what_they_already_reach(custody_client, world):
    """The positive control: Alice reaches everything on `C`, so her owner grant on what she
    creates there is recorded; Carol's `create` covers a `create` record and no more."""
    c = custody_client
    alice_id, alice = world["alice"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "C")))
    af.ok(af.submit(c, alice, af.grant("g-ac", alice_id, "C", ALL)))
    af.ok(af.submit(c, alice, af.edge("C", "A1")))
    af.ok(af.submit(c, alice, af.grant("g-a1", alice_id, "A1", ["read", "admin"])))
    af.ok(af.submit(c, alice, af.grant("g-cc", carol_id, "C", ["create"])))
    af.ok(af.submit(c, carol, af.edge("C", "X2")))
    af.ok(af.submit(c, carol, af.grant("g-x2", carol_id, "X2", ["create"])))
    assert af.submit(c, carol, af.grant("g-x2", carol_id, "X2", ["create", "read"])
                     ).status_code == 403


def test_a_self_rooted_creation_keeps_the_creator_s_base_case(custody_client, world):
    """A node with no creation parent is its creator's to set up, as Mantle's own base case."""
    c = custody_client
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, carol, af.root("Solo")))
    af.ok(af.submit(c, carol, af.grant("g-solo", carol_id, "Solo", ALL)))


# -- 8. a compensation withdraws the actor's own fresh entry, never a deny ----------------------

def test_a_deny_is_never_lifted_by_compensation(custody_client, world):
    """A deny is made in the person's Origin session (review 12): Origin writes it, so it is
    confirmed when appended, and no compensation, on any credential, lifts it."""
    c = custody_client
    alice = world["alice"][1]
    bob_id, bob = world["bob"]
    af.store_share(c, "ck:W")
    kept = af.ok(af.submit(c, alice, af.grant("g-deny", bob_id, "W", ["read"], effect="deny")))
    r = af.submit(c, alice, af.grant("g-deny", bob_id, "W", ["read"], effect="deny",
                                     state="retired"), compensates=kept["seq"])
    assert r.status_code == 403
    assert af.release(c, "ck:W", bob, collection="W").status_code == 403


def test_a_compensation_comes_soon_and_on_the_same_credential(custody_client, world,
                                                              monkeypatch):
    from origin import config
    from origin.services import authority_ledger
    from origin.services.auth_service import create_jwt_token

    c = custody_client
    alice_id, alice = world["alice"]
    added = af.ok(af.submit(c, alice, af.edge("W", "m-1")))
    other = create_jwt_token({"sub": alice_id, "email": "alice@team.test", "name": "alice",
                              "client_id": "platform", "aud": config.AUTHORITY_ISSUER,
                              "iat": time.time() - 1})
    r = af.submit(c, other, af.unedge("W", "m-1"), compensates=added["seq"])
    assert r.status_code == 403 and "credential" in r.json()["detail"]
    monkeypatch.setattr(authority_ledger, "COMPENSATION_WINDOW_SECONDS", -1)
    r = af.submit(c, alice, af.unedge("W", "m-1"), compensates=added["seq"])
    assert r.status_code == 403 and "within" in r.json()["detail"]
    monkeypatch.setattr(authority_ledger, "COMPENSATION_WINDOW_SECONDS", 60)
    af.ok(af.submit(c, alice, af.unedge("W", "m-1"), compensates=added["seq"]))


# -- 5. the system principal's narrowings land --------------------------------------------------

def test_the_system_principal_changes_nothing_of_its_own(custody_client, world, system):
    """Review 16: a background delegation makes no change of its own, narrowing included: it
    shortens no expiry, retires no grant and removes no edge. It holds nothing on `W`."""
    _sys_id, bg = system
    c = custody_client
    alice = world["alice"][1]
    carol_id = world["carol"][0]
    af.ok(af.submit(c, alice, af.grant("g-cw", carol_id, "W", ["read"], expires_at=_later(60))))
    assert af.submit(c, bg, af.grant("g-cw", carol_id, "W", ["read"], expires_at=_later(5))
                     ).status_code == 403
    assert af.submit(c, bg, af.grant("g-cw", carol_id, "W", ["read"], expires_at=_later(120))
                     ).status_code == 403                                 # longer: a widening
    assert af.submit(c, bg, af.grant("g-bw", world["bob"][0], "W", ["read", "share"],
                                     state="retired")).status_code == 403
    af.ok(af.submit(c, alice, af.edge("W", "m-2")))
    assert af.submit(c, bg, af.unedge("W", "m-2")).status_code == 403
    assert af.submit(c, bg, af.grant("g-nd", carol_id, "W", ["read"], effect="deny")
                     ).status_code == 403                                 # issues nothing new
    assert _grant_row("g-bw").state == "active"


# -- 3. a bootstrap states only what Origin has not seen, once -----------------------------------

def test_a_bootstrap_on_an_empty_ledger_states_unseen_ids(custody_client, monkeypatch):
    boot = af.open_bootstrap(custody_client, af.operator(monkeypatch))
    af.ok(af.submit(custody_client, boot, af.root("Old"), bootstrap=True))
    af.ok(af.submit(custody_client, boot, af.grant("g-old", "someone", "Old"), bootstrap=True))


def test_after_cutover_a_bootstrap_states_only_the_listed_unseen_ids(custody_client, world,
                                                                    monkeypatch):
    op = af.operator(monkeypatch)
    unlisted = af.open_bootstrap(custody_client, op)
    r = af.submit(custody_client, unlisted, af.root("Old"), bootstrap=True)
    assert r.status_code == 403 and "listed" in r.json()["detail"]
    listed = af.open_bootstrap(custody_client, op, ids=["Old", "W", "g-old"])
    r = af.submit(custody_client, listed, af.grant("g-w", world["carol"][0], "W"),
                  bootstrap=True)
    assert r.status_code == 403 and "already holds" in r.json()["detail"]   # seen, even listed
    af.ok(af.submit(custody_client, listed, af.root("Old"), bootstrap=True))
    af.ok(af.submit(custody_client, listed, af.grant("g-old", "someone", "Old"), bootstrap=True))


def test_a_bootstrap_credential_serves_one_batch(custody_client, monkeypatch):
    boot = af.open_bootstrap(custody_client, af.operator(monkeypatch))
    af.ok(af.submit(custody_client, boot, af.root("Old"), bootstrap=True))
    tok = _shares._token("POST", "-", htu="/internal/authority/bootstrap-done")
    r = custody_client.post("/internal/authority/bootstrap-done",
                            headers={"Authorization": f"Bearer {tok}",
                                     "X-Acting-Credential": boot})
    assert r.status_code == 200, r.text
    r = af.submit(custody_client, boot, af.root("Older"), bootstrap=True)
    assert r.status_code == 403


# -- 9. a new key principal is registered with its creation ------------------------------------

def test_a_root_for_a_new_id_comes_with_its_creation(custody_client, world):
    c = custody_client
    carol_id, carol = world["carol"]
    alice_id = world["alice"][0]
    for proof in ({}, {"created_by": alice_id, "created_at": _later(0)},
                  af.creation(carol, minutes_ago=30), {"created_by": carol_id,
                                                       "created_at": "not a time"}):
        r = af.submit(c, carol, af.root("N1"), proof=proof)
        assert r.status_code == 403, proof
    af.ok(af.submit(c, carol, af.root("N1"), proof=af.creation(carol)))


# -- 10. expiry is time, not text ---------------------------------------------------------------

def test_expiry_is_compared_as_time():
    from origin.services import authority_ledger as al
    from origin.services.authority_reach import Grant, unexpired

    def g(expires):
        return Grant(id="g", resource_id="W", grantee_id="p", grantee_type="user",
                     actions=frozenset({"read"}), effect="allow", state="active",
                     expires_at=expires)

    # 11:00 at +05:00 is 06:00 UTC: earlier than 10:00 UTC, though it sorts later as text.
    assert not al._widens(g("2030-01-01T10:00:00+00:00"), g("2030-01-01T11:00:00+05:00"))
    assert al._widens(g("2030-01-01T11:00:00+05:00"), g("2030-01-01T10:00:00+00:00"))
    assert not unexpired("next tuesday")
    assert unexpired("2999-01-01T00:00:00Z") and not unexpired("2000-01-01T00:00:00+09:00")


def test_an_unparseable_expiry_is_refused(custody_client, world):
    r = af.submit(custody_client, world["alice"][1],
                  af.grant("g-x", world["carol"][0], "W", expires_at="soon"), digest="0" * 64)
    assert r.status_code == 400 and "ISO-8601" in r.json()["detail"]


# -- 11. an issuer's narrowing keeps the grant's effect -----------------------------------------

def test_an_issuer_cannot_turn_their_grant_into_a_deny(custody_client, world):
    """Bob holds `share` on `W`: he issues an invite and may narrow it, but changing its effect
    to deny needs admin."""
    c = custody_client
    bob = world["bob"][1]
    af.ok(af.submit(c, bob, af.invite("g-inv", "tok-1", "W", ["read"])))
    deny = af.invite("g-inv", "tok-1", "W", ["read"])
    deny["effect"] = "deny"
    r = af.submit(c, bob, deny)
    assert r.status_code == 403
    af.ok(af.submit(c, bob, af.invite("g-inv", "tok-1", "W", ["read"], state="retired")))


# -- 13. the replay checks nodes and who added each edge ----------------------------------------

@pytest.mark.parametrize("tamper", ["node", "edge"])
def test_verify_replays_creators_and_edge_adders(custody_client, world, monkeypatch, tamper):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEdge, AuthorityNode
    from origin.tests import operator_console_fixtures as oc

    af.ok(af.submit(custody_client, world["alice"][1], af.edge("W", "m-3")))
    af.operator(monkeypatch)
    assert oc.call(custody_client, "GET", "/oracle/authority-ledger/verify").json()["ok"]
    with SessionLocal() as db:
        if tamper == "node":
            db.get(AuthorityNode, "m-3").created_by = world["carol"][0]
        else:
            db.get(AuthorityEdge, ("W", "m-3")).added_by = world["carol"][0]
        db.commit()
    v = oc.call(custody_client, "GET", "/oracle/authority-ledger/verify").json()
    assert not v["ok"] and ("nodes" if tamper == "node" else "edges") in v["detail"]


def test_each_receipt_names_the_ledger_head(custody_client, world):
    r1 = af.ok(af.submit(custody_client, world["alice"][1], af.edge("W", "m-4")))
    r2 = af.ok(af.submit(custody_client, world["alice"][1], af.edge("W", "m-5")))
    assert r1["head_seq"] == r1["seq"] and r2["head_seq"] == r2["seq"] > r1["seq"]


# -- 2. the person-delegation exchange takes a person's own access token only --------------------

def _exchange(c, subject_token):
    tok = _shares._token("POST", "-", iss="chorus", htu="/internal/delegation-token")
    return c.post("/internal/delegation-token",
                  json={"server_client_id": "agience-server-sage", "subject_token": subject_token,
                        "ttl_seconds": 600},
                  headers={"Authorization": f"Bearer {tok}"})


def test_mcp_client_and_refresh_tokens_are_not_exchanged(custody_client, world):
    from origin import config
    from origin.services.auth_service import create_jwt_token

    alice_id, alice = world["alice"]
    mcp = create_jwt_token({"sub": alice_id, "aud": "third-party-client",
                            "principal_type": "mcp_client", "scopes": ["read"]})
    refresh = create_jwt_token({"sub": alice_id, "email": "a@x", "client_id": "platform",
                                "aud": config.AUTHORITY_ISSUER, "token_type": "refresh"},
                               expires_hours=24 * 30)
    for t in (mcp, refresh):
        assert _exchange(custody_client, t).status_code == 403
    # Nor a person's own access token, by anyone (review 27): only a delegation narrowed to the
    # asking persona is exchanged (`test_review27_custody`).
    assert _exchange(custody_client, alice).status_code == 403


# -- 15. a seed credential serves one pass --------------------------------------------------------

def test_a_seed_pass_ends_its_seed_credential(custody_client, world, system, monkeypatch):
    from origin.tests import operator_console_fixtures as oc

    sys_id, _bg = system
    af.ok(af.submit(custody_client, world["alice"][1], af.grant("g-sw", sys_id, "W", ALL)))
    af.operator(monkeypatch)
    from origin.services.authority_ledger import body_digest
    first, second = (af.grant("g-s1", world["carol"][0], "W"),
                     af.grant("g-s2", world["carol"][0], "W"))
    seed = oc.call(custody_client, "POST", "/oracle/seed-credential",
                   json={"minutes": 10, "plan": [body_digest(first), body_digest(second)]}).json()
    af.ok(af.submit(custody_client, seed["token"], first))
    tok = _shares._token("POST", "-", htu="/internal/authority/seed-done")
    r = custody_client.post("/internal/authority/seed-done",
                            headers={"Authorization": f"Bearer {tok}",
                                     "X-Acting-Credential": seed["token"]})
    assert r.status_code == 200, r.text
    r = af.submit(custody_client, seed["token"], second)
    assert r.status_code == 403 and "revoked" in r.json()["detail"]


# -- review: a member's own owner grant, custody credentials as bearers, a deny's expiry ----------

def test_a_member_s_own_grant_on_their_artifact_does_not_outlast_their_reach(custody_client, world):
    """Carol reads `C` and records an owner grant on what she creates there. Once her grant on
    `C` is retired, her own grant on the artifact no longer opens `ck:C`; a grant someone else
    issued on an artifact (Alice's, to Dana) does."""
    c = custody_client
    alice_id, alice = world["alice"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "C")))
    af.ok(af.submit(c, alice, af.grant("g-ac", alice_id, "C", ALL)))
    af.ok(af.submit(c, alice, af.grant("g-cc", carol_id, "C", ["read", "create"])))
    af.ok(af.submit(c, carol, af.edge("C", "B1")))
    af.ok(af.submit(c, carol, af.grant("g-c1", carol_id, "B1", ["read"])))
    af.store_share(c, "ck:C")
    assert af.release(c, "ck:C", carol, collection="C", artifact="B1").status_code == 200
    af.ok(af.submit(c, alice, af.grant("g-cc", carol_id, "C", ["read", "create"], state="retired")))
    assert af.release(c, "ck:C", carol, collection="C", artifact="B1").status_code == 403
    dana_id, dana = af.person("dana")
    af.ok(af.submit(c, alice, af.edge("C", "A2")))
    af.ok(af.submit(c, alice, af.grant("g-a2", alice_id, "A2", ALL)))
    af.ok(af.submit(c, alice, af.grant("g-da2", dana_id, "A2", ["read"])))
    assert af.release(c, "ck:C", dana, collection="C", artifact="A2").status_code == 200


def test_a_custody_credential_is_no_bearer_token(custody_client, world, system, monkeypatch):
    _sys, background = system
    boot = af.open_bootstrap(custody_client, af.operator(monkeypatch))
    for tok in (background, boot):
        r = custody_client.get("/auth/me/preferences", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401, (r.status_code, r.text[:80])


def test_shortening_a_deny_is_a_widening(custody_client, world, system):
    """A deny that ends sooner lifts it sooner: the system principal may not, and neither may an
    issuer without admin."""
    _sys, bg = system
    c = custody_client
    alice = world["alice"][1]
    af.ok(af.submit(c, alice, af.grant("g-d", world["bob"][0], "W", ["read"], effect="deny",
                                       expires_at=_later(600))))
    r = af.submit(c, bg, af.grant("g-d", world["bob"][0], "W", ["read"], effect="deny",
                                  expires_at=_later(-1)))
    assert r.status_code == 403


# -- the still-open list, closed ----------------------------------------------------------------

def test_a_member_whose_creation_edge_is_demoted_or_removed_gets_no_base_case(custody_client,
                                                                                 world):
    c = custody_client
    alice_id, alice = world["alice"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "C")))
    af.ok(af.submit(c, alice, af.grant("g-ac", alice_id, "C", ALL)))
    af.ok(af.submit(c, alice, af.grant("g-cc", carol_id, "C", ["create", "add"])))
    # A creation edge is removed, never demoted (review 30): no one demotes it, Admin included.
    af.ok(af.submit(c, carol, af.edge("C", "M1")))
    for who in (carol, alice):
        r = af.submit(c, who, af.edge("C", "M1", origin=False))
        assert r.status_code == 403 and "never demoted" in r.text, r.text
    for member, undo in (("M2", af.unedge("C", "M2")),):
        af.ok(af.submit(c, carol, af.edge("C", member)))
        af.ok(af.submit(c, alice, undo))
        r = af.submit(c, carol, af.grant(f"g-{member}", carol_id, member, ["read", "admin"]))
        # A creation edge removed leaves the member no creation parent: it is deleted at Origin
        # (review 15), and nothing is granted on it.
        assert r.status_code == 409, (member, r.text)


def _secondary(c, alice_cred, alice_id, dst):
    """A root `dst` of Alice's, hung in W by a secondary edge (review 16: the only kind of edge a
    background retry withdraws). Returns the edge's receipt."""
    af.ok(af.submit(c, alice_cred, af.root(dst)))
    af.ok(af.submit(c, alice_cred, af.grant(f"g-a-{dst}", alice_id, dst, ALL)))
    return af.ok(af.submit(c, alice_cred, af.edge("W", dst, origin=False)))


def test_a_retried_withdrawal_keeps_the_still_latest_check(custody_client, world, system,
                                                           monkeypatch):
    """The system principal retries Alice's withdrawal past the window; Origin takes it only while
    her entry is the latest change to its row."""
    from origin.services import authority_ledger

    _sys, bg = system
    c = custody_client
    alice_id, alice = world["alice"]
    first = _secondary(c, alice, alice_id, "m-6")
    second = _secondary(c, alice, alice_id, "m-7")
    af.ok(af.submit(c, alice, af.edge("W", "m-7", origin=False,
                                      propagate=["read"])))               # m-7 changed since
    monkeypatch.setattr(authority_ledger, "COMPENSATION_WINDOW_SECONDS", -1)   # long past it
    r = af.submit(c, bg, af.unedge("W", "m-7"), compensates=second["seq"])
    assert r.status_code == 409
    af.ok(af.submit(c, bg, af.unedge("W", "m-6"), compensates=first["seq"]))


def test_a_bootstrap_window_s_ids_hold_before_cutover_too(custody_client, monkeypatch):
    boot = af.open_bootstrap(custody_client, af.operator(monkeypatch), ids=["Old"])
    r = af.submit(custody_client, boot, af.root("Other"), bootstrap=True)
    assert r.status_code == 403 and "lists ids" in r.json()["detail"]
    af.ok(af.submit(custody_client, boot, af.root("Old"), bootstrap=True))


def test_a_bootstrap_keeps_the_person_id_checks(custody_client, monkeypatch):
    pid, _tok = af.person("pat")
    boot = af.open_bootstrap(custody_client, af.operator(monkeypatch))
    af.ok(af.submit(custody_client, boot, af.root("Shelf"), bootstrap=True))
    r = af.submit(custody_client, boot, af.edge("Shelf", pid), bootstrap=True)
    assert r.status_code == 403 and "person" in r.json()["detail"]
    r = af.submit(custody_client, boot, af.root(pid, "Shelf"), bootstrap=True)
    assert r.status_code in (403, 409)
    af.ok(af.submit(custody_client, boot, af.root(pid), bootstrap=True))


# -- third review: only an unconfirmed entry is withdrawn ----------------------------------------

def _confirm(c, seqs):
    from origin.services.authority_ledger import confirm_digest

    tok = _shares._token("POST", "-", htu="/internal/authority/confirm",
                         body_sha256=confirm_digest(seqs))
    return c.post("/internal/authority/confirm", json={"seqs": seqs},
                  headers={"Authorization": f"Bearer {tok}"})


def test_a_confirmed_entry_is_not_withdrawn_by_anyone(custody_client, world, system, monkeypatch):
    """Mantle confirms each entry whose write committed. A withdrawal, its actor's within the
    window or the system principal's retry after it, is only for an entry not confirmed."""
    from origin.services import authority_ledger

    _sys, bg = system
    c = custody_client
    alice_id, alice = world["alice"]
    kept = _secondary(c, alice, alice_id, "m-8")
    failed = _secondary(c, alice, alice_id, "m-9")
    assert _confirm(c, [kept["seq"]]).json()["confirmed"] == 1
    r = af.submit(c, alice, af.unedge("W", "m-8"), compensates=kept["seq"])
    assert r.status_code == 403 and "confirmed" in r.json()["detail"]
    monkeypatch.setattr(authority_ledger, "COMPENSATION_WINDOW_SECONDS", -1)
    r = af.submit(c, bg, af.unedge("W", "m-8"), compensates=kept["seq"])
    assert r.status_code == 403
    af.ok(af.submit(c, bg, af.unedge("W", "m-9"), compensates=failed["seq"]))


def test_a_superseded_withdrawal_names_the_row_s_latest_entry(custody_client, world):
    c = custody_client
    alice = world["alice"][1]
    first = af.ok(af.submit(c, alice, af.edge("W", "m-10")))
    later = af.ok(af.submit(c, alice, af.edge("W", "m-10", propagate=["read"])))
    r = af.submit(c, alice, af.unedge("W", "m-10"), compensates=first["seq"])
    assert r.status_code == 409 and f"latest entry {later['seq']}" in r.json()["detail"]


# -- fourth review: creation grants by batch, confirmation, the operator's ledger routes ----------

def test_a_creator_s_rights_are_the_creation_grant_in_the_same_batch(custody_client, world):
    """`created_by` grants nothing (architecture §51). A self-rooted id's creator gets their grant
    only in the batch that creates it; a later batch needs admin like anyone."""
    c = custody_client
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, carol, af.root("R1"), batch="make-r1"))
    assert af.submit(c, carol, af.grant("g-r1", carol_id, "R1", ALL), batch="later"
                     ).status_code == 403
    af.ok(af.submit(c, carol, af.grant("g-r1", carol_id, "R1", ALL), batch="make-r1"))
    af.ok(af.submit(c, carol, af.grant("g-r1b", world["bob"][0], "R1"), batch="later"))  # admin


def test_confirmation_is_body_bound_and_for_this_service_s_pending_entries(custody_client,
                                                                          world):
    from origin.services.authority_ledger import confirm_digest

    c = custody_client
    e = af.ok(af.submit(c, world["alice"][1], af.edge("W", "m-11")))
    tok = _shares._token("POST", "-", htu="/internal/authority/confirm",
                         body_sha256=confirm_digest([e["seq"] + 99]))
    r = c.post("/internal/authority/confirm", json={"seqs": [e["seq"]]},
               headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401                                   # the token names another body
    assert _confirm(c, [e["seq"] + 500]).status_code == 403       # not one it submitted
    assert _confirm(c, [e["seq"]]).status_code == 200
    assert _confirm(c, [e["seq"]]).status_code == 403             # no longer pending


def test_the_operator_lists_and_resolves_what_mantle_never_confirmed(custody_client, world,
                                                                    monkeypatch):
    from origin.tests import operator_console_fixtures as oc

    c = custody_client
    alice = world["alice"][1]
    d = af.ok(af.submit(c, alice, af.grant("g-d3", world["bob"][0], "W", ["read"],
                                           effect="deny")))
    w = af.ok(af.submit(c, alice, af.edge("W", "m-13")))
    k = af.ok(af.submit(c, alice, af.edge("W", "m-12")))
    af.operator(monkeypatch)
    pending = [x["seq"] for x in oc.call(c, "GET", "/oracle/authority-ledger/unconfirmed"
                                         ).json()["entries"]]
    assert d["seq"] not in pending                    # made in the session: Origin's own write
    assert w["seq"] in pending and k["seq"] in pending
    r = oc.call(c, "POST", "/oracle/authority-ledger/resolve",
                json={"seq": w["seq"], "decision": "withdraw"})
    assert r.status_code == 200 and r.json()["receipt"]["outcome"] == "appended"
    assert _edge_row("W", "m-13") is None
    assert _grant_row("g-d3").state == "active"
    assert oc.call(c, "POST", "/oracle/authority-ledger/resolve",
                   json={"seq": k["seq"], "decision": "keep"}).status_code == 200
    r = af.submit(c, alice, af.unedge("W", "m-12"), compensates=k["seq"])
    assert r.status_code == 410                                    # Mantle's due clears


def test_the_operator_finds_and_revokes_what_a_credential_co_signed(custody_client, world,
                                                                   monkeypatch):
    from origin.tests import operator_console_fixtures as oc

    c = custody_client
    alice = world["alice"][1]
    g = af.ok(af.submit(c, alice, af.grant("g-leak", world["carol"][0], "W", ["read"])))
    af.operator(monkeypatch)
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    with SessionLocal() as db:
        ref = db.get(AuthorityEntry, g["seq"]).credential_ref
    found = oc.call(c, "GET", f"/oracle/authority-ledger/entries?credential_ref={ref}").json()
    assert g["seq"] in [e["seq"] for e in found["entries"]]
    r = oc.call(c, "POST", "/oracle/authority-ledger/revoke", json={"seqs": [g["seq"]]})
    assert r.status_code == 200 and r.json()["revoked"][0]["receipt"]["outcome"] == "appended"
    assert _grant_row("g-leak").state == "revoked"
    af.store_share(c, "ck:W")
    assert af.release(c, "ck:W", world["carol"][1], collection="W").status_code == 403


@pytest.mark.parametrize("action", ["create", "update", "delete", "evict", "invoke", "add",
                                    "share", "admin"])
def test_no_action_but_read_opens_a_collection_key_at_origin(custody_client, world, action):
    """Architecture §51, CRUDEASIO: each action stands alone; only Read releases a content key."""
    c = custody_client
    alice = world["alice"][1]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.root("Inbox")))
    af.ok(af.submit(c, alice, af.grant("g-ai", world["alice"][0], "Inbox", ALL + ["invoke"])))
    af.ok(af.submit(c, alice, af.grant("g-ci", carol_id, "Inbox", [action])))
    af.store_share(c, "ck:Inbox")
    assert af.release(c, "ck:Inbox", carol, collection="Inbox").status_code == 403
