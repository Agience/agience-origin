"""The sixth review's ledger and custody cases (2026-11-02), each refused on Origin's own rules.

M1  Any write to an existing share, whatever key check it claims, is replaceable only while the
    share is marked so, and only by the key's principal or Admin on what it keys. The key check is
    Mantle's claim, never proof. The operator restores a superseded share from history.
M2  A deny is changed only by Admin, its issuer included; a compensation restores the entry's prior
    state and never retires the row.
M4  Every Admin-level grant, and every platform-admin appointment, raises an operator alert.
L1  The operator retires a planted root or node; a person's derived ids are theirs alone.
L4  A drop key is accepted on Admin on the collection, and a changed one only from the operator.
    Also: an expired or non-person grant is no platform-admin appointment; a seed credential marks
    for re-key only the shares it lists.
"""
from __future__ import annotations

import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]


@pytest.fixture
def people(custody_client):
    return {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob", "carol", "mal")}


def _activate(c, principal, credential):
    """On the acting credential of one holding Admin on what the key keys (review 25)."""
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/activate")
    return c.post(f"/internal/key-shares/{principal}/activate",
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def _collection(c, owner, cid="K", batch="a"):
    af.ok(af.submit(c, owner[1], af.root(cid), batch=batch))
    af.ok(af.submit(c, owner[1], af.grant(f"g-{cid}-own", owner[0], cid, ALL), batch=batch))


# -- M1 -------------------------------------------------------------------------------------------

def test_m1_a_reader_cannot_replace_an_active_share_by_keeping_its_kcv(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _collection(c, alice)
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read"]), batch="a2"))
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200
    assert _activate(c, "ck:K", alice[1]).status_code == 200
    before = af.release(c, "ck:K", alice[1]).json()
    r = af.store_share(c, "ck:K", bob[1], y=_shares.OTHER_Y)          # same kcv
    after = af.release(c, "ck:K", alice[1]).json()
    assert r.status_code == 403 and after["y"] == before["y"], r.text


def test_m1_an_active_share_is_not_replaced_even_by_its_admin(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _collection(c, alice)
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200
    assert _activate(c, "ck:K", alice[1]).status_code == 200
    r = af.store_share(c, "ck:K", alice[1], y=_shares.OTHER_Y)
    assert r.status_code == 403 and "marked for re-key" in r.text


def test_m1_a_reader_restating_the_same_share_changes_nothing(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _collection(c, alice)
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read"]), batch="a2"))
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200
    r = af.store_share(c, "ck:K", bob[1])
    assert r.status_code == 200 and r.json()["outcome"] == "unchanged"


def test_m1_a_pending_share_is_replaced_by_its_admin_and_restored_by_the_operator(
        custody_client, people, monkeypatch):
    c = custody_client
    alice = people["alice"]
    af.operator(monkeypatch)
    _collection(c, alice)
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200      # first share: pending
    first = af.release(c, "ck:K", alice[1]).json()
    assert af.store_share(c, "ck:K", alice[1], y=_shares.OTHER_Y).status_code == 200
    assert af.release(c, "ck:K", alice[1]).json()["y"] == _shares.OTHER_Y
    hist = oc.call(c, "GET", "/oracle/key-shares/ck:K/history")
    assert hist.status_code == 200, hist.text
    old = hist.json()["history"][0]
    assert old["kcv"] == first["kcv"] and "y" not in old
    r = oc.call(c, "POST", "/oracle/key-shares/ck:K/restore", json={"history_id": old["id"]})
    assert r.status_code == 200, r.text
    assert af.release(c, "ck:K", alice[1]).json()["y"] == first["y"]
    later = oc.call(c, "GET", "/oracle/key-shares/ck:K/history").json()["history"]
    assert len(later) == 2                                              # the replaced one is kept


# -- M2 -------------------------------------------------------------------------------------------

def _denied(c, people):
    alice, bob, carol = people["alice"], people["bob"], people["carol"]
    _collection(c, alice)
    af.ok(af.submit(c, alice[1], af.grant("g-ck", carol[0], "K", ["read"]), batch="a2"))
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["admin", "read"]), batch="a3"))
    af.ok(af.submit(c, bob[1], af.grant("g-deny", carol[0], "K", ["read"], effect="deny"),
                    batch="b1"))
    af.store_share(c, "ck:K", alice[1])
    assert af.release(c, "ck:K", carol[1]).status_code == 403
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["admin", "read"],
                                          state="revoked"), batch="a4"))


def test_m2_a_deny_issuer_without_admin_cannot_change_the_deny(custody_client, people):
    c = custody_client
    _denied(c, people)
    bob, carol = people["bob"], people["carol"]
    r = af.submit(c, bob[1], af.grant("g-deny", carol[0], "K", ["read", "update"],
                                      effect="deny"), batch="b3")
    assert r.status_code == 403, r.text
    assert af.release(c, "ck:K", carol[1]).status_code == 403


def test_m2_compensation_restores_the_prior_state_and_never_retires_the_row(custody_client,
                                                                            people):
    """Withdrawing a grant's retirement (Mantle's deletion that failed) puts the grant back as it
    was, never retired. (A deny is made in the person's Origin session since review 12, confirmed
    when appended, and never withdrawn.)"""
    c = custody_client
    _denied(c, people)
    alice = people["alice"]
    gone = af.deleted_member(c, alice[1], alice[0], "K", "m-m2", "g-m2")
    af.ok(af.submit(c, alice[1], af.grant("g-m2", alice[0], "m-m2", ["read", "update", "delete"],
                                          state="retired"),
                    compensates=gone["seq"], batch=None, via_session=False))
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        row = db.get(AuthorityGrant, "g-m2")
        assert (row.state, row.effect, row.actions) == ("active", "allow", "read,update,delete")


def test_m2_the_original_issuer_does_not_narrow_their_own_grant_without_admin(custody_client,
                                                                             people):
    """created_by grants nothing (§51): an allow grant's issuer who lost Admin changes nothing."""
    c = custody_client
    alice, bob, carol = people["alice"], people["bob"], people["carol"]
    _collection(c, alice)
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["admin", "read", "update"]),
                    batch="a2"))
    af.ok(af.submit(c, bob[1], af.grant("g-cb", carol[0], "K", ["read", "update"]), batch="b1"))
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["admin", "read", "update"],
                                          state="revoked"), batch="a3"))
    r = af.submit(c, bob[1], af.grant("g-cb", carol[0], "K", ["read"]), batch="b2")
    assert r.status_code == 403, r.text


def test_m2_an_invite_s_issuer_without_admin_does_not_close_it(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _collection(c, alice)
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["share", "read"]), batch="a2"))
    af.ok(af.submit(c, bob[1], af.invite("inv-1", "tok-1", "K", ["read"]), batch="b1"))
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["share", "read"],
                                          state="revoked"), batch="a3"))
    r = af.submit(c, bob[1], af.invite("inv-1", "tok-1", "K", ["read"], state="revoked"),
                  batch="b2")
    assert r.status_code == 403, r.text
    assert af.ok(af.submit(c, alice[1], af.invite("inv-1", "tok-1", "K", ["read"],
                                                  state="revoked"), batch="a4"))


# -- M4 -------------------------------------------------------------------------------------------

def test_m4_an_admin_grant_and_a_platform_admin_appointment_raise_operator_alerts(
        custody_client, people, monkeypatch):
    from origin.services.platform_settings_service import settings as platform_settings

    c = custody_client
    alice, bob, carol = people["alice"], people["bob"], people["carol"]
    af.operator(monkeypatch)
    _collection(c, alice, cid="AUTH", batch="auth")
    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw: "AUTH"
                        if k == "platform.authority_collection_id" else real_get(k, *a, **kw))
    _collection(c, alice, cid="K", batch="k")
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read", "admin"]), batch="k2"))
    af.ok(af.submit(c, alice[1], af.grant("g-ck", carol[0], "K", ["read"]), batch="k3"))
    af.ok(af.submit(c, alice[1], af.grant("g-cauth", carol[0], "AUTH", ["read"]), batch="a2"))
    r = oc.call(c, "GET", "/oracle/alerts")
    assert r.status_code == 200, r.text
    kinds = {(a["kind"], a["resource_id"], a["subject"]) for a in r.json()["alerts"]}
    assert ("admin_grant", "K", bob[0]) in kinds
    assert ("platform_admin", "AUTH", carol[0]) in kinds
    assert ("admin_grant", "AUTH", alice[0]) not in kinds              # her creation grant
    assert ("platform_admin", "AUTH", alice[0]) not in kinds
    assert not any(s == carol[0] and res == "K" for _k, res, s in kinds)  # Read on K: none


# -- L1 -------------------------------------------------------------------------------------------

def test_l1_a_person_s_derived_card_id_is_theirs_alone(custody_client, people):
    c = custody_client
    alice, mal = people["alice"], people["mal"]
    for card in (str(uuid.uuid5(uuid.NAMESPACE_URL, f"agience://person/{alice[0]}/own")),
                 str(uuid.uuid5(uuid.NAMESPACE_URL, f"agience://person/{alice[0]}")),
                 str(uuid.uuid5(uuid.NAMESPACE_URL, f"agience://workspace/inbox/{alice[0]}"))):
        r = af.submit(c, mal[1], af.root(card), batch=None)
        assert r.status_code == 403 and "derived" in r.text, r.text
        assert af.submit(c, alice[1], af.root(card), batch=None).status_code == 200


def test_l1_the_operator_retires_a_planted_root(custody_client, people, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant, AuthorityNode, AuthorityRoot

    c = custody_client
    alice, mal = people["alice"], people["mal"]
    af.operator(monkeypatch)
    squat = f"squat-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, mal[1], af.root(squat), batch="m"))
    af.ok(af.submit(c, mal[1], af.grant("g-mal", mal[0], squat, ALL), batch="m"))
    r = oc.call(c, "POST", "/oracle/authority-ledger/retire-root",
                json={"principal_id": squat, "reason": "planted"})
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        assert db.get(AuthorityRoot, squat) is None and db.get(AuthorityNode, squat) is None
        assert db.get(AuthorityGrant, "g-mal").state == "revoked"
    af.ok(af.submit(c, alice[1], af.root(squat), batch="al"))
    af.ok(af.submit(c, alice[1], af.grant("g-al", alice[0], squat, ALL), batch="al"))


# -- info -----------------------------------------------------------------------------------------

def test_an_expired_or_non_person_admin_grant_is_no_appointment(custody_client, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    from origin.routers import authority_router
    from origin.services.platform_settings_service import settings as platform_settings

    af.operator(monkeypatch)
    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw: "AUTH"
                        if k == "platform.authority_collection_id" else real_get(k, *a, **kw))
    with SessionLocal() as db:
        db.add(AuthorityGrant(grant_id="g-exp", grantee_id="someone", grantee_type="user",
                              resource_id="AUTH", actions="admin", effect="allow",
                              state="active", expires_at="2000-01-01T00:00:00+00:00",
                              created_by="", seq=0))
        db.add(AuthorityGrant(grant_id="g-inv", grantee_id="h" * 64, grantee_type="invite",
                              resource_id="AUTH", actions="admin", effect="allow",
                              state="active", created_by="", seq=0))
        db.commit()
        assert authority_router._platform_admin(db, af.OPERATOR)


def test_a_seed_credential_marks_only_the_shares_it_lists(custody_client, people, monkeypatch):
    from origin import service_identity

    c = custody_client
    alice = people["alice"]
    af.operator(monkeypatch)
    monkeypatch.setattr(service_identity, "get_system_principal_id",
                        lambda: "00000000-0000-0000-0000-00000000005e")
    _collection(c, alice, cid="K1", batch="k1")
    _collection(c, alice, cid="K2", batch="k2")
    for k in ("ck:K1", "ck:K2"):
        assert af.store_share(c, k, alice[1]).status_code == 200
        assert _activate(c, k, alice[1]).status_code == 200
    seed = oc.call(c, "POST", "/oracle/seed-credential",
                   json={"minutes": 30, "rekey_shares": ["ck:K1"]})
    assert seed.status_code == 200, seed.text
    token = seed.json()["token"]

    def mark(principal):
        tok = _shares._token("POST", principal,
                             htu=f"/internal/key-shares/{principal}/rekey-pending")
        return c.post(f"/internal/key-shares/{principal}/rekey-pending",
                      headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": token})

    assert mark("ck:K1").status_code == 200
    assert mark("ck:K2").status_code == 403
