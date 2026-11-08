"""Review 9's job-grant cases (2026-11-02), each refused on Origin's own rules.

H2  A job grant is made only at Origin's own page, in the person's Origin session with a fresh
    step-up, never on a bearer token or a delegation alone; every one made raises an operator
    alert; the person lists and revokes their own; signing out everywhere revokes them.
M5  A job grant is live only while its grantor still holds what it was granted under (their own
    key, or Admin on each collection it names) and is an active person: checked when a delegation
    is minted and when one is used.
M6  The operator's job grants cover only collections the platform principal itself holds Admin on.
Low A background delegation is bound to its job at use.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import _mint, _root, job_grant

custody_client = _shares.custody_client
PATH = "/auth/me/job-grants"


def _days(d):
    return (datetime.now(timezone.utc) + timedelta(days=d)).isoformat()


def _page_grant(c, who, body: dict):
    """The person grants a job at Origin's own page: their session, and a fresh step-up."""
    raw = json.dumps(body).encode()
    step = oc.person_reauth(c, who[1], who[0], "POST", PATH, raw)
    return c.post(PATH, content=raw, headers={"Authorization": f"Bearer {who[1]}",
                                              "Content-Type": "application/json",
                                              "X-Step-Up": step})


def _revoke(c, who, gid):
    """Revoke a job grant at Origin's own page: in the session, with a fresh step-up (review 11)."""
    path = f"{PATH}/{gid}/revoke"
    step = oc.person_reauth(c, who[1], who[0], "POST", path, b"")
    return c.post(path, headers={"Authorization": f"Bearer {who[1]}", "X-Step-Up": step})


def _alerts(kind):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import OperatorAlert
    with SessionLocal() as db:
        return [a for a in db.query(OperatorAlert).filter(OperatorAlert.kind == kind)]


# -- H2 -------------------------------------------------------------------------------------------

def test_a_held_access_token_alone_makes_no_job_grant(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    r = af.submit(c, alice[1], job_grant("jg-mantle", "platform.reindex", alice[0],
                                         expires_at=_days(29)), batch=None)
    assert r.status_code == 403 and "Origin's own page" in r.text, r.text
    assert _mint(c, alice[0], "platform.reindex").status_code == 403


def test_the_page_route_needs_the_session_and_a_step_up(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    body = {"job": "platform.reindex", "expires_at": _days(7)}
    bare = c.post(PATH, json=body, headers={"Authorization": f"Bearer {alice[1]}"})
    assert bare.status_code == 403                                  # no session
    oc.origin_page_session(c, alice[0])
    no_step = c.post(PATH, json=body, headers={"Authorization": f"Bearer {alice[1]}"})
    assert no_step.status_code == 403                               # no step-up


def test_a_job_grant_made_at_origin_s_page_works_and_alerts(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    r = _page_grant(c, alice, {"job": "platform.reindex", "expires_at": _days(7)})
    assert r.status_code == 200, r.text
    gid = r.json()["grant_id"]
    assert [a.resource_id for a in _alerts("job_grant")] == [gid]
    tok = _mint(c, alice[0], "platform.reindex").json()["token"]
    assert af.release(c, alice[0], tok).status_code == 200
    mine = c.get(PATH, headers={"Authorization": f"Bearer {alice[1]}"}).json()["job_grants"]
    assert [g["grant_id"] for g in mine] == [gid]
    assert _revoke(c, alice, gid).status_code == 200
    assert _mint(c, alice[0], "platform.reindex").status_code == 403


def test_a_person_lists_and_revokes_only_their_own(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    bob = af.person("bob", email="bob@team.test")
    _root(c, alice, alice[0])
    gid = _page_grant(c, alice, {"job": "platform.reindex", "expires_at": _days(7)}).json()[
        "grant_id"]
    c.cookies.clear()                             # Bob's own session on this client, not Alice's
    oc.origin_page_session(c, bob[0])
    seen = c.get(PATH, headers={"Authorization": f"Bearer {bob[1]}"})
    assert seen.status_code == 200, seen.text
    assert seen.json()["job_grants"] == []
    assert _revoke(c, bob, gid).status_code == 404


def test_signing_out_everywhere_revokes_the_person_s_job_grants(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    assert _page_grant(c, alice, {"job": "platform.reindex",
                                  "expires_at": _days(7)}).status_code == 200
    r = c.post("/auth/sign-out-everywhere", headers={"Authorization": f"Bearer {alice[1]}"})
    assert r.status_code == 200, r.text
    assert _mint(c, alice[0], "platform.reindex").status_code == 403


# -- M5 -------------------------------------------------------------------------------------------

def _as_page(person_id, entry):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al
    with SessionLocal() as db:
        return al.append(db, entry, actor=al.Actor(person_id, al.ORIGIN_PAGE, "page:test"))


def test_a_job_grant_dies_with_its_grantor_s_admin(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    bob = af.person("bob", email="bob@team.test")
    _root(c, alice, "K")
    # Admin and Read: a job opens the collection's key, and a key is a Read (review 10, R4).
    af.ok(af.submit(c, alice[1], af.grant("g-bob", bob[0], "K", ["admin", "read"]), batch="b"))
    _as_page(bob[0], job_grant("jg-bob", "platform.rekey", "ck:K", ["K"], expires_at=_days(29)))
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200
    early = _mint(c, "ck:K", "platform.rekey")
    assert early.status_code == 200, early.text
    af.ok(af.submit(c, alice[1], af.grant("g-bob", bob[0], "K", ["admin", "read"],
                                          state="revoked"), batch=None))
    assert _mint(c, "ck:K", "platform.rekey").status_code == 403
    assert af.release(c, "ck:K", early.json()["token"], collection="K").status_code in (401, 403)


def test_a_deactivated_person_s_job_grant_releases_nothing(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.person import Person

    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    _as_page(alice[0], job_grant("jg-a", "platform.reindex", alice[0], expires_at=_days(29)))
    early = _mint(c, alice[0], "platform.reindex")
    assert early.status_code == 200
    with SessionLocal() as db:
        db.get(Person, uuid.UUID(alice[0])).deactivated_at = datetime.now(timezone.utc)
        db.commit()
    assert _mint(c, alice[0], "platform.reindex").status_code == 403
    assert af.release(c, alice[0], early.json()["token"]).status_code in (401, 403)


# -- M6 -------------------------------------------------------------------------------------------

def test_the_operator_s_job_grant_covers_only_the_platform_s_own_collections(custody_client,
                                                                            monkeypatch):
    from origin import service_identity
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger

    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: "sys-principal")
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, "K")
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200
    with SessionLocal() as db, pytest.raises(authority_ledger.EntryRefused, match="Admin"):
        authority_ledger.operator_job_grant(db, job="ledger.retry", hours=24, collections=["K"],
                                            operator_id=af.OPERATOR, ref="job")
    assert _mint(c, "ck:K", "ledger.retry").status_code == 403


def test_an_operator_grant_whose_admin_is_gone_mints_nothing(custody_client, monkeypatch):
    from origin import service_identity
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant

    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: "sys-principal")
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, "K")
    assert af.store_share(c, "ck:K", alice[1]).status_code == 200
    with SessionLocal() as db:                    # a grant stated without the Admin it needs
        db.add(AuthorityJobGrant(grant_id="jg-op", job="ledger.retry", principal="sys-principal",
                                 collections=json.dumps(["K"]), expires_at=_days(1),
                                 state="active", created_by=af.OPERATOR, seq=0))
        db.commit()
    assert _mint(c, "ck:K", "ledger.retry").status_code == 403


# -- a delegation is bound to its job at use ------------------------------------------------------

def test_a_background_delegation_is_bound_to_its_job_at_use(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyDelegation

    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    _as_page(alice[0], job_grant("jg-b", "platform.reindex", alice[0], expires_at=_days(1)))
    tok = _mint(c, alice[0], "platform.reindex").json()["token"]
    from jose import jwt as jose_jwt
    jti = jose_jwt.get_unverified_claims(tok)["jti"]
    with SessionLocal() as db:
        db.get(KeyCustodyDelegation, jti).job = "platform.rekey"   # not the grant's job
        db.commit()
    assert af.release(c, alice[0], tok).status_code in (401, 403)


def test_origin_s_page_offers_linking_and_the_person_s_job_grants(custody_client):
    page = custody_client.get("/passkey")
    assert page.status_code == 200
    assert 'id="linkBtn"' in page.text and 'id="jobs"' in page.text
    js = custody_client.get("/web/passkey.js").text
    assert "/auth/me/link-provider" in js and "/auth/me/job-grants" in js
