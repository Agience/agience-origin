"""Background work runs only on a job grant (John, 2026-11-02), and custody only on isolated
production.

A person grants a named background job narrow authority over their own key, and an Admin of a
collection over that collection's key: which job, which collections, until when, revocable. The
grant is an entry in Origin's ledger (`job_grant`). Mantle's service token alone mints nothing: a
background delegation is minted only under a live job grant naming that job, only for that grant's
principal and collections, a limited number of times a minute, each one recorded. What no one
granted stays shut. The console's standing 24-hour background authority is gone.

Custody (a share stored or released, a background delegation, a job grant) is refused unless the
node is isolated production (`services.custody_plane`).

And the platform-admin alerts (review 8, R6): pinning the Authorities collection alerts for every
admin it appoints, the pin is refused for an id Origin's replica does not know, the console shows
Origin's own view of a candidate, and a bootstrap's Admin grants are summarised per batch.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]


def _later(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def job_grant(gid, job, principal, collections=(), *, expires_at=None, state="active") -> dict:
    return {"kind": "job_grant", "grant_id": gid, "job": job, "principal": principal,
            "collections": list(collections), "expires_at": expires_at or _later(),
            "state": state}


def _mint(c, principal, job):
    tok = _shares._token("POST", principal, htu=f"/internal/custody-delegations/{principal}",
                         job=job)
    return c.post(f"/internal/custody-delegations/{principal}", json={"job": job},
                  headers={"Authorization": f"Bearer {tok}"})


@pytest.fixture
def people(custody_client):
    return {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob")}


def _root(c, who, rid):
    af.ok(af.submit(c, who[1], af.root(rid), batch=f"r-{rid}"))
    af.ok(af.submit(c, who[1], af.grant(f"g-{rid}", who[0], rid, ALL), batch=f"r-{rid}"))


# -- the service token alone mints nothing ---------------------------------------------------------

def test_with_no_job_grant_nothing_is_minted(custody_client, people):
    alice = people["alice"]
    _root(custody_client, alice, alice[0])
    r = _mint(custody_client, alice[0], "platform.reindex")
    assert r.status_code == 403 and "job grant" in r.text


def test_a_person_grants_a_job_over_their_own_key_and_nothing_else(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _root(c, alice, alice[0])
    _root(c, bob, bob[0])
    af.ok(af.page(alice[0], job_grant("jg-1", "platform.reindex", alice[0])))
    r = _mint(c, alice[0], "platform.reindex")
    assert r.status_code == 200, r.text
    from jose import jwt as jose_jwt

    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyDelegation
    claims = jose_jwt.get_unverified_claims(r.json()["token"])
    assert claims["sub"] == alice[0] and r.json()["job_grant"] == "jg-1"
    with SessionLocal() as db:                               # the job is recorded by its jti
        assert db.get(KeyCustodyDelegation, claims["jti"]).job == "platform.reindex"
    assert _mint(c, alice[0], "platform.seal").status_code == 403          # another job
    assert _mint(c, bob[0], "platform.reindex").status_code == 403         # another principal
    # Bob cannot grant a job over Alice's key.
    r = af.page(bob[0], job_grant("jg-2", "platform.reindex", alice[0]))
    assert r.status_code == 403


def test_a_collection_admin_grants_a_job_over_that_collection_only(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _root(c, alice, "K")
    _root(c, alice, "L")
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read"]), batch="bk"))
    # Bob holds Read on K, not Admin: he grants nothing over it.
    assert af.page(bob[0], job_grant("jg-b", "platform.rekey", "ck:K", ["K"])).status_code == 403
    af.ok(af.page(alice[0], job_grant("jg-k", "platform.rekey", "ck:K", ["K"])))
    assert _mint(c, "ck:K", "platform.rekey").status_code == 200
    assert _mint(c, "ck:L", "platform.rekey").status_code == 403


def test_a_background_delegation_releases_nothing_outside_its_grant(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _root(c, alice, "K")
    _root(c, alice, "L")
    af.ok(af.page(alice[0], job_grant("jg-k", "platform.rekey", "ck:K", ["K"])))
    for k in ("ck:K", "ck:L"):
        st = af.store_share(c, k, alice[1])
        assert st.status_code == 200, st.text
    tok = _mint(c, "ck:K", "platform.rekey").json()["token"]
    r = af.release(c, "ck:K", tok, collection="K")
    assert r.status_code == 200, r.text
    assert af.release(c, "ck:L", tok, collection="L").status_code == 403


def test_a_revoked_or_expired_job_grant_mints_nothing_and_ends_its_delegations(custody_client,
                                                                              people):
    c = custody_client
    alice = people["alice"]
    _root(c, alice, alice[0])
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    until = _later()
    af.ok(af.page(alice[0], job_grant("jg-1", "platform.reindex", alice[0],
                                           expires_at=until)))
    tok = _mint(c, alice[0], "platform.reindex").json()["token"]
    assert af.release(c, alice[0], tok).status_code == 200
    # Revoked at Origin's own page, in her session (review 12: never on a token Mantle holds).
    af.ok(af.page(alice[0], job_grant("jg-1", "platform.reindex", alice[0],
                                      expires_at=until, state="revoked")))
    assert af.release(c, alice[0], tok).status_code == 403
    assert _mint(c, alice[0], "platform.reindex").status_code == 403
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    r = af.page(alice[0], job_grant("jg-2", "platform.reindex", alice[0], expires_at=past))
    assert r.status_code in (400, 403)


def test_issuance_is_rate_limited_recorded_and_alerted(custody_client, people, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyDelegation
    from origin.services import share_credentials

    c = custody_client
    alice = people["alice"]
    af.operator(monkeypatch)
    monkeypatch.setattr(share_credentials, "JOB_ISSUANCE_PER_MINUTE", 3)
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], job_grant("jg-1", "platform.reindex", alice[0])))
    assert [_mint(c, alice[0], "platform.reindex").status_code for _ in range(4)] == \
        [200, 200, 200, 429]
    with SessionLocal() as db:
        rows = db.query(KeyCustodyDelegation).filter_by(job_grant_id="jg-1").all()
        assert len(rows) == 3 and {r.job for r in rows} == {"platform.reindex"}
    alerts = [a for a in oc.call(c, "GET", "/oracle/alerts").json()["alerts"]
              if a["kind"] == "background_issuance"]
    assert len(alerts) == 1 and "jg-1" in alerts[0]["detail"]          # one per grant per hour


def test_the_console_lists_and_revokes_job_grants_and_has_no_standing_authority(
        custody_client, people, monkeypatch):
    c = custody_client
    alice = people["alice"]
    af.operator(monkeypatch)
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], job_grant("jg-1", "platform.reindex", alice[0])))
    assert oc.call(c, "POST", "/oracle/custody-background", json={}).status_code == 404
    listed = oc.call(c, "GET", "/oracle/job-grants")
    assert listed.status_code == 200 and [g["grant_id"] for g in listed.json()["grants"]] == \
        ["jg-1"]
    assert oc.call(c, "POST", "/oracle/job-grants/jg-1/revoke", json={}).status_code == 200
    assert _mint(c, alice[0], "platform.reindex").status_code == 403


def test_the_operator_grants_a_job_for_the_platform_s_own_principal_only(custody_client, people,
                                                                         monkeypatch):
    from origin import service_identity

    c = custody_client
    alice = people["alice"]
    af.operator(monkeypatch)
    system = "00000000-0000-0000-0000-00000000005e"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: system)
    r = oc.call(c, "POST", "/oracle/job-grants", json={"job": "ledger.retry", "hours": 24})
    assert r.status_code == 200, r.text
    assert _mint(c, system, "ledger.retry").status_code == 200
    r = oc.call(c, "POST", "/oracle/job-grants", json={"job": "platform.reindex", "hours": 1,
                                                       "principal": alice[0]})
    assert r.status_code in (400, 403)


# -- custody only on isolated production ---------------------------------------------------------

def test_custody_is_refused_off_isolated_production(custody_client, people, monkeypatch):
    from origin.services import custody_plane

    c = custody_client
    alice = people["alice"]
    _root(c, alice, alice[0])
    monkeypatch.setattr(custody_plane, "TEST_OVERRIDE", None)
    monkeypatch.setenv("AGIENCE_PLANE", "home")
    assert af.store_share(c, alice[0], alice[1]).status_code == 403
    assert af.page(alice[0], job_grant("jg-1", "platform.reindex", alice[0])).status_code == 403
    assert _mint(c, alice[0], "platform.reindex").status_code == 403


def test_the_plane_signal_needs_production_and_isolation_evidence(monkeypatch, tmp_path):
    from origin.services import custody_plane

    monkeypatch.setattr(custody_plane, "TEST_OVERRIDE", None)
    monkeypatch.setenv("KEYS_DIR", str(tmp_path))
    monkeypatch.delenv("AGIENCE_PLANE", raising=False)
    assert "AGIENCE_PLANE" in custody_plane.custody_refusal()
    monkeypatch.setenv("AGIENCE_PLANE", "production")
    ok = custody_plane.custody_refusal(evidence={"euid": 1001, "no_new_privs": True,
                                                  "keys_uid": 1001, "keys_mode": 0o700,
                                                  "db_uid": 1001, "db_mode": 0o700})
    assert ok is None
    assert "root" in custody_plane.custody_refusal(
        evidence={"euid": 0, "no_new_privs": True, "keys_uid": 0, "keys_mode": 0o700})
    assert "NoNewPrivileges" in custody_plane.custody_refusal(
        evidence={"euid": 1001, "no_new_privs": False, "keys_uid": 1001, "keys_mode": 0o700,
                  "db_uid": 1001, "db_mode": 0o700})
    assert "KEYS_DIR" in custody_plane.custody_refusal(
        evidence={"euid": 1001, "no_new_privs": True, "keys_uid": 1001, "keys_mode": 0o755})


# -- R6: platform-admin alerts --------------------------------------------------------------------

def test_pinning_the_authorities_collection_alerts_for_every_admin_it_appoints(
        custody_client, people, monkeypatch):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.operator(monkeypatch)
    _root(c, alice, "AUTH")
    af.ok(af.submit(c, alice[1], af.grant("g-b", bob[0], "AUTH", ["read", "admin"]), batch="ab"))
    before = {a["id"] for a in oc.call(c, "GET", "/oracle/alerts").json()["alerts"]}
    view = oc.call(c, "GET", "/oracle/authority-ledger/collection/AUTH")
    assert view.status_code == 200, view.text
    assert set(view.json()["admins"]) == {alice[0], bob[0]} and view.json()["root"]
    r = oc.call(c, "PUT", "/oracle/settings/platform.authority_collection_id",
                json={"value": "AUTH"})
    assert r.status_code == 200, r.text
    new = [a for a in oc.call(c, "GET", "/oracle/alerts").json()["alerts"]
           if a["id"] not in before and a["kind"] == "platform_admin"]
    assert {a["subject"] for a in new} == {alice[0], bob[0]}


def test_an_unknown_authorities_id_is_not_pinned(custody_client, monkeypatch):
    af.operator(monkeypatch)
    r = oc.call(custody_client, "PUT", "/oracle/settings/platform.authority_collection_id",
                json={"value": f"nowhere-{uuid.uuid4().hex[:6]}"})
    assert r.status_code in (400, 404, 409) and "replica" in r.text


def test_a_bootstrap_s_admin_grants_are_one_summary_per_batch(custody_client, people,
                                                              monkeypatch):
    c = custody_client
    bob = people["bob"]
    af.operator(monkeypatch)
    boot = af.open_bootstrap(c)
    for n in range(3):
        cid = f"B{n}-{uuid.uuid4().hex[:4]}"
        af.ok(af.submit(c, boot, af.grant(f"g-{cid}", bob[0], cid, ["read", "admin"]),
                        bootstrap=True, batch=None))
    alerts = oc.call(c, "GET", "/oracle/alerts").json()["alerts"]
    admin = [a for a in alerts if a["kind"] == "admin_grant"]
    summary = [a for a in alerts if a["kind"] == "bootstrap_admin_summary"]
    assert admin == [] and len(summary) == 1 and "3" in summary[0]["detail"]
