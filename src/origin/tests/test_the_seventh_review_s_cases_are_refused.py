"""The seventh review's ledger cases (2026-11-02), each refused on Origin's own rules.

F5   A withdrawal on a background or operator credential only narrows: it never makes a grant
     more live than it is. Restoring a wider state is the entry's own actor's, on its own
     credential, within its window.
F6   A creator's own creation grant, in its creating batch, raises no alert; every other grant
     carrying Admin does.
F9   Platform admin counts only grants to a person.
F10  The bootstrap credential marks for re-key only the shares its window lists.
F11  Every id Mantle derives from a person's id is that person's alone.
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
def world(custody_client):
    c = custody_client
    people = {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob", "mal")}
    a = people["alice"][1]
    af.ok(af.submit(c, a, af.root("W")))
    af.ok(af.submit(c, a, af.grant("g-aw", people["alice"][0], "W", ALL)))
    af.ok(af.submit(c, a, af.grant("g-bw", people["bob"][0], "W", ["read"]), batch="b2"))
    return people


@pytest.fixture
def system(custody_client, monkeypatch):
    from origin import service_identity

    sys_id = "00000000-0000-0000-0000-00000000aaaa"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: sys_id)
    # Its job grant lists W: a background retry acts only within those collections (review 16).
    return sys_id, af.background(sys_id, collections=("W",))


def _row(gid):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant

    with SessionLocal() as db:
        r = db.get(AuthorityGrant, gid)
        return None if r is None else (r.state, r.actions)


# -- F5 -------------------------------------------------------------------------------------------

def test_f5_a_background_withdrawal_does_not_restore_a_revoked_grant(custody_client, world,
                                                                     system):
    c = custody_client
    alice, bob = world["alice"], world["bob"]
    rev = af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["read"], state="revoked"),
                          batch="rev"))
    _sys, tok = system
    r = af.submit(c, tok, af.grant("g-bw", bob[0], "W", ["read"], state="retired"),
                  compensates=rev["seq"], batch=None)
    assert r.status_code == 403, r.text
    assert _row("g-bw")[0] == "revoked"


def test_f5_a_background_withdrawal_still_narrows(custody_client, world, system):
    """A secondary edge Mantle added and never confirmed is withdrawn by the system principal's
    retry. A creation edge is not: removing it would delete the member at Origin, so an
    unconfirmed one is the operator's to resolve (review 16). (A grant is made in the person's
    Origin session since review 12, confirmed when appended.)"""
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEdge
    c = custody_client
    alice = world["alice"]
    created = af.ok(af.submit(c, alice[1], af.edge("W", "m-f5"), batch="wide"))
    _sys, tok = system
    r = af.submit(c, tok, af.unedge("W", "m-f5"), compensates=created["seq"], batch=None)
    assert r.status_code == 403 and "operator" in r.text, r.text
    af.ok(af.submit(c, alice[1], af.root("Y-f5"), batch="y"))
    af.ok(af.submit(c, alice[1], af.grant("g-y-f5", alice[0], "Y-f5", ALL), batch="y"))
    wide = af.ok(af.submit(c, alice[1], af.edge("W", "Y-f5", origin=False), batch="wide2"))
    r = af.submit(c, tok, af.unedge("W", "Y-f5"), compensates=wide["seq"], batch=None)
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        assert db.get(AuthorityEdge, ("W", "Y-f5")) is None


def test_f5_the_actor_s_own_withdrawal_restores_within_its_window(custody_client, world):
    c = custody_client
    alice = world["alice"]
    gone = af.deleted_member(c, alice[1], alice[0], "W", "m-f5b", "g-f5b")
    af.ok(af.submit(c, alice[1], af.grant("g-f5b", alice[0], "m-f5b",
                                          ["read", "update", "delete"], state="retired"),
                    compensates=gone["seq"], batch=None, via_session=False))
    assert _row("g-f5b")[0] == "active"                         # her failed write, undone


# -- F6 -------------------------------------------------------------------------------------------

def test_f6_no_alert_for_a_creation_grant_an_alert_for_every_other_admin_grant(
        custody_client, world, monkeypatch):
    c = custody_client
    af.operator(monkeypatch)
    alice, bob = world["alice"], world["bob"]
    af.ok(af.submit(c, alice[1], af.grant("g-bw2", bob[0], "W", ["read", "admin"]), batch="x"))
    alerts = oc.call(c, "GET", "/oracle/alerts").json()["alerts"]
    subjects = {(a["kind"], a["subject"]) for a in alerts}
    assert ("admin_grant", bob[0]) in subjects
    assert ("admin_grant", alice[0]) not in subjects            # her own creation grant


# -- F9 -------------------------------------------------------------------------------------------

def test_f9_a_non_person_grantee_makes_no_platform_admin(custody_client, world, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.routers import authority_router
    from origin.services.platform_settings_service import settings as ps

    real = ps.get
    monkeypatch.setattr(ps, "get", lambda k, *a, **kw: "W" if k ==
                        "platform.authority_collection_id" else real(k, *a, **kw))
    c = custody_client
    alice, mal = world["alice"], world["mal"]
    af.ok(af.submit(c, alice[1], af.grant("g-mal", mal[0], "W", ["admin"],
                                          grantee_type="service"), batch="m"))
    with SessionLocal() as db:
        assert authority_router._platform_admin(db, mal[0]) is False
        assert authority_router._platform_admin(db, alice[0]) is True


# -- F10 ------------------------------------------------------------------------------------------

def _mark(c, principal, credential):
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/rekey-pending")
    return c.post(f"/internal/key-shares/{principal}/rekey-pending",
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def test_f10_a_bootstrap_credential_marks_only_the_shares_its_window_lists(custody_client,
                                                                          monkeypatch):
    c = custody_client
    af.operator(monkeypatch)
    alice = af.person("alice")
    for cid in ("K1", "K2"):
        af.ok(af.submit(c, alice[1], af.root(cid), batch=cid))
        af.ok(af.submit(c, alice[1], af.grant(f"g-{cid}", alice[0], cid, ALL), batch=cid))
        assert af.store_share(c, f"ck:{cid}", alice[1]).status_code == 200
    unlisted = af.open_bootstrap(c)
    assert _mark(c, "ck:K1", unlisted).status_code == 403          # a window with no list
    listed = af.open_bootstrap(c, ids=["K1"])
    assert _mark(c, "ck:K1", listed).status_code == 200
    assert _mark(c, "ck:K2", listed).status_code == 403


# -- F11 ------------------------------------------------------------------------------------------

def _forms(person, email):
    from prism.trust import service_identity
    ember = uuid.uuid5(uuid.NAMESPACE_DNS, "ember.agience.ai")
    ident = uuid.uuid5(uuid.NAMESPACE_DNS, "artifact-identity.mantle.agience.ai")
    out = [uuid.uuid5(uuid.NAMESPACE_URL, f"agience://person/{person}"),
           uuid.uuid5(uuid.NAMESPACE_URL, f"agience://person/{person}/own"),
           uuid.uuid5(uuid.NAMESPACE_URL, f"agience://workspace/inbox/{person}"),
           uuid.uuid5(uuid.NAMESPACE_URL, f"agience://observations/{person}"),
           uuid.uuid5(ember, f"local-collection:{person}"),
           uuid.uuid5(ember, f"local-collection:{email}"),
           uuid.uuid5(ident, f"{person}\nember:memory")]
    ns = service_identity.get_instance_namespace()
    if ns is not None:
        out.append(uuid.uuid5(ns, f"user/{person}"))
    return [str(u) for u in out]


def test_f11_every_id_derived_from_a_person_is_theirs_alone(custody_client, world):
    c = custody_client
    alice, mal = world["alice"], world["mal"]
    af.ok(af.submit(c, mal[1], af.root("M"), batch="m"))
    af.ok(af.submit(c, mal[1], af.grant("g-mm", mal[0], "M", ALL), batch="m"))
    for node in _forms(alice[0], "alice@team.test"):
        r = af.submit(c, mal[1], af.root(node), batch=None)
        assert r.status_code == 403 and "derived" in r.text, (node, r.text)
        r = af.submit(c, mal[1], af.edge("M", node), batch=None)        # his own collection
        assert r.status_code == 403 and "derived" in r.text, (node, r.text)
        assert af.submit(c, alice[1], af.root(node), batch=None).status_code == 200


def test_f11_origin_s_forms_are_mantle_s(custody_client):
    """The list Origin checks is the derivations Mantle uses, computed by Mantle's own code."""
    mantle = pytest.importorskip("mantle")  # noqa: F841
    from mantle.events.observation import observations_container_id
    from mantle.services.artifact_identity import derive_artifact_id
    from mantle.services.seed_provisioning import user_provisioning as up
    from mantle.shard.local_collection import local_collection_id

    from origin.services import authority_ledger as al

    p = str(uuid.uuid4())
    got = set(al.derived_ids(p, email="p@x.test"))
    for want in (up.person_artifact_id(p), str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                          f"agience://person/{p}/own")),
                 up.inbox_workspace_id(p), observations_container_id(p),
                 local_collection_id(p), local_collection_id("p@x.test"),
                 derive_artifact_id(p, "ember:memory")):
        assert want in got, want
