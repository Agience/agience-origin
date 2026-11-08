# ruff: noqa: F811 — `world` and `system` are pytest fixtures, imported and named as parameters
"""Review 11's ledger cases (2026-11-02), each refused on Origin's own rules.

H1  Delete stands alone: it retires no deny and no one's grant on a resource that stays; only
    with the resource deleted (its creation edge removed) in the same batch.
M3  A deny on a collection holds against every path to its key, a member's Read included.
M6  The first drop key needs Read and Admin on the collection: only a holder of its key can derive
    it.
    A withdrawal by its own actor re-checks what they hold now.
    The pinned Authorities collection is never retired, and a creation grant on it alerts.
    Derived ids follow an address change, and one someone else registered alerts.
    retire_root clears a planted deny; a seed credential writes one batch.
    Ember: no share at all, and no memory collection; only members created in it.
"""
from __future__ import annotations

import base64
import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, _grant_row, system, world)

custody_client = _shares.custody_client


def _alerts():
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        return authority_ledger.alerts(db, include_acknowledged=True)


# -- H1 -------------------------------------------------------------------------------------------

def test_a_delete_holder_lifts_no_deny_on_a_resource_that_stays(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    bob_id, bob = world["bob"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "S")))
    af.ok(af.submit(c, alice, af.grant("g-as", alice_id, "S", ALL)))
    af.ok(af.submit(c, alice, af.grant("g-deny", bob_id, "S", ["read"], effect="deny")))
    af.store_share(c, "ck:S")
    af.ok(af.submit(c, alice, af.grant("g-cdel", carol_id, "W", ["delete"])))
    r = af.submit(c, carol, af.grant("g-deny", bob_id, "S", ["read"], effect="deny",
                                     state="deleted"), batch=None)
    assert r.status_code == 403, r.text
    assert af.release(c, "ck:S", bob, collection="S").status_code == 403


def test_a_delete_holder_retires_no_one_s_grant_on_a_resource_that_stays(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.grant("g-cdel2", carol_id, "W", ["delete"])))
    r = af.submit(c, carol, af.grant("g-aw", alice_id, "W", ALL, state="deleted"), batch=None)
    assert r.status_code == 403, r.text


def test_deleting_a_resource_retires_its_grants_in_the_same_batch(custody_client, world):
    """Control: the deletion itself (its creation edge removed) then its grants, one batch."""
    c = custody_client
    alice_id, alice = world["alice"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "S3")))
    af.ok(af.submit(c, alice, af.grant("g-as3", alice_id, "S3", ALL)))
    af.ok(af.submit(c, alice, af.grant("g-cdel3", carol_id, "W", ["delete"])))
    af.ok(af.submit(c, carol, af.unedge("W", "S3"), batch="del"))
    r = af.submit(c, carol, af.grant("g-as3", alice_id, "S3", ALL, state="deleted"), batch="del")
    assert r.status_code == 200, r.text


# -- M3 -------------------------------------------------------------------------------------------

def test_a_deny_on_a_collection_holds_against_a_member_read(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.edge("W", "S2")))
    af.ok(af.submit(c, alice, af.grant("g-as2", alice_id, "S2", ALL)))
    af.ok(af.submit(c, alice, af.edge("S2", "A1")))
    af.ok(af.submit(c, alice, af.grant("g-aa1", alice_id, "A1", ALL)))
    af.ok(af.submit(c, alice, af.grant("g-cr", carol_id, "A1", ["read"])))
    af.ok(af.submit(c, alice, af.grant("g-cd", carol_id, "S2", ["read"], effect="deny")))
    af.store_share(c, "ck:S2")
    assert af.release(c, "ck:S2", carol, collection="S2").status_code == 403
    assert af.release(c, "ck:S2", carol, collection="S2", artifact="A1").status_code == 403


# -- withdrawal re-checks the actor ---------------------------------------------------------------

def test_a_withdrawal_after_losing_admin_restores_nothing(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    bob_id, bob = world["bob"]
    carol_id, carol = world["carol"]
    af.ok(af.submit(c, alice, af.grant("g-cadm", carol_id, "W", ["admin"])))
    rev = af.ok(af.submit(c, carol, af.grant("g-bw", bob_id, "W", ["read", "share"],
                                             state="revoked")))
    af.ok(af.submit(c, alice, af.grant("g-cadm", carol_id, "W", ["admin"], state="revoked")))
    r = af.submit(c, carol, af.grant("g-bw", bob_id, "W", ["read", "share"], state="retired"),
                  compensates=rev["seq"], batch=None)
    assert r.status_code == 403, r.text
    assert _grant_row("g-bw").state == "revoked"


def test_a_withdrawal_by_an_admin_who_still_holds_it_restores(custody_client, world):
    """Control: the actor still holds what made the change (Delete), so undoing their own failed
    deletion stands."""
    c = custody_client
    alice_id, alice = world["alice"]
    gone = af.deleted_member(c, alice, alice_id, "W", "m-11c", "g-11c")
    af.ok(af.submit(c, alice, af.grant("g-11c", alice_id, "m-11c", ["read", "update", "delete"],
                                       state="retired"), compensates=gone["seq"], batch=None,
                    via_session=False))
    assert _grant_row("g-11c").state == "active"


# -- M6 -------------------------------------------------------------------------------------------


# -- the pinned Authorities collection -----------------------------------------------------------

@pytest.fixture
def pinned(monkeypatch):
    from origin.services.platform_settings_service import settings as platform_settings
    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw:
                        "AUTH" if k == "platform.authority_collection_id"
                        else real_get(k, *a, **kw))


def test_the_pinned_authorities_collection_is_never_retired(custody_client, world, pinned):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.root("AUTH")))
    af.ok(af.submit(c, alice, af.grant("g-auth", alice_id, "AUTH", ALL)))
    with SessionLocal() as db, pytest.raises(authority_ledger.EntryRefused, match="re-pin"):
        authority_ledger.retire_root(db, "AUTH", af.OPERATOR, "planted")


def test_a_creation_grant_on_the_pinned_collection_alerts(custody_client, world, pinned):
    c = custody_client
    alice_id, alice = world["alice"]
    before = len(_alerts())
    af.ok(af.submit(c, alice, af.root("AUTH")))
    af.ok(af.submit(c, alice, af.grant("g-auth", alice_id, "AUTH", ALL)))
    new = _alerts()[before:]
    assert any(a["kind"] == "platform_admin" and a["subject"] == alice_id for a in new), new


# -- derived ids ----------------------------------------------------------------------------------

def test_derived_ids_follow_an_address_change(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.models.person import Person
    from origin.services import authority_ledger
    c = custody_client
    alice_id, _alice = world["alice"]
    _carol_id, carol = world["carol"]
    ns = uuid.uuid5(uuid.NAMESPACE_DNS, "ember.agience.ai")
    with SessionLocal() as db:
        authority_ledger.derived_owner(db, "x")                       # warm the cache
        p = db.get(Person, uuid.UUID(alice_id))
        p.email = f"alice-{uuid.uuid4().hex[:6]}@team.test"
        new_email = p.email
        db.commit()
    lc = str(uuid.uuid5(ns, f"local-collection:{new_email}"))
    r = af.submit(c, carol, af.root(lc), batch=None)
    assert r.status_code == 403 and "derived" in r.text, r.text


def test_an_id_squatted_before_its_person_exists_alerts(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    c = custody_client
    _carol_id, carol = world["carol"]
    email = f"future-{uuid.uuid4().hex[:6]}@team.test"
    ns = uuid.uuid5(uuid.NAMESPACE_DNS, "ember.agience.ai")
    squat = str(uuid.uuid5(ns, f"local-collection:{email}"))
    af.ok(af.submit(c, carol, af.root(squat), batch=None))           # no such person yet
    newcomer, _tok = af.person("New", email=email)
    with SessionLocal() as db:
        authority_ledger.derived_owner(db, "x")
    assert any(a["kind"] == "derived_id_squatted" and a["resource_id"] == squat
               and a["subject"] == newcomer for a in _alerts())


# -- retire_root and seed batches -----------------------------------------------------------------

def test_retire_root_clears_a_planted_deny(custody_client, world, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    from origin.services import authority_ledger
    c = custody_client
    mal_id, mal = world["carol"]
    bob_id, _bob = world["bob"]
    af.operator(monkeypatch)
    squat = f"squat-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, mal, af.root(squat), batch="m"))
    af.ok(af.submit(c, mal, af.grant("g-m", mal_id, squat, ALL), batch="m"))
    af.ok(af.submit(c, mal, af.grant("g-mdeny", bob_id, squat, ["read"], effect="deny"),
                    batch="m2"))
    with SessionLocal() as db:
        authority_ledger.retire_root(db, squat, af.OPERATOR, "planted")
        assert db.get(AuthorityGrant, "g-mdeny").state != "active"


def test_a_seed_credential_writes_one_batch(custody_client, world, monkeypatch):
    from origin import service_identity
    from origin.tests import operator_console_fixtures as oc
    c = custody_client
    alice_id, alice = world["alice"]
    af.operator(monkeypatch)
    sys_id = "00000000-0000-0000-0000-00000000005e"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: sys_id)
    seed = oc.call(c, "POST", "/oracle/seed-credential", json={"minutes": 10})
    assert seed.status_code == 200, seed.text
    tok = seed.json()["token"]
    af.ok(af.submit(c, alice, af.grant("g-sys", sys_id, "W", ["admin", "read"])))
    first = af.submit(c, tok, af.grant("g-seed1", alice_id, "W", ["read"], state="revoked"),
                      batch="one")
    assert first.status_code in (200, 403), first.text
    if first.status_code == 200:
        r = af.submit(c, tok, af.grant("g-seed2", alice_id, "W", ["read"], state="revoked"),
                      batch="two")
        assert r.status_code == 403 and "one batch" in r.text, r.text


# -- Ember ----------------------------------------------------------------------------------------

def _ember(c, monkeypatch, token):
    from origin import config
    from origin.tests.test_the_eighth_review_s_sign_in_cases import _exchange
    monkeypatch.setattr(config, "NARROW_AUDIENCES", {"ember": ["ember:memory", "ember:read"]},
                        raising=False)
    r = _exchange(c, token, "ember")
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_ember_makes_no_memory_collection_no_drop_key_and_no_share(custody_client,
                                                                   monkeypatch):
    from origin.services import authority_ledger
    c = custody_client
    ada, tok = af.person("Ada")
    bob, _ = af.person("Bob")
    e = _ember(c, monkeypatch, tok)
    mid = authority_ledger.memory_collection_id(ada)
    assert af.submit(c, e, af.root(mid), batch="e").status_code == 403
    af.ok(af.submit(c, tok, af.root(mid), batch="own"))               # the person makes it
    af.ok(af.submit(c, tok, af.grant(f"g-{mid}", ada, mid, ALL), batch="own"))
    pub = base64.b64encode(b"\x09" * 32).decode()
    assert af.submit(c, e, {"kind": "drop_key", "collection_id": mid, "public": pub},
                     batch=None).status_code == 403
    member = f"mem-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, e, af.edge(mid, member), batch="n"))           # a memory, created in it
    af.ok(af.submit(c, e, af.grant(f"g-{member}", ada, member, ["read", "update", "delete"]),
                    batch="n"))
    from datetime import datetime, timedelta, timezone
    later = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert af.submit(c, e, af.grant("g-share", bob, member, ["read"], expires_at=later),
                     batch=None).status_code == 403
