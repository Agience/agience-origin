"""Review 26 at Origin.

H1. A non-person principal's whole master key (the platform user, the system principal, a
persona's principal) is split on no one's call. The operator grants `platform.custody` over each
such principal (`POST /oracle/job-grants` with `principal`), never over a person's key or a
collection's, and the split pass runs under it.

M1. The platform mail secrets, as Mantle now provisions them (members of a platform collection the
system principal administers, by a creation edge the bootstrap states), get the seed's seal
record and the operator's. Stated as roots, as before, they get neither.

L3. Whoever stored a collection key's first share may activate it.

L5. A persona's delegation makes ledger entries on the one path a persona's routes need: a new
member, by its creation edge, in a collection its person may create or add in, and its person's
creation grant on that member, in the same batch. Nothing else.

I3. Activation is refused off isolated production, and `verify_token` refuses an Origin-signed
token with no `exp`.
"""
from __future__ import annotations

import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review22_a_verdict_binds_the_sealed_copy as r22
from origin.tests import test_review23_only_a_credential_s_creator_records_its_seals as r23
from origin.tests import test_review25_a_persona_s_delegation_gets_a_bounded_reach_verdict as r25p
from origin.tests.test_background_work_runs_on_a_job_grant import _mint

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
ALL = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]
SECRET = "platform-mail-client-secret"
MAIL_COLL = "platform-mail-credentials"


# -- H1: the operator grants platform.custody over a non-person principal --------------------------

def _bootstrap_roots(c, ids):
    boot = af.open_bootstrap(c, ids=list(ids))
    for pid in ids:
        af.ok(af.submit(c, boot, af.root(pid), bootstrap=True, batch=None))


def test_the_operator_grants_custody_over_a_non_person_principal(custody_client, monkeypatch):
    from origin import service_identity

    c = custody_client
    af.operator(monkeypatch)
    system = "00000000-0000-0000-0000-00000000005e"
    platform_user = str(uuid.uuid5(uuid.NAMESPACE_URL, "agience://platform"))
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: system)
    _bootstrap_roots(c, [platform_user, "agience-server-lumen"])
    for principal in (platform_user, "agience-server-lumen"):
        r = oc.call(c, "POST", "/oracle/job-grants",
                    json={"job": "platform.custody", "hours": 2, "principal": principal})
        assert r.status_code == 200, r.text
        assert _mint(c, principal, "platform.custody").status_code == 200
        assert _mint(c, principal, "platform.reindex").status_code == 403


def test_the_operator_grants_no_job_over_a_person_or_a_collection(custody_client, monkeypatch):
    c = custody_client
    af.operator(monkeypatch)
    alice = af.person("Alice")
    af.ok(af.submit(c, alice[1], af.root(alice[0]), batch="a"))
    _bootstrap_roots(c, ["agience-server-lumen"])
    for principal, job in ((alice[0], "platform.custody"), ("ck:anything", "platform.custody"),
                           ("agience-server-lumen", "platform.reindex"), ("never-seen", "platform.custody")):
        r = oc.call(c, "POST", "/oracle/job-grants",
                    json={"job": job, "hours": 2, "principal": principal})
        assert r.status_code in (400, 403, 404), (principal, job, r.text)


# -- M1: the shape Mantle now provisions gets a seal record ----------------------------------------

def _mail_world(c, monkeypatch, *, under_collection: bool):
    operator = af.person("Operator")
    seed = r23._seed(c, monkeypatch)
    ids = [SECRET, "g-op-secret", "g-sys-secret", MAIL_COLL, "g-sys-coll", "g-op-coll"]
    boot = af.open_bootstrap(c, ids=ids)
    if under_collection:
        af.ok(af.submit(c, boot, af.root(MAIL_COLL), bootstrap=True, batch=None))
        af.ok(af.submit(c, boot, af.grant("g-op-coll", operator[0], MAIL_COLL, ALL),
                        bootstrap=True, batch=None))
        af.ok(af.submit(c, boot, af.grant("g-sys-coll", r23.SYSTEM, MAIL_COLL, ["admin"]),
                        bootstrap=True, batch=None))
        af.ok(af.submit(c, boot, af.edge(MAIL_COLL, SECRET), bootstrap=True, batch=None))
    else:
        af.ok(af.submit(c, boot, af.root(SECRET), bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.grant("g-op-secret", operator[0], SECRET,
                                      ["read", "update", "invoke", "admin"]),
                    bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.grant("g-sys-secret", r23.SYSTEM, SECRET, ["invoke"]),
                    bootstrap=True, batch=None))
    return operator, seed


def test_the_provisioned_mail_secret_gets_the_seed_s_and_the_operator_s_record(unsealed_world,
                                                                               monkeypatch):
    c, _alice, _bob = unsealed_world
    operator, seed = _mail_world(c, monkeypatch, under_collection=True)
    r = r22.record(c, seed, cred=SECRET)
    assert r.status_code == 200, r.text
    assert r22.record(c, operator[1], cred=SECRET).status_code == 200


def test_a_mail_secret_stated_as_a_root_still_gets_no_seed_record(unsealed_world, monkeypatch):
    c, _alice, _bob = unsealed_world
    _operator, seed = _mail_world(c, monkeypatch, under_collection=False)
    assert r22.record(c, seed, cred=SECRET).status_code == 403


# -- L3 and I3: activation --------------------------------------------------------------------------

def _activate(c, principal, credential):
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/activate")
    return c.post(f"/internal/key-shares/{principal}/activate",
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def test_whoever_stored_a_collection_key_s_first_share_may_activate_it(custody_client):
    c = custody_client
    alice, bob, carol = af.person("Alice"), af.person("Bob"), af.person("Carol")
    af.ok(af.submit(c, alice[1], af.root("K"), batch="a"))
    af.ok(af.submit(c, alice[1], af.grant("g-k", alice[0], "K", ALL), batch="a"))
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read"]), batch="b"))
    af.ok(af.submit(c, alice[1], af.grant("g-ck", carol[0], "K", ["read"]), batch="c"))
    assert af.store_share(c, "ck:K", credential=bob[1]).status_code == 200   # a reader stores it
    assert _activate(c, "ck:K", carol[1]).status_code == 403                 # another reader
    assert _activate(c, "ck:K", bob[1]).status_code == 200                   # its storer


def test_activation_is_refused_off_isolated_production(custody_client, monkeypatch):
    from origin.services import custody_plane

    c = custody_client
    alice = af.person("Alice")
    af.ok(af.submit(c, alice[1], af.root(alice[0]), batch="a"))
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    monkeypatch.setattr(custody_plane, "TEST_OVERRIDE", None)
    monkeypatch.setenv("AGIENCE_PLANE", "home")
    assert _activate(c, alice[0], alice[1]).status_code == 403


def test_an_origin_signed_token_with_no_exp_is_no_token(custody_client):
    from jose import jwt as jose_jwt

    from origin import config
    from origin.services import auth_service as a
    from origin.services.auth_verifier import verify_token

    claims = {"iss": config.AUTHORITY_ISSUER, "sub": str(uuid.uuid4()),
              "aud": config.AUTHORITY_ISSUER}
    def signed(c):
        return jose_jwt.encode(c, a.get_private_key_pem(), algorithm=a.JWT_ALGORITHM,
                               headers={"kid": a.get_key_id()})
    assert verify_token(a.create_jwt_token(dict(claims))) is not None     # the same, with exp
    assert verify_token(signed(claims)) is None


# -- L5: a persona's delegation makes the entries a persona's routes need --------------------------

@pytest.fixture()
def notes(custody_client):
    """Bob's notes collection, his own; Alice's shelf, where Bob holds Read only."""
    c = custody_client
    alice, bob = af.person("Alice"), af.person("Bob")
    af.ok(af.submit(c, bob[1], af.root("notes-b"), batch="n"))
    af.ok(af.submit(c, bob[1], af.grant("g-nb", bob[0], "notes-b", ALL), batch="n"))
    af.ok(af.submit(c, alice[1], af.root("shelf-a"), batch="s"))
    af.ok(af.submit(c, alice[1], af.grant("g-sa", alice[0], "shelf-a", ALL), batch="s"))
    af.ok(af.submit(c, alice[1], af.grant("g-sab", bob[0], "shelf-a", ["read"]), batch="s2"))
    return c, alice, bob


def test_a_persona_creates_a_note_for_its_person(notes, unsealed_world):
    c, _alice, bob = notes
    persona = r25p._narrowed(bob[0])
    r = af.submit(c, persona, af.edge("notes-b", "note-1"), batch="p", via_session=False)
    assert r.status_code == 200, r.text
    r = af.submit(c, persona, af.grant("g-note-1", bob[0], "note-1", ALL), batch="p",
                  via_session=False)
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("entry", [
    af.edge("shelf-a", "note-2"),                                  # where its person only reads
    af.grant("g-share", "someone-else", "notes-b", ["read"]),      # a share
    af.grant("g-deny", "someone-else", "notes-b", ["read"], effect="deny"),
    af.unedge("notes-b", "note-0"),
    af.root("a-new-root"),
])
def test_a_persona_makes_nothing_else(notes, unsealed_world, entry):
    c, _alice, bob = notes
    persona = r25p._narrowed(bob[0])
    r = af.submit(c, persona, entry, batch="q", via_session=False)
    assert r.status_code == 403, r.text
