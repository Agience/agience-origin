"""Review 23, M1 and M2, as review 24 settles them: who records a credential's seals.

The operator's seed credential, handed to Mantle for one seed pass, recorded seals for any
credential, and a record replaces the one before it, so Mantle could have a person's next verdict
name a copy Mantle sealed. A seed now records seals only for a credential the platform system
principal wrote. Anyone else records them only while they may update the credential (review 24,
`test_review24_seals_are_recorded_on_current_authority.py`).

M2: Mantle records a new credential's seals after its creation edge is at Origin, so a person's new
credential gets a verdict.
"""
from __future__ import annotations

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review22_a_verdict_binds_the_sealed_copy as r22

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
SYSTEM = "00000000-0000-0000-0000-00000000aaaa"


def _seed(c, monkeypatch, plan=()):
    from origin import service_identity
    from origin.services.authority_ledger import body_digest
    from origin.tests import operator_console_fixtures as oc

    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: SYSTEM)
    af.operator(monkeypatch)
    seed = oc.call(c, "POST", "/oracle/seed-credential",
                   json={"minutes": 10, "plan": [body_digest(e) for e in plan]})
    assert seed.status_code == 200, seed.text
    return seed.json()["token"]


def test_a_seed_credential_never_replaces_a_person_s_seal_record(unsealed_world, monkeypatch):
    c, alice, bob = unsealed_world
    assert r22.record(c, alice[1]).status_code == 200
    seed = _seed(c, monkeypatch)
    assert r22.record(c, seed, sealed={"iris": "c" * 64}).status_code == 403
    claims = jose_jwt.get_unverified_claims(r21._ask(c, r21._delegation(bob[0])).json()["verdict"])
    assert claims["sealed_sha256"] == r22.SEALED


def test_a_seed_records_seals_for_a_credential_it_wrote(unsealed_world, monkeypatch):
    c, alice, _bob = unsealed_world
    seed = _seed(c, monkeypatch, plan=[af.edge(r21.SHELF, "platform-cred")])
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, r21.SHELF, ["create", "add"]),
                    batch="sys"))
    r = af.submit(c, seed, af.edge(r21.SHELF, "platform-cred"), batch="seed")
    assert r.status_code == 200, r.text
    assert r22.record(c, seed, cred="platform-cred").status_code == 200


def test_a_contributor_without_update_records_no_seals(unsealed_world):
    """Carol may write into the shelf but not update what is there (review 24: a record needs
    Update now); the shelf's Admin may."""
    c, alice, _bob = unsealed_world
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, ["create", "add"]),
                    batch="c"))
    af.ok(af.submit(c, carol[1], af.edge(r21.SHELF, "carol-cred"), batch="c2"))
    assert r22.record(c, carol[1], cred="carol-cred").status_code == 403
    assert r22.record(c, alice[1], cred="carol-cred").status_code == 200


def test_a_person_s_new_credential_gets_a_verdict(unsealed_world):
    """M2: the record made once the creation edge is at Origin, as Mantle now makes it."""
    c, alice, bob = unsealed_world
    assert r22.record(c, alice[1], cred="cred-new").status_code == 403       # before its edge
    af.ok(af.submit(c, alice[1], af.edge(r21.SHELF, "cred-new"), batch="late"))
    assert r22.record(c, alice[1], cred="cred-new").status_code == 200
    from origin.services.authority_ledger import canonical
    import hashlib
    body = {"credential_id": "cred-new", "card_id": r21.CARD, "nonce": "n" * 32}
    tok = r21._shares._token("POST", "-", htu=r21.PATH,
                             body_sha256=hashlib.sha256(canonical(body).encode()).hexdigest())
    r = r21._ask(c, r21._delegation(bob[0]), body=body, token=tok)
    assert r.status_code == 200, r.text
