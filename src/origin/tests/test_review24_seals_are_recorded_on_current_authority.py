"""Review 24, M1: a seal record is kept from a subject who may update the credential now.

Round 23 kept a record from the credential's creator, whatever they held on it later. A creator
the collection's Admin had since revoked and denied still recorded seals, on the token for Mantle
the web app hands Mantle, so Mantle chose the endpoint digests Bob's next verdict named. A record
is now kept only from a subject who reaches the credential for Update now, by Origin's own walk,
with no deny on Update anywhere up its creation chain. A seed counts only for a credential the
platform system principal wrote. An Admin may reseal after a rotation.
"""
from __future__ import annotations

import hashlib

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review22_a_verdict_binds_the_sealed_copy as r22

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
RIGHTS = ["create", "read", "update", "add"]


def _mantle_token(person_id):
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import issue_mantle_token

    with SessionLocal() as db:
        return issue_mantle_token(db_persons.get_by_id(db, person_id), client_id="agience-client")


def _verdict_for(c, bob, credential):
    from origin.services.authority_ledger import canonical

    body = {"credential_id": credential, "card_id": r21.CARD, "nonce": hashlib.sha256(
        credential.encode()).hexdigest()[:32]}
    tok = r21._shares._token("POST", "-", htu=r21.PATH,
                             body_sha256=hashlib.sha256(canonical(body).encode()).hexdigest())
    return r21._ask(c, r21._delegation(bob[0]), body=body, token=tok)


def test_a_revoked_and_denied_creator_records_no_seals(unsealed_world):
    c, alice, bob = unsealed_world
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, RIGHTS), batch="c"))
    af.ok(af.submit(c, carol[1], af.edge(r21.SHELF, "team-cred"), batch="c2"))
    assert r22.record(c, carol[1], cred="team-cred").status_code == 200
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, RIGHTS,
                                          state="revoked"), batch="c3"))
    af.ok(af.submit(c, alice[1], af.grant("d-carol", carol[0], r21.SHELF,
                                          ["read", "update", "invoke", "admin"], effect="deny"),
                    batch="c4"))
    r = r22.record(c, _mantle_token(carol[0]), cred="team-cred", sealed={"iris": "d" * 64},
                   endpoints="e" * 64)
    assert r.status_code == 403
    # Her earlier record no longer stands either (review 25): no verdict until one who may
    # update the credential reseals it.
    assert _verdict_for(c, bob, "team-cred").status_code == 403
    assert r22.record(c, alice[1], cred="team-cred").status_code == 200
    v = _verdict_for(c, bob, "team-cred")
    assert v.status_code == 200, v.text
    claims = jose_jwt.get_unverified_claims(v.json()["verdict"])
    assert (claims["sealed_sha256"], claims["endpoints_sha256"]) == (r22.SEALED, r22.ENDPOINTS)


def test_a_deny_on_update_up_the_chain_holds_against_her_grant(unsealed_world):
    c, alice, _bob = unsealed_world
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, RIGHTS), batch="c"))
    af.ok(af.submit(c, carol[1], af.edge(r21.SHELF, "team-cred"), batch="c2"))
    af.ok(af.submit(c, alice[1], af.grant("d-carol", carol[0], r21.SHELF, ["update"],
                                          effect="deny"), batch="c3"))
    assert r22.record(c, carol[1], cred="team-cred").status_code == 403


def test_an_admin_reseals_after_a_rotation(unsealed_world):
    """The shelf's Admin may update a credential Carol wrote, so records its new seals."""
    c, alice, _bob = unsealed_world
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, RIGHTS), batch="c"))
    af.ok(af.submit(c, carol[1], af.edge(r21.SHELF, "team-cred"), batch="c2"))
    assert r22.record(c, alice[1], cred="team-cred").status_code == 200


def test_invoke_alone_records_nothing(unsealed_world):
    c, _alice, bob = unsealed_world
    assert r22.record(c, bob[1]).status_code == 403
