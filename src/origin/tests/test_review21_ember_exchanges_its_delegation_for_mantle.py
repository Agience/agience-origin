"""Ember calls Mantle on a delegation addressed to Mantle, from its own exchange at Origin (review
21, F6).

Ember forwarded the delegation it was sent (`aud` `ember`) to Mantle, so Mantle could replay it at
Ember. Ember now exchanges it at the token endpoint (RFC 8693), with its own account's token as the
actor (`actor_token`), for the same person's delegation addressed to Mantle: `aud` `mantle`, actor
`ember`, Ember's scopes and no more, never longer than the one it came from, recorded as a hop, and
never exchanged again. Ember takes only `aud` `ember`, so this one opens nothing there. It acts at
Origin as Ember's narrowed delegation does (it releases no key).
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"
SCOPES = ["ember:memory", "ember:read"]


def _ember_account():
    """Ember's own Origin account, and its access token as Origin issues it (narrowed to Ember)."""
    from origin.db.session import SessionLocal
    from origin.services import service_accounts
    from origin.services.auth_service import create_jwt_token

    pid, _ = af.person("Ember")
    with SessionLocal() as db:
        service_accounts.mark(db, pid, "ember")
        db.commit()
    return create_jwt_token({"sub": pid})


def _for_ember(person_id):
    from origin.services.auth_service import issue_narrow_delegation
    return issue_narrow_delegation(person_id, "ember", SCOPES)


def _exchange(c, subject, actor, audience="mantle"):
    form = {"grant_type": TOKEN_EXCHANGE, "subject_token": subject,
            "subject_token_type": ACCESS, "audience": audience}
    if actor is not None:
        form["actor_token"] = actor
    return c.post("/auth/token", data=form)


def test_ember_gets_the_person_s_delegation_addressed_to_mantle(custody_client):
    from jose import jwt as jose_jwt

    c = custody_client
    alice = af.person("Alice")
    subject = _for_ember(alice[0])
    r = _exchange(c, subject, _ember_account())
    assert r.status_code == 200, r.text
    got = jose_jwt.get_unverified_claims(r.json()["access_token"])
    came = jose_jwt.get_unverified_claims(subject)
    assert (got["aud"], got["act"], got["sub"]) == ("mantle", {"sub": "ember"}, alice[0])
    assert got["narrowed"] is True and set(got["scope"].split()) == set(SCOPES)
    assert got["exp"] <= came["exp"] and got["hop"] == {"from": "ember", "jti": came["jti"]}


def test_it_acts_at_origin_as_ember_s_delegation(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    alice = af.person("Alice")
    tok = _exchange(custody_client, _for_ember(alice[0]), _ember_account()).json()["access_token"]
    with SessionLocal() as db:
        cred = share_credentials.verify_share_credential(db, tok)
    assert cred.kind == "narrowed" and cred.subject == alice[0]


@pytest.mark.parametrize("actor", ["none", "person", "another-account"])
def test_only_ember_s_own_account_exchanges_it(custody_client, actor):
    from origin.db.session import SessionLocal
    from origin.services import service_accounts
    from origin.services.auth_service import create_jwt_token

    alice = af.person("Alice")
    if actor == "none":
        token = None
    elif actor == "person":
        token = af.person("Bob")[1]
    else:
        pid, _ = af.person("Lumen")
        with SessionLocal() as db:
            service_accounts.mark(db, pid, "lumen")
            db.commit()
        token = create_jwt_token({"sub": pid})
    assert _exchange(custody_client, _for_ember(alice[0]), token).status_code in (400, 401, 403)


def test_the_result_is_not_exchanged_again_and_nothing_else_becomes_one(custody_client):
    c = custody_client
    alice = af.person("Alice")
    ember = _ember_account()
    once = _exchange(c, _for_ember(alice[0]), ember).json()["access_token"]
    assert _exchange(c, once, ember).status_code in (400, 401, 403)
    assert _exchange(c, alice[1], ember).status_code in (400, 401, 403)     # a person's own
    assert _exchange(c, _for_ember(alice[0]), ember, audience="origin").status_code in (
        400, 401, 403)
