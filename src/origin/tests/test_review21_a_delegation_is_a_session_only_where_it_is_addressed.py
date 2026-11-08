"""At Origin, a delegation is a bearer only when it is addressed to Origin (review 21, F5).

A person's delegation Origin issued to a persona or to Mantle stood for that person at every
Origin route behind `get_auth`, as their own session would: a holder of one addressed to
`agience-server-iris` read the person's account at `/auth/userinfo`. Origin now takes a
non-narrowed delegation as a bearer only with `aud` its own issuer or `origin`. A narrowed one
still opens only the routes that list it.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


def _userinfo(c: TestClient, token: str) -> int:
    return c.get("/auth/userinfo", headers={"Authorization": f"Bearer {token}"}).status_code


def test_a_delegation_addressed_to_another_service_is_no_session(custody_client):
    from origin.services.auth_service import issue_delegation_token

    alice = af.person("Alice")
    for aud in ("agience-server-iris", "mantle", "ember-not-narrowed"):
        assert _userinfo(custody_client, issue_delegation_token(aud, alice[0], 300)) == 401, aud


def test_the_person_s_own_token_still_is_and_a_server_delegation_is_not(custody_client):
    """The person's own token is their session. A persona's server delegation, which Origin
    addresses to Mantle (review 22), is not."""
    from origin.services.auth_service import issue_delegation_token

    alice = af.person("Alice")
    assert _userinfo(custody_client, alice[1]) == 200
    assert _userinfo(custody_client,
                     issue_delegation_token("agience-server-iris", alice[0], 300)) == 401
