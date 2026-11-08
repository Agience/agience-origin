"""Review 23, H1: a person's bearer alone never mints a token addressed to anything else.

Mantle holds the person's token on every call. Origin's token exchange took a person's access token
with no client authentication and narrowed it to Iris, Lumen, Sage, Crystal or Ember, so Mantle
could have Iris act with the person's secrets. Now:

* the person-to-narrowed exchange is made only in the person's Origin session
  (`POST /auth/me/authority/narrow`, the session cookie, `X-Origin-Session` and the web app's
  `Origin`); the token endpoint refuses a person's bearer;
* the web app calls Mantle on a token addressed to Mantle (`POST /auth/me/authority/mantle-token`,
  in the session), which is no session at Origin, exchanges for nothing, and is no subject for a
  persona's delegation exchange, though Origin still verifies it as the acting caller's credential.

Tokens come from Origin's own fixtures (`authority_fixtures.person`) and routes.
"""
from __future__ import annotations

import pytest
from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"


def _bearer_exchange(c, subject, audience):
    return c.post("/auth/token", data={"grant_type": EXCHANGE, "subject_token": subject,
                                       "subject_token_type": ACCESS, "audience": audience})


def _in_session(c, person_id, path, body=None, *, header=True, origin=None):
    from origin import config
    from origin.tests import operator_console_fixtures as oc

    oc.origin_page_session(c, person_id)
    headers = {"Origin": origin or config.APP_URI or config.ORIGIN_URI}
    if header:
        headers["X-Origin-Session"] = "1"
    return c.post(path, json=body or {}, headers=headers)


@pytest.mark.parametrize("audience", ["iris", "lumen", "sage", "crystal", "ember"])
def test_the_access_token_mantle_holds_narrows_to_nothing(custody_client, audience):
    alice = af.person("Alice")
    assert _bearer_exchange(custody_client, alice[1], audience).status_code in (400, 401, 403)


def test_the_person_s_session_narrows(custody_client, monkeypatch):
    from origin import authority_trust, config
    from origin.key_manager import get_jwk_public
    from prism.trust.server_auth import ServerAuth

    m = authority_trust._manifest
    monkeypatch.setattr(authority_trust, "_manifest", authority_trust.AuthorityManifest(
        issuer=config.AUTHORITY_ISSUER, artifact_id=m.artifact_id,
        trust_anchors={**m.trust_anchors, "origin": {"jwks": {"keys": [get_jwk_public()]}}},
        bootstrap_token_hash=None, raw={}))

    alice = af.person("Alice")
    r = _in_session(custody_client, alice[0], "/auth/me/authority/narrow", {"audience": "iris"})
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    taken = ServerAuth("agience-server-iris", "http://mantle.invalid").verify_narrowed_delegation(tok)
    assert taken is not None and taken["sub"] == alice[0]


def test_the_session_route_needs_the_header_the_web_app_and_a_session(custody_client):
    c = custody_client
    alice = af.person("Alice")
    path = "/auth/me/authority/narrow"
    assert _in_session(c, alice[0], path, {"audience": "iris"}, header=False).status_code == 403
    assert _in_session(c, alice[0], path, {"audience": "iris"},
                       origin="https://evil.example").status_code == 403
    c.cookies.clear()
    from origin import config
    assert c.post(path, json={"audience": "iris"},
                  headers={"X-Origin-Session": "1", "Origin": config.APP_URI or config.ORIGIN_URI,
                           "Authorization": f"Bearer {alice[1]}"}).status_code == 401


def test_the_session_narrows_only_to_a_narrow_audience_and_its_scopes(custody_client):
    alice = af.person("Alice")
    c = custody_client
    assert _in_session(c, alice[0], "/auth/me/authority/narrow",
                       {"audience": "somewhere"}).status_code == 400
    assert _in_session(c, alice[0], "/auth/me/authority/narrow",
                       {"audience": "ember", "scope": "platform:admin"}).status_code == 400


def _mantle_token(c, person_id):
    r = _in_session(c, person_id, "/auth/me/authority/mantle-token")
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_the_web_app_s_token_for_mantle_is_addressed_to_mantle(custody_client):
    alice = af.person("Alice")
    claims = jose_jwt.get_unverified_claims(_mantle_token(custody_client, alice[0]))
    assert claims["aud"] == "mantle" and claims["sub"] == alice[0]
    assert "act" not in claims and not claims.get("token_type")


def test_the_token_for_mantle_mints_nothing_and_is_no_session(custody_client):
    from origin.services.dependencies import AuthContext, get_auth

    c = custody_client
    alice = af.person("Alice")
    m = _mantle_token(c, alice[0])
    c.cookies.clear()
    for audience in ("iris", "ember", "crystal"):
        assert _bearer_exchange(c, m, audience).status_code in (400, 401, 403)
    assert c.get("/auth/userinfo", headers={"Authorization": f"Bearer {m}"}).status_code == 401
    # A persona's delegation exchange takes no token addressed to Mantle as its subject.
    c.app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="lumen", principal_type="service", user_id=None)
    try:
        r = c.post("/internal/delegation-token",
                   json={"server_client_id": "agience-server-lumen", "subject_token": m})
        assert r.status_code == 403
    finally:
        c.app.dependency_overrides.pop(get_auth, None)


def test_the_token_for_mantle_is_the_acting_caller_s_credential(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    alice = af.person("Alice")
    m = _mantle_token(custody_client, alice[0])
    with SessionLocal() as db:
        got = share_credentials.verify_share_credential(db, m)
    assert got.subject == alice[0] and got.kind == "access"


def test_a_relay_token_is_narrowed_to_the_relay_in_the_session(custody_client):
    alice = af.person("Alice")
    r = _in_session(custody_client, alice[0], "/auth/me/authority/narrow", {"audience": "relay"})
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert (claims["aud"], claims["act"], claims["scope"]) == ("relay", {"sub": "relay"},
                                                                "relay:host")
