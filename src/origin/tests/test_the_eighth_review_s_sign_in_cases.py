"""Review 8's sign-in cases (2026-11-02).

R1  A change to how a person signs in (linking or unlinking an identity, adding or removing a
    passkey) is made only in Origin's own session: a first-party cookie Origin sets when the
    person signs in on Origin's own pages, which no bearer token stands in for. A re-authentication
    ticket is started only from that session; its start page shows the exact action, the identity
    to be linked included, and needs an explicit confirm before the sign-in; a sign-in with no
    `auth_time` proves nothing. Passkey registration options are issued only in that session.
R3  A narrowed delegation (RFC 8693 token exchange) for Ember and the facets: short, scoped, never
    platform admin, no refresh token.
R7  An exact retry of a refresh within its grace returns the same new token.
R8  Legacy refresh tokens end at a cut-off; sign-out and sign-out-everywhere; refreshed access
    tokens carry their own `jti`; the platform client's development redirect bases are opt-in;
    Mantle's host is never an allowed origin, SSO return or app address.
"""
from __future__ import annotations

import hashlib

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_sign_in_method_changes_only_with_a_fresh_step_up as t

custody_client = t.custody_client
LINK = t.LINK


def _session(c, person_id):
    """Origin's own first-party session, as Origin's sign-in page leaves it in the browser."""
    from origin.db.session import SessionLocal
    from origin.services import origin_session

    with SessionLocal() as db:
        raw = origin_session.issue(db, person_id)
        db.commit()
    c.cookies.set(origin_session.cookie_name(), raw)
    return raw


def _page_options(c, token, method, path, body: bytes):
    """Origin's own page asks, in the person's Origin session (the cookie) and with their token."""
    return c.post("/auth/me/step-up-options",
                  json={"method": method, "path": path, "body": body.decode() if body else "",
                        "body_sha256": hashlib.sha256(body).hexdigest()},
                  headers={"Authorization": f"Bearer {token}"})


def _complete(c, ticket, provider, sub, email, *, auth_time=True):
    from datetime import datetime, timezone

    from origin import config
    from origin.routers import auth_router
    from origin.services import person_step_up
    code = t._code(provider, sub, email, redirect=person_step_up.complete_uri())
    auth_router.authorization_codes[code].update(
        {"code_challenge": person_step_up.code_challenge(ticket),
         "code_challenge_method": "S256", "client_id": config.PLATFORM_CLIENT_ID,
         "auth_time": int(datetime.now(timezone.utc).timestamp()) if auth_time else None})
    return c.get("/auth/reauth/complete", params={"code": code, "state": ticket})


# -- R1 -------------------------------------------------------------------------------------------

def test_a_bearer_token_alone_starts_no_re_authentication(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    body = t._link_body(t._code("google", "mallory-google", "mallory@evil.test"))
    r = c.post("/auth/me/step-up-options",
               json={"method": "POST", "path": LINK, "body": body.decode(),
                     "body_sha256": hashlib.sha256(body).hexdigest()},
               headers={"Authorization": f"Bearer {alice_token}"})
    assert r.status_code == 403 and "Origin" in r.text, r.text


def test_a_bearer_token_alone_changes_no_sign_in_even_with_a_passkey_step_up(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    authn = oc.Authenticator().register(alice)
    body = t._link_body(t._code("google", "mallory-google", "mallory@evil.test"))
    step = t._passkey_step(c, alice_token, authn, "POST", LINK, body)
    assert t._send(c, "POST", LINK, alice_token, body, step).status_code == 403
    assert t._resolves_to("google", "mallory-google", "mallory@evil.test") != alice


def test_the_start_page_shows_the_action_and_needs_a_confirm(custody_client):
    c = custody_client
    alice, tok = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    _session(c, alice)
    body = t._link_body(t._code("google", "mallory-google", "mallory@evil.test"))
    r = _page_options(c, tok, "POST", LINK, body)
    assert r.status_code == 200 and r.json()["kind"] == "reauth", r.text
    ticket = r.json()["ticket"]
    start = c.get("/auth/reauth/start", params={"ticket": ticket}, follow_redirects=False)
    assert start.status_code == 200 and "mallory@evil.test" in start.text
    assert "google" in start.text.lower() and "<form" in start.text
    # Not proven by a sign-in that was never confirmed.
    assert _complete(c, ticket, "google", "alice-google", "alice@team.test").status_code == 400
    csrf = start.text.split('name="csrf" value="')[1].split('"')[0]
    go = c.post("/auth/reauth/start", data={"ticket": ticket, "csrf": csrf},
                follow_redirects=False)
    assert go.status_code == 303 and "/auth/authorize" in go.headers["location"]
    assert "prompt=login" in go.headers["location"]


def test_the_page_flow_links_an_identity_in_origin_s_own_session(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    _session(c, alice)
    body = t._attempted_body(c, alice_token, t._code("google", "alice-2nd", "a2@team.test"))
    ticket = _page_options(c, alice_token, "POST", LINK, body).json()["ticket"]
    start = c.get("/auth/reauth/start", params={"ticket": ticket})
    csrf = start.text.split('name="csrf" value="')[1].split('"')[0]
    c.post("/auth/reauth/start", data={"ticket": ticket, "csrf": csrf}, follow_redirects=False)
    assert _complete(c, ticket, "google", "alice-google", "alice@team.test").status_code == 200
    r = t._send(c, "POST", LINK, alice_token, body, f"reauth:{ticket}")
    assert r.status_code == 200, r.text
    assert t._resolves_to("google", "alice-2nd", "a2@team.test") == alice


def test_a_sign_in_with_no_auth_time_proves_nothing(custody_client):
    c = custody_client
    alice, tok = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    _session(c, alice)
    ticket = _page_options(c, tok, "DELETE", f"{LINK}/google", b"").json()["ticket"]
    start = c.get("/auth/reauth/start", params={"ticket": ticket})
    csrf = start.text.split('name="csrf" value="')[1].split('"')[0]
    c.post("/auth/reauth/start", data={"ticket": ticket, "csrf": csrf}, follow_redirects=False)
    r = _complete(c, ticket, "google", "alice-google", "alice@team.test", auth_time=False)
    assert r.status_code == 400 and "fresh" in r.text


def test_registration_options_need_origin_s_own_session(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    authn = oc.Authenticator().register(alice)
    path = "/auth/passkey/register-options"
    step = t._passkey_step(c, alice_token, authn, "POST", path, b"")
    assert t._send(c, "POST", path, alice_token, b"", step).status_code == 403   # bearer only
    _session(c, alice)
    step = t._passkey_step(c, alice_token, authn, "POST", path, b"")
    assert t._send(c, "POST", path, alice_token, b"", step).status_code == 200


# -- R3 -------------------------------------------------------------------------------------------

EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


def _exchange(c, subject, audience, scope=None):
    """A person's narrowed delegation as the web app now gets it: in their Origin session
    (review 23, H1). Anything that is not a person's own access token goes to the token endpoint,
    which refuses it."""
    from origin import config
    from origin.tests import operator_console_fixtures as oc

    claims = jose_jwt.get_unverified_claims(subject)
    if claims.get("principal_type", "user") == "user" and not claims.get("act"):
        oc.origin_page_session(c, str(claims["sub"]))
        body = {"audience": audience, **({"scope": scope} if scope else {})}
        return c.post("/auth/me/authority/narrow", json=body,
                      headers={"X-Origin-Session": "1",
                               "Origin": config.APP_URI or config.ORIGIN_URI})
    data = {"grant_type": EXCHANGE, "subject_token": subject,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience}
    if scope:
        data["scope"] = scope
    return c.post("/auth/token", data=data)


def test_a_narrowed_delegation_for_ember(custody_client, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "NARROW_AUDIENCES",
                        {"ember": ["ember:memory", "ember:share", "ember:read"]}, raising=False)
    c = custody_client
    alice, alice_token = af.person("Alice")
    r = _exchange(c, alice_token, "ember")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "refresh_token" not in body and body["expires_in"] <= 300
    claims = jose_jwt.get_unverified_claims(body["access_token"])
    assert claims["sub"] == alice and claims["aud"] == "ember"
    assert claims["act"]["sub"] == "ember" and claims["principal_type"] == "delegation"
    assert "platform:admin" not in (claims.get("scope") or "")
    assert set((claims.get("scope") or "").split()) <= {"ember:memory", "ember:share",
                                                        "ember:read"}
    assert _exchange(c, alice_token, "ember", "platform:admin").status_code == 400
    assert _exchange(c, alice_token, "somewhere-else").status_code == 400
    assert _exchange(c, body["access_token"], "ember").status_code in (400, 401)  # no chaining


# -- R7, R8 ---------------------------------------------------------------------------------------

def _signed_in(c):
    _p, _tok = af.person("Rita")
    from origin.db.session import SessionLocal
    from origin.db import persons as db_persons
    from origin.services import refresh_tokens
    from origin.services.auth_service import person_token_claims

    with SessionLocal() as db:
        person = db_persons.get_by_id(db, _p)
        claims = person_token_claims(person, client_id="platform")
        rt = refresh_tokens.issue(db, claims)
        db.commit()
    return _p, rt


def _refresh(c, rt):
    return c.post("/auth/token", data={"grant_type": "refresh_token", "refresh_token": rt,
                                       "client_id": "platform"})


def test_an_exact_retry_gets_no_grace(custody_client):
    """Review 10, R6: the grace this test once held let a thief share the family. A retry of a used
    refresh token revokes it, like any other reuse."""
    c = custody_client
    _p, rt = _signed_in(c)
    first = _refresh(c, rt)
    assert first.status_code == 200, first.text
    assert _refresh(c, rt).status_code == 400
    assert _refresh(c, first.json()["refresh_token"]).status_code == 400    # family revoked


def test_a_refreshed_access_token_has_its_own_jti(custody_client):
    c = custody_client
    _p, rt = _signed_in(c)
    a = _refresh(c, rt).json()
    b = _refresh(c, a["refresh_token"]).json()
    ja = jose_jwt.get_unverified_claims(a["access_token"]).get("jti")
    jb = jose_jwt.get_unverified_claims(b["access_token"]).get("jti")
    assert ja and jb and ja != jb


def test_sign_out_revokes_the_family_and_everywhere_revokes_all(custody_client):
    c = custody_client
    p, rt = _signed_in(c)
    from origin.db.session import SessionLocal
    from origin.db import persons as db_persons
    from origin.services import refresh_tokens
    from origin.services.auth_service import person_token_claims

    with SessionLocal() as db:
        other = refresh_tokens.issue(db, person_token_claims(db_persons.get_by_id(db, p),
                                                             client_id="platform"))
        db.commit()
    assert c.post("/auth/sign-out", data={"refresh_token": rt}).status_code == 200
    assert _refresh(c, rt).status_code == 400
    nxt = _refresh(c, other)
    assert nxt.status_code == 200
    from origin.services.auth_service import create_jwt_token
    access = create_jwt_token({"sub": p, "email": "r@x.test", "name": "R",
                               "client_id": "platform", "aud": __import__(
                                   "origin.config", fromlist=["x"]).AUTHORITY_ISSUER})
    assert c.post("/auth/sign-out-everywhere",
                  headers={"Authorization": f"Bearer {access}"}).status_code == 200
    assert _refresh(c, nxt.json()["refresh_token"]).status_code == 400


def test_a_legacy_refresh_token_is_refused_after_the_cut_off(custody_client, monkeypatch):
    from origin import config
    from origin.services.auth_service import create_jwt_token
    c = custody_client
    p, _rt = _signed_in(c)
    legacy = create_jwt_token({"sub": p, "token_type": "refresh", "client_id": "platform",
                               "aud": "platform"})
    monkeypatch.setattr(config, "REFRESH_LEGACY_CUTOFF", "2000-01-01T00:00:00+00:00",
                        raising=False)
    assert _refresh(c, legacy).status_code == 400


def test_the_development_redirect_bases_are_opt_in(monkeypatch):
    from origin import config
    from origin.services.auth_service import is_client_redirect_allowed
    monkeypatch.setattr(config, "PLATFORM_DEV_REDIRECTS", False, raising=False)
    for uri in ("http://127.0.0.1:8765/cb", "https://vscode.dev/redirect",
                "https://oauth.pstmn.io/v1/callback"):
        assert not is_client_redirect_allowed(uri, platform_client=True), uri
    monkeypatch.setattr(config, "PLATFORM_DEV_REDIRECTS", True, raising=False)
    assert is_client_redirect_allowed("http://127.0.0.1:8765/cb", platform_client=True)


def test_mantle_s_host_is_never_an_allowed_origin_sso_return_or_app_address(monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "MANTLE_URI", "https://mantle.test", raising=False)
    assert config.without_mantle(["https://mantle.test", "https://my.test"]) == \
        ["https://my.test"]
    assert config.without_mantle("https://mantle.test/x") == []


def test_a_sign_in_delivered_to_a_persona_facet_gets_only_a_narrowed_delegation(
        custody_client, monkeypatch):
    """A `FACET_URIS` origin other than the web app gets a delegation for itself, never the
    platform token or a refresh token."""
    import base64 as _b64
    from origin import config
    from origin.routers import auth_router
    c = custody_client
    monkeypatch.setattr(config, "FACET_URIS", ["https://my.test", "https://aria.test"],
                        raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://my.test", raising=False)
    # Since review 12 a facet is narrowed to only when Origin lists it (`NARROW_FACETS`).
    monkeypatch.setattr(config, "NARROW_FACETS", ["https://aria.test"], raising=False)
    alice, _tok = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    verifier = "v" * 48
    challenge = _b64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()) \
        .rstrip(b"=").decode()
    code = t._code("google", "alice-google", "alice@team.test", redirect="https://aria.test/cb")
    auth_router.authorization_codes[code].update(
        {"code_challenge": challenge, "code_challenge_method": "S256",
         "client_id": config.PLATFORM_CLIENT_ID})
    r = c.post("/auth/token", data={"grant_type": "authorization_code", "code": code,
                                    "redirect_uri": "https://aria.test/cb",
                                    "client_id": config.PLATFORM_CLIENT_ID,
                                    "code_verifier": verifier})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "refresh_token" not in body
    claims = jose_jwt.get_unverified_claims(body["access_token"])
    assert claims["aud"] == "https://aria.test" and claims["principal_type"] == "delegation"
    assert claims["scope"] == "persona"


def test_the_ember_proxy_s_forward_auth_accepts_an_ember_delegation(custody_client, monkeypatch):
    """lumen.agience.ai's proxy asks Origin's `/auth/userinfo` before it passes a request to
    Ember: the narrowed delegation Facet now sends there must be accepted, or the Ember API is
    shut."""
    from origin import config
    monkeypatch.setattr(config, "NARROW_AUDIENCES",
                        {"ember": ["ember:memory", "ember:share", "ember:read"]}, raising=False)
    c = custody_client
    alice, alice_token = af.person("Alice")
    delegation = _exchange(c, alice_token, "ember").json()["access_token"]
    r = c.get("/auth/userinfo", headers={"Authorization": f"Bearer {delegation}"})
    assert r.status_code == 200, r.text
    assert r.json()["id"] == alice
