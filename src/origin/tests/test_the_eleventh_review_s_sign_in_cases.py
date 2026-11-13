"""Review 11's sign-in, token and page cases (2026-11-02).

John  Ember's share is gone: `ember:share` is never issued. A malformed `NARROW_AUDIENCES` fails
      closed: no narrowed audience at all.
H2    A retired signing key leaves Origin's public JWKS once the longest token lifetime has passed.
H3    Persona servers (Iris, Lumen, Sage, Crystal) get narrowed delegations like Ember: their own
      audience and scope, five minutes, no refresh, never `platform:admin`. A persona exchanges
      one for its own server delegation, and only its own.
M1    The refresh grant authenticates its client: `client_id` is required and must be the
      family's.
M2    Origin publishes not-before changes, signed (`GET /auth/not-before`).
M5    A service account (Ember's) is issued only a narrowed delegation for its audience.
M7    Every Origin page is sent with a CSP that forbids framing and inline script; revoking a job
      grant needs a step-up.
M8    Pausing registration is enforced in Origin; uvicorn is never told to trust every peer's
      forwarded headers.
Lows  A re-authentication completes only in the Origin session that began it, and the sign-in
      leading to it starts no session; a link's code must be Origin's own platform client's,
      returning to `/passkey`; the passkey Remove button sends the credential's id; a person
      with no passkey keeps the link's code and state through the re-authentication.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_sign_in_method_changes_only_with_a_fresh_step_up as t
from origin.tests.test_the_eighth_review_s_sign_in_cases import (
    _exchange, _signed_in)

custody_client = t.custody_client
WEB = Path(__file__).resolve().parents[1] / "web"


def _refresh(c, rt, client_id="platform"):
    data = {"grant_type": "refresh_token", "refresh_token": rt}
    if client_id is not None:
        data["client_id"] = client_id
    return c.post("/auth/token", data=data)


# -- John: no Ember share -------------------------------------------------------------------------

def test_ember_is_never_issued_a_share(custody_client):
    from origin import config
    c = custody_client
    assert "ember:share" not in config._narrow_audiences_from_env().get("ember", [])
    _p, tok = af.person("Ann")
    r = _exchange(c, tok, "ember")
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert set(claims["scope"].split()) == {"ember:memory", "ember:read"}
    assert _exchange(c, tok, "ember", "ember:share").status_code == 400


@pytest.mark.parametrize("raw", ["not json", "[1, 2]", '{"ember": 5}'])
def test_a_malformed_narrow_audiences_fails_closed(monkeypatch, raw):
    from origin import config
    from origin.services import auth_service
    monkeypatch.setenv("NARROW_AUDIENCES", raw)
    monkeypatch.setattr(config, "NARROW_AUDIENCES", config._narrow_audiences_from_env())
    monkeypatch.setattr(config, "FACET_URIS", ["https://aria.example.test"], raising=False)
    assert auth_service.narrow_audiences() == {}


# -- H2 -------------------------------------------------------------------------------------------

def test_a_retired_key_leaves_the_jwks_after_the_longest_token_lifetime(custody_client, tmp_path,
                                                                       monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from origin.services import auth_service, signing_keys

    pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key() \
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (tmp_path / "origin.retired.origin-old.public.pem").write_bytes(pub)
    monkeypatch.setattr(signing_keys, "keys_dir", lambda: tmp_path)
    life = signing_keys.retired_key_lifetime()
    assert life >= timedelta(seconds=auth_service.access_token_expires_in_seconds())
    now = datetime.now(timezone.utc)
    signing_keys.record_retired("origin-old", folder=tmp_path, at=now)
    kids = [k["kid"] for k in signing_keys.published_jwks(now=now + life - timedelta(minutes=1))]
    assert "origin-old" in kids
    kids = [k["kid"] for k in signing_keys.published_jwks(now=now + life + timedelta(minutes=1))]
    assert "origin-old" not in kids


# -- H3 -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("persona", ["iris", "lumen", "sage", "crystal"])
def test_a_persona_server_gets_only_a_narrowed_delegation(custody_client, persona):
    c = custody_client
    _p, tok = af.person("Ann")
    r = _exchange(c, tok, persona)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "refresh_token" not in body and body["expires_in"] <= 300
    claims = jose_jwt.get_unverified_claims(body["access_token"])
    assert claims["aud"] == persona and claims["act"]["sub"] == persona
    assert claims["scope"] == f"persona:{persona}" and "platform:admin" not in claims["scope"]
    assert _exchange(c, tok, persona, "platform:admin").status_code == 400
    # Never a key, never an Origin route.
    me = c.get("/auth/me/preferences", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code in (401, 403)


def _as_service(name):
    from origin.main import app
    from origin.services.dependencies import AuthContext, get_auth
    app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=name, principal_type="service", user_id=None)


def test_a_persona_exchanges_its_own_narrowed_delegation_and_no_other(custody_client):
    from origin.main import app
    from origin.services.dependencies import get_auth

    c = custody_client
    p, tok = af.person("Ann")
    iris = _exchange(c, tok, "iris").json()["access_token"]
    lumen = _exchange(c, tok, "lumen").json()["access_token"]
    try:
        _as_service("iris")
        ok = c.post("/internal/delegation-token",
                    json={"server_client_id": "agience-server-iris", "subject_token": iris})
        assert ok.status_code == 200, ok.text
        claims = jose_jwt.get_unverified_claims(ok.json()["token"])
        assert claims["sub"] == p and claims["act"]["iss"] == "iris"
        other = c.post("/internal/delegation-token",
                       json={"server_client_id": "agience-server-iris", "subject_token": lumen})
        assert other.status_code == 403
        _as_service("lumen")
        theirs = c.post("/internal/delegation-token",
                        json={"server_client_id": "agience-server-lumen", "subject_token": iris})
        assert theirs.status_code == 403
        _as_service("mantle")
        shared = c.post("/internal/delegation-token",
                        json={"server_client_id": "agience-server-iris", "subject_token": iris})
        assert shared.status_code == 403
    finally:
        app.dependency_overrides.pop(get_auth, None)


# -- M1 -------------------------------------------------------------------------------------------

def test_the_refresh_grant_needs_the_family_s_own_client(custody_client):
    c = custody_client
    _p, rt = _signed_in(c)
    assert _refresh(c, rt, client_id=None).status_code == 400
    assert _refresh(c, rt, client_id="someone-else").status_code == 400
    _p, rt = _signed_in(c)
    r = _refresh(c, rt, client_id="platform")
    assert r.status_code == 200, r.text


# -- M2 -------------------------------------------------------------------------------------------

def test_origin_publishes_not_before_changes_signed(custody_client):
    from origin.key_manager import get_public_key_pem

    c = custody_client
    p, tok = af.person("Ann")
    assert c.post("/auth/sign-out-everywhere",
                  headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    r = c.get("/auth/not-before", params={"after": 0})
    assert r.status_code == 200, r.text
    claims = jose_jwt.decode(r.json()["token"], get_public_key_pem(), algorithms=["RS256"],
                             options={"verify_aud": False})
    assert any(e["sub"] == p and e["not_before"] > 0 for e in claims["entries"])
    assert "all_before" in claims and claims["iss"]
    # Served by sequence since review 12 (M8): nothing changed after the highest number.
    later = c.get("/auth/not-before", params={"after": claims["seq"]})
    assert jose_jwt.get_unverified_claims(later.json()["token"])["entries"] == []


# -- M5 -------------------------------------------------------------------------------------------

def test_a_service_account_is_issued_only_its_narrowed_delegation(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import service_accounts

    c = custody_client
    p, rt = _signed_in(c)
    with SessionLocal() as db:
        service_accounts.mark(db, p, "ember")
        db.commit()
    r = _refresh(c, rt)
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert claims["aud"] == "ember" and claims["act"]["sub"] == "ember"
    assert claims["principal_type"] == "delegation" and "roles" not in claims
    assert r.json()["refresh_token"]                          # Ember keeps its own sign-in


# -- M7 -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/login", "/account", "/passkey", "/web/passkey.html",
                                  "/web/index.html", "/logout", "/reset-password",
                                  "/verify-email"])
def test_every_origin_page_refuses_framing_and_inline_script(custody_client, path):
    r = custody_client.get(path)
    assert r.status_code == 200, (path, r.status_code)
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp, (path, csp)
    script = re.search(r"script-src ([^;]*)", csp)
    assert script and "'unsafe-inline'" not in script.group(1), (path, csp)


def test_the_authorize_chooser_refuses_framing_and_inline_script(custody_client):
    from origin import config
    from origin.services import person_step_up
    r = custody_client.get("/auth/authorize", params={
        "client_id": config.PLATFORM_CLIENT_ID, "redirect_uri": person_step_up.link_uri(),
        "response_type": "code", "state": "s", "code_challenge": "x" * 43,
        "code_challenge_method": "S256"}, follow_redirects=False)
    assert r.status_code == 200, r.text
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in \
        (re.search(r"script-src ([^;]*)", csp) or [None, "'unsafe-inline'"])[1]
    assert "onclick=" not in r.text and not re.search(r"<script>(?!\s*</script>)", r.text)


def test_no_origin_page_carries_inline_script_or_handlers():
    from origin.routers import auth_router
    bad = []
    for f in WEB.glob("*.html"):
        text = f.read_text(encoding="utf-8")
        if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text) or re.search(r"\son\w+=", text):
            bad.append(f.name)
    page = auth_router._LOCAL_LOGIN_PAGE
    if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", page):
        bad.append("_LOCAL_LOGIN_PAGE")
    assert bad == []


def test_stopping_a_job_grant_is_one_click_in_a_signed_in_session(custody_client):
    """John, 2026-11-12: stop is one click with a valid session, no step-up (origin `4f2c2cd`). It
    stays the person's own: no session, or another person's grant, is refused."""
    from origin.tests.test_background_work_runs_on_a_job_grant import _root
    from origin.tests.test_the_ninth_review_s_job_grant_cases import PATH, _days, _page_grant

    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    bob = af.person("bob", email="bob@team.test")
    _root(c, alice, alice[0])
    gid = _page_grant(c, alice, {"job": "platform.reindex", "expires_at": _days(7)}).json()[
        "grant_id"]
    nobody = c.post(f"{PATH}/{gid}/revoke")
    assert nobody.status_code in (401, 403), nobody.text
    other = c.post(f"{PATH}/{gid}/revoke", headers={"Authorization": f"Bearer {bob[1]}"})
    assert other.status_code in (403, 404), other.text
    ok = c.post(f"{PATH}/{gid}/revoke", headers={"Authorization": f"Bearer {alice[1]}"})
    assert ok.status_code == 200, ok.text


# -- M8 -------------------------------------------------------------------------------------------

def test_paused_registration_is_refused_by_origin_itself(custody_client, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "REGISTRATION_PAUSED", True, raising=False)
    r = custody_client.post("/auth/password/register", json={
        "username": "newbie", "email": "newbie@x.test", "password": "a-long-enough-password",
        "name": "N"})
    assert r.status_code == 403 and "paused" in r.text.lower(), r.text


def test_origin_refuses_to_trust_every_peer_s_forwarded_headers(monkeypatch):
    from origin import config
    monkeypatch.delenv("ORIGIN_UDS", raising=False)
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    assert config.forwarded_trust_problem() is not None          # every TCP peer
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
    assert config.forwarded_trust_problem() is None
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    monkeypatch.setenv("ORIGIN_UDS", "/run/agience-origin/origin.sock")
    assert config.forwarded_trust_problem() is None              # only Caddy opens the socket


# -- lows -----------------------------------------------------------------------------------------

def test_a_re_authentication_completes_only_in_the_session_that_began_it(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    path = "/auth/passkey/register-options"
    ticket = t._page_reauth(c, alice_token, alice, "POST", path, b"")
    began = c.cookies.get("origin_session")
    c.cookies.clear()                                         # another browser
    r = t._complete_fresh(c, ticket, "google", "alice-google", "alice@team.test")
    assert r.status_code == 403, r.text
    assert "origin_session=" not in r.headers.get("set-cookie", "")
    c.cookies.set("origin_session", began)
    ticket = t._page_reauth(c, alice_token, alice, "POST", path, b"")
    ok = t._complete_fresh(c, ticket, "google", "alice-google", "alice@team.test")
    assert ok.status_code == 200, ok.text
    assert "origin_session=" not in ok.headers.get("set-cookie", "")   # the same session


def test_a_sign_in_on_its_way_to_a_re_authentication_or_a_link_starts_no_session(
        custody_client):
    from origin.db.session import SessionLocal
    from origin.routers import auth_router
    from origin.services import link_attempts, person_step_up

    with SessionLocal() as db:
        state = link_attempts.begin(db, "p-1", "c" * 43)
        assert auth_router._starts_origin_session({"redirect_uri": "https://app.test/cb"}, db)
        assert auth_router._starts_origin_session(
            {"redirect_uri": person_step_up.link_uri(), "state": "plain"}, db)  # a sign-in
        assert not auth_router._starts_origin_session(
            {"redirect_uri": person_step_up.complete_uri()}, db)
        assert not auth_router._starts_origin_session(
            {"redirect_uri": person_step_up.link_uri(), "state": state}, db)


@pytest.mark.parametrize("field,value", [("client_id", "someone-else"),
                                         ("redirect_uri", "https://app.test/cb")])
def test_a_link_s_code_is_origin_s_own_and_returns_to_passkey(custody_client, field, value):
    from origin.routers import auth_router

    c = custody_client
    bob, bob_token = af.person("Bob", email="bob@team.test")
    t._identity(bob, "google", "bob-google")
    oc.origin_page_session(c, bob)
    code = t._code("google", "mal-g", "mal@evil.test", redirect=t.link_redirect())
    body = t._attempted_body(c, bob_token, code)
    auth_router.authorization_codes[code][field] = value
    ticket = t._page_reauth(c, bob_token, bob, "POST", t.LINK, body)
    assert t._complete_fresh(c, ticket, "google", "bob-google", "bob@team.test").status_code         == 200
    r = t._send(c, "POST", t.LINK, bob_token, body, f"reauth:{ticket}")
    assert r.status_code in (400, 403), r.text
    assert t._resolves_to("google", "mal-g", "mal@evil.test") != str(bob)


def test_the_passkey_page_s_remove_sends_the_credential_id():
    js = (WEB / "passkey-page.js").read_text(encoding="utf-8")
    remove = js[js.find("Remove"):]
    assert "credential_id" in js or "/auth/passkey/credentials/" in remove


def test_a_person_with_no_passkey_keeps_the_link_through_the_re_authentication():
    js = (WEB / "passkey-page.js").read_text(encoding="utf-8")
    assert "sessionStorage" in js and "pendingLink" in js
