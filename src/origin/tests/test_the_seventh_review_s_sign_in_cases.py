"""Review 7's sign-in cases (2026-11-02).

F1   Every passkey ceremony is Origin's own: the relying party is Origin's host and the expected
     origin is Origin's own address, never `FACET_URI`. An assertion made on any other page, or a
     passkey registered under any other relying party, is refused. Origin serves the page that runs
     the ceremonies (`/passkey`).
F2   Mantle's host is never a first-party redirect base, whatever `FACET_URI`/`FACET_URIS` say.
     Refresh tokens rotate on use and are recorded by `jti`; a used one presented again is theft
     and revokes its whole family; deactivating a person revokes theirs.
F12  Only `branding.title` stays on the ordinary token.
     A re-authentication forces a fresh sign-in: `prompt=login` and `max_age=0` upstream, and an
     `auth_time` older than the ticket is refused.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from origin.tests import operator_console_fixtures as oc

_PW = "a-long-enough-password"


@pytest.fixture
def db_client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _person(email: str) -> str:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import hash_password

    with SessionLocal() as db:
        p = db_persons.create(db, {"email": email, "name": "P", "email_verified": True,
                                   "password_hash": hash_password(_PW)})
        db.commit()
        return str(p.id)


def _login(c, email):
    r = c.post("/auth/password/login", json={"identifier": email, "password": _PW})
    assert r.status_code == 200, r.text
    return r.json()


# -- F1 -------------------------------------------------------------------------------------------

def test_the_relying_party_and_origin_are_origins_own_address(monkeypatch):
    from origin import config
    from origin.services import passkey_service

    monkeypatch.setattr(config, "FACET_URI", "https://my.facet.test")
    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.example.test")
    assert passkey_service._get_rp_id() == "origin.example.test"
    assert passkey_service.expected_origin() == "https://origin.example.test"


def _passkey_login(c, email, auth, *, origin=None, rp=None):
    opts = c.post("/auth/passkey/login-options", json={"email": email}).json()["options"]
    if rp is not None:
        opts = {**opts, "rpId": rp}
    return c.post("/auth/passkey/login-complete", json={
        "challenge": opts["challenge"], "credential": auth.assertion(opts, origin=origin)})


def test_an_assertion_made_on_the_facet_s_page_is_refused(db_client, monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "FACET_URI", "https://my.facet.test")
    pid = _person("pk1@example.com")
    auth = oc.Authenticator().register(pid)
    assert _passkey_login(db_client, "pk1@example.com", auth,
                          origin="https://my.facet.test").status_code == 401
    assert _passkey_login(db_client, "pk1@example.com", auth).status_code == 200


def test_a_passkey_registered_under_another_relying_party_is_refused(db_client):
    """The home peer's passkeys were made under Mantle's host: they are re-enrolled, never
    accepted."""
    pid = _person("pk2@example.com")
    auth = oc.Authenticator().register(pid)
    r = _passkey_login(db_client, "pk2@example.com", auth, rp="mantle.home.example.test")
    assert r.status_code == 401


def test_origin_serves_the_page_that_runs_the_ceremonies(db_client):
    r = db_client.get("/passkey")
    assert r.status_code == 200 and "navigator.credentials" in db_client.get(
        "/web/passkey.js").text
    csp = r.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp


# -- F2: redirects --------------------------------------------------------------------------------

def test_mantle_s_host_is_never_a_redirect_base(monkeypatch):
    """A URI on Mantle's origin is refused even when a list names it."""
    from origin import config
    from origin.services.auth_service import is_client_redirect_allowed

    monkeypatch.setattr(config, "MANTLE_URI", "https://mantle.example.test", raising=False)
    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {"platform": [
        "https://mantle.example.test/callback", "https://my.example.test/callback"]})
    assert not is_client_redirect_allowed("https://mantle.example.test/callback",
                                          client_id="platform")
    assert is_client_redirect_allowed("https://my.example.test/callback", client_id="platform")



def test_mantle_s_origin_alone_is_refused_not_every_port_on_its_host(monkeypatch):
    """One host serving Origin, Mantle and the web app on separate ports (a single-host install):
    Mantle's origin (scheme, host and port) is never a redirect base, and Origin's own
    `/auth/reauth/complete` on the same host but its own port still is."""
    from origin import config
    from origin.services.auth_service import is_client_redirect_allowed

    monkeypatch.setattr(config, "MANTLE_URI", "http://127.0.0.1:18082", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "http://127.0.0.1:18080", raising=False)
    listed = ["http://127.0.0.1:18080/auth/reauth/complete", "http://127.0.0.1:15173/auth/callback",
              "http://127.0.0.1:18082/callback"]
    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {"platform": listed})
    assert is_client_redirect_allowed(listed[0], client_id="platform")
    assert is_client_redirect_allowed(listed[1], client_id="platform")
    # Listed, and on Mantle's origin: refused.
    assert not is_client_redirect_allowed(listed[2], client_id="platform")
    # A first-party list is exact, loopback included: Mantle's port is refused though listed, a
    # listed other port is admitted, and an unlisted port is not.
    monkeypatch.setattr(config, "MANTLE_URI", "http://localhost:8082", raising=False)
    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {"platform": [
        "http://localhost:8082/callback", "http://localhost:8083/callback"]})
    assert not is_client_redirect_allowed("http://localhost:8082/callback", client_id="platform")
    assert is_client_redirect_allowed("http://localhost:8083/callback", client_id="platform")
    assert not is_client_redirect_allowed("http://localhost:8084/callback", client_id="platform")

# -- F2: refresh tokens ---------------------------------------------------------------------------

def _refresh(c, token):
    return c.post("/auth/token", data={"grant_type": "refresh_token", "refresh_token": token,
                                       "client_id": _rc(token)})


def test_a_refresh_rotates_and_the_new_one_works(db_client):
    _person("rt1@example.com")
    first = _login(db_client, "rt1@example.com")["refresh_token"]
    r = _refresh(db_client, first)
    assert r.status_code == 200, r.text
    second = r.json()["refresh_token"]
    assert second and second != first
    assert _refresh(db_client, second).status_code == 200


def test_a_used_refresh_token_presented_again_revokes_its_family(db_client):
    _person("rt2@example.com")
    first = _login(db_client, "rt2@example.com")["refresh_token"]
    second = _refresh(db_client, first).json()["refresh_token"]
    stolen = _refresh(db_client, first)                              # replayed: theft
    assert stolen.status_code == 400
    assert _refresh(db_client, second).status_code == 400            # the whole family is gone


def test_deactivating_a_person_revokes_their_refresh_tokens(db_client):
    from origin.db.session import SessionLocal
    from origin.services import person_service

    pid = _person("rt3@example.com")
    first = _login(db_client, "rt3@example.com")["refresh_token"]
    with SessionLocal() as db:
        person_service.deactivate(db, pid, "test")
        db.commit()
        person_service.reactivate(db, pid)
        db.commit()
    assert _refresh(db_client, first).status_code == 400


def test_every_refresh_token_is_recorded_by_jti(db_client):
    from jose import jwt as jose_jwt

    from origin.db.session import SessionLocal
    from origin.models.refresh_token import RefreshToken

    _person("rt4@example.com")
    tok = _login(db_client, "rt4@example.com")["refresh_token"]
    jti = jose_jwt.get_unverified_claims(tok)["jti"]
    with SessionLocal() as db:
        row = db.get(RefreshToken, jti)
        assert row is not None and row.family and row.used_at is None and row.revoked_at is None


# -- F12 ------------------------------------------------------------------------------------------

def test_only_the_title_stays_on_the_ordinary_token():
    from origin.services.platform_settings_service import HARMLESS_SETTINGS, is_console_key

    assert HARMLESS_SETTINGS == frozenset({"branding.title"})
    assert is_console_key("branding.email_logo_url") and is_console_key("email.from_name")


# -- re-authentication is fresh -------------------------------------------------------------------

def test_a_re_authentication_asks_the_provider_for_a_fresh_sign_in(db_client):
    from origin.db.session import SessionLocal
    from origin.models.person_step_up import PersonStepUp
    from origin.services import person_step_up

    with SessionLocal() as db:
        db.add(PersonStepUp(ticket="t-fresh", person_id="p", digest="0" * 64, verifier="v" * 48,
                            describe="add a passkey", confirmed_time=datetime.now(timezone.utc)))
        db.commit()
        where = person_step_up.start_location(db, "t-fresh")
    assert "prompt=login" in where and "max_age=0" in where


def test_the_federated_redirect_carries_prompt_login_and_max_age_zero():
    from origin.routers import auth_router

    assert auth_router.federation_kwargs({"prompt": "login", "max_age": 0}) ==         {"prompt": "login", "max_age": 0}
    assert auth_router.federation_kwargs({}) == {}


def test_a_re_authentication_never_rides_an_open_session(db_client, monkeypatch):
    """Origin's own sign-in renders its form whatever session the browser holds: a re-
    authentication is a sign-in, never a session read."""
    from urllib.parse import urlencode

    from origin import config
    from origin.routers import auth_router
    from origin.services import person_step_up

    monkeypatch.setattr(auth_router, "_local_methods", lambda: (True, False))
    q = {"response_type": "code", "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
         "redirect_uri": person_step_up.complete_uri(), "state": "s", "prompt": "login",
         "max_age": "0", "code_challenge": "x" * 43, "code_challenge_method": "S256"}
    r = db_client.get("/auth/authorize?" + urlencode(q), follow_redirects=False)
    assert r.status_code == 200, r.text and "<form" in r.text.lower()


def test_a_stale_auth_time_does_not_prove_a_ticket(db_client):
    from origin import config
    from origin.db.session import SessionLocal
    from origin.models.person_step_up import PersonStepUp
    from origin.services import person_step_up

    pid = _person("ra1@example.com")
    with SessionLocal() as db:
        db.add(PersonStepUp(ticket="t-stale", person_id=pid, digest="0" * 64, verifier="v" * 48,
                            describe="add a passkey", confirmed_time=datetime.now(timezone.utc),
                            session_sha256="s" * 64))
        db.commit()
        code = {"user_info": {"provider": "local", "sub": pid},
                "redirect_uri": person_step_up.complete_uri(),
                "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
                "code_challenge_method": "S256",
                "code_challenge": person_step_up._s256("v" * 48),
                "timestamp": datetime.now(timezone.utc),
                "auth_time": int(time.time()) - 3600}
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as refused:
            person_step_up.complete(db, "t-stale", "c1", {"c1": code}, timedelta(minutes=5),
                                    session_sha256="s" * 64)
        assert refused.value.status_code == 400 and "fresh" in refused.value.detail


def _rc(token):
    from origin.tests.authority_fixtures import refresh_client
    return refresh_client(token)
