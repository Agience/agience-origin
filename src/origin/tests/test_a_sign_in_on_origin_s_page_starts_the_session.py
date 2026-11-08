"""A password or OTP sign-in on Origin's own page starts the person's Origin session.

Origin's own `/login` page signs a person in at `/auth/password/login`, `/auth/password/register`
and `/auth/otp/verify`. A sign-in there starts the Origin session the same way `/auth/authorize`'s
local form does (`origin_session.start`: HttpOnly, SameSite=Strict, `__Host-` on https), so the
web app can then get its token for Mantle (`POST /auth/me/authority/mantle-token`) and `/passkey`
can add a passkey. A sign-in posted from any other page (the web app's included) starts no session:
credentials are typed only on Origin's page.
"""
from __future__ import annotations

import pytest

from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

PASSWORD = "a-long-enough-password-1"


@pytest.fixture
def c(custody_client, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "APP_URI", "http://app.test", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "http://origin.test", raising=False)
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "http://origin.test", raising=False)
    monkeypatch.setattr("origin.routers.auth_router.email_verification_required",
                        lambda *_a, **_k: False)
    custody_client.cookies.clear()
    return custody_client


ORIGIN_PAGE = {"Origin": "http://origin.test"}
APP_PAGE = {"Origin": "http://app.test"}


def _register(c, name, headers):
    return c.post("/auth/password/register", headers=headers, json={
        "username": name, "name": name, "email": f"{name}@example.test", "password": PASSWORD})


def _login(c, name, headers):
    return c.post("/auth/password/login", headers=headers,
                  json={"identifier": name, "password": PASSWORD})


def _session_cookie(r):
    from origin.services import origin_session
    return [h for h in r.headers.get_list("set-cookie")
            if h.startswith(origin_session.cookie_name() + "=")]


def _mantle_token(c):
    return c.post("/auth/me/authority/mantle-token", json={},
                  headers={"Origin": "http://app.test", "X-Origin-Session": "1"})


def test_a_person_who_signs_in_with_a_password_then_gets_a_token_for_mantle(c):
    assert _register(c, "alice", APP_PAGE).status_code == 200
    c.cookies.clear()
    r = _login(c, "alice", ORIGIN_PAGE)
    assert r.status_code == 200, r.text
    (cookie,) = _session_cookie(r)
    low = cookie.lower()
    assert "httponly" in low and "samesite=strict" in low and "path=/" in low
    t = _mantle_token(c)
    assert t.status_code == 200, t.text
    assert t.json()["access_token"]


def test_registering_on_origin_s_page_starts_the_session(c):
    r = _register(c, "bob", ORIGIN_PAGE)
    assert r.status_code == 200 and r.json().get("access_token"), r.text
    assert _session_cookie(r)
    assert _mantle_token(c).status_code == 200


def test_a_sign_in_posted_from_another_page_starts_no_session(c):
    assert _register(c, "carol", APP_PAGE).status_code == 200
    for headers in (APP_PAGE, {"Origin": "https://evil.example"}, {}):
        c.cookies.clear()
        r = _login(c, "carol", headers)
        assert r.status_code == 200
        assert not _session_cookie(r)
        assert _mantle_token(c).status_code == 401


def test_an_otp_sign_in_on_origin_s_page_starts_the_session(c, monkeypatch):
    from origin.services import otp_service

    assert _register(c, "dave", APP_PAGE).status_code == 200
    c.cookies.clear()

    async def _verified(_db, email, code):
        from origin.db import persons as db_persons
        from origin.db.session import SessionLocal
        with SessionLocal() as db:
            return str(db_persons.get_by_email(db, email).id) if code == "123456" else None

    monkeypatch.setattr(otp_service, "verify_otp", _verified)
    body = {"email": "dave@example.test", "code": "123456"}
    r = c.post("/auth/otp/verify", json=body, headers={"Origin": "http://app.test"})
    assert r.status_code == 200 and not _session_cookie(r)
    c.cookies.clear()
    r = c.post("/auth/otp/verify", json=body, headers=ORIGIN_PAGE)
    assert r.status_code == 200, r.text
    assert _session_cookie(r)
    assert _mantle_token(c).status_code == 200


def test_on_https_the_session_is_the_host_cookie(c, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.test", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.test", raising=False)
    assert _register(c, "erin", APP_PAGE).status_code == 200
    r = _login(c, "erin", {"Origin": "https://origin.test"})
    cookies = [h for h in r.headers.get_list("set-cookie")
               if h.startswith("__Host-origin_session=")]
    assert len(cookies) == 1 and "secure" in cookies[0].lower()
