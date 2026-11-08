"""Signing out at Origin ends the browser's Origin session.

`GET /logout` revokes the session the request carries and deletes its cookie (on https the
`__Host-` name, and the plain name too), so nothing made in that session works afterwards: the web
app's token for Mantle, a narrowed delegation, an authority change. `POST /auth/sign-out` ends the
session the request carries as well, and signing out everywhere ends all of the person's.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import test_the_thirteenth_review_s_session_cases as _thirteenth
from origin.tests.test_the_thirteenth_review_s_session_cases import BASE, _as, _hdr, _own

custody_client = _thirteenth.custody_client
people = _thirteenth.people


def _session_cookie(c):
    from origin.services import origin_session
    return c.cookies.get(origin_session.cookie_name())


def _everything_in_the_session(c):
    return {
        "mantle-token": c.post(f"{BASE}/mantle-token", json={}, headers=_hdr()).status_code,
        "narrow": c.post(f"{BASE}/narrow", json={"audience": "ember"}, headers=_hdr()).status_code,
        "entry": c.post(f"{BASE}/entries", json={"entry": af.edge("W", "W2")},
                        headers=_hdr()).status_code,
    }


def test_after_logout_nothing_in_the_session_works(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    _as(c, alice[0])
    raw = _session_cookie(c)
    assert c.post(f"{BASE}/mantle-token", json={}, headers=_hdr()).status_code == 200
    r = c.get("/logout")
    assert r.status_code == 200
    deleted = [h for h in r.headers.get_list("set-cookie") if "origin_session=" in h]
    assert deleted and all("max-age=0" in h.lower() or "expires=" in h.lower() for h in deleted)
    c.cookies.clear()
    from origin.services import origin_session
    c.cookies.set(origin_session.cookie_name(), raw)    # even a browser that kept the cookie
    assert _everything_in_the_session(c) == {"mantle-token": 401, "narrow": 401, "entry": 401}


def test_logout_deletes_both_cookie_names_on_https(custody_client, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.test", raising=False)
    r = custody_client.get("/logout")
    names = {h.split("=", 1)[0] for h in r.headers.get_list("set-cookie")}
    assert {"__Host-origin_session", "origin_session"} <= names


def test_sign_out_ends_the_session_it_carries(custody_client, people):
    from origin.db.session import SessionLocal
    from origin.services import refresh_tokens
    from origin.services.auth_service import person_token_claims

    c = custody_client
    alice = people["alice"]
    _as(c, alice[0])
    with SessionLocal() as db:
        from origin.db import persons as db_persons
        refresh = refresh_tokens.issue(db, person_token_claims(
            db_persons.get_by_id(db, alice[0]), client_id="platform"))
        db.commit()
    assert c.post("/auth/sign-out", data={"refresh_token": refresh}).status_code == 200
    assert c.post(f"{BASE}/mantle-token", json={}, headers=_hdr()).status_code == 401
