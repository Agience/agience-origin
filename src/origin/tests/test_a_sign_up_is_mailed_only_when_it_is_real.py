"""FR-027 (John, 2026-11-14): Origin mails a sign-up only when it is certain the request is real.

2026-11-14: bots registered dot-mangled addresses (`m.el.in.da..san.ch.ez2.0.1.2@gmail.com`), and
Origin mailed each one: the owner got mail they never asked for, and a malformed address bounced.
"""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from origin.services import signup_guard as G


@pytest.fixture
def db_client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


@pytest.mark.parametrize("addr", [
    "person@example.com", "first.last+tag@example.co.uk", "a@localhost", "x_y-z@sub.example.org",
    "m.el.in.da.san.ch.ez@gmail.com",              # single dots in a Gmail local part
    "name+filter+more@gmail.com", "o'brien@example.ie", "a.b-c_d@mail.sub.example.technology",
    "user@example.museum", "user@xn--bcher-kva.example", "x@a.co", ("a" * 64) + "@example.com",
    "1234567890@example.com", "user=tag@example.com", "user{x}@example.com",
])
def test_an_address_smtp_carries_is_mailable(addr):
    assert G.mailable_address(addr)


@pytest.mark.parametrize("addr", [
    "m.el.in.da..san.ch.ez2.0.1.2@gmail.com",      # a doubled dot: the bounce that started this
    ".lead@example.com", "trail.@example.com", "no-at.example.com", "two@@example.com",
    "a@b@example.com", "sp ace@example.com", "x@-bad.com", "x@bad-.com", "x@exa_mple.com", "x@",
    "@example.com", ("a" * 65) + "@example.com", "x@" + ("a" * 250) + ".com",
])
def test_an_address_smtp_cannot_carry_is_not(addr):
    assert not G.mailable_address(addr)


@pytest.mark.real_signup_form
def test_a_form_counts_only_when_a_person_filled_it_in():
    t0 = 1_000_000.0
    tok = G.form_token(now=t0)
    assert not G.form_is_real(tok, "", now=t0 + 1)                     # too fast for a person
    assert G.form_is_real(tok, "", now=t0 + 10)
    assert not G.form_is_real(tok, "https://spam.example", now=t0 + 10)  # the hidden field filled
    assert not G.form_is_real(tok, "", now=t0 + G.MAX_FORM_AGE + 1)     # stale
    assert not G.form_is_real("", "", now=t0 + 10)                      # no token at all
    forged = tok.split(".")[0] + "." + "0" * 32
    assert not G.form_is_real(forged, "", now=t0 + 10)


def test_sign_up_mail_stops_at_the_hourly_ceiling():
    t = 5_000_000.0
    assert all(G.signup_mail_admitted(per_hour=3, now=t + i) for i in range(3))
    assert not G.signup_mail_admitted(per_hour=3, now=t + 4)
    assert G.signup_mail_admitted(per_hour=3, now=t + 3601)              # the hour has passed


@pytest.mark.real_signup_form
def test_a_bot_sign_up_is_answered_as_a_real_one_and_nothing_is_made_or_mailed(db_client, monkeypatch):
    client = db_client
    from origin.services import email_service
    sent = []
    monkeypatch.setattr(email_service, "send_email_verification", lambda *a, **k: sent.append(a))
    body = {"username": "bot@example.com", "email": "bot@example.com",
            "password": "correct horse battery staple", "form_token": "", "website": ""}
    r = client.post("/auth/password/register", json=body)
    assert r.status_code == 200 and r.json()["verification_required"] is True
    login = client.post("/auth/password/login", json={"identifier": "bot@example.com",
                                                      "password": body["password"]})
    assert login.status_code == 401, "an account was made for a form no person filled in"
    assert not sent


def test_a_malformed_address_is_refused_before_anything_is_made(db_client):
    client = db_client
    body = {"username": "x", "email": "m.el.in.da..san.ch.ez2.0.1.2@gmail.com",
            "password": "correct horse battery staple"}
    r = client.post("/auth/password/register", json=body)
    assert r.status_code == 400


def test_the_form_token_route_grants_nothing_and_is_not_cached(client):
    r = client.get("/auth/signup-form")
    assert r.status_code == 200 and "." in r.json()["form_token"]
    assert r.headers.get("cache-control") == "no-store"
