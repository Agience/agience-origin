"""One account per address, however the address is written.

2026-11-09: an account was created for `john@ikailo.com.` while `john@ikailo.com` already had one.
Mail to both reaches one mailbox, but the two strings differ, so the unique column let both in.
Every address Origin stores or looks up now goes through one canonical form
(`origin.services.email_address`): stripped, lower-cased, the domain without a trailing dot and in
its IDNA ASCII form. Where a person types an address to create an account, anything else is
refused, not rewritten; where an address is looked up, it is canonicalised first.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

_PW = "a-long-enough-password"


@pytest.fixture
def db_client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _seed(email: str, *, password: bool = True, username: str | None = None) -> str:
    """A stored row exactly as given, as a legacy row would be: no canonicalisation."""
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import hash_password

    with SessionLocal() as db:
        person = db_persons.create(db, {
            "email": email, "username": username or email, "name": "",
            "password_hash": hash_password(_PW) if password else None,
            "email_verified": True,
        })
        db.commit()
        return str(person.id)


def _stored_emails() -> list[str]:
    from sqlalchemy import select

    from origin.db.session import SessionLocal
    from origin.models.person import Person

    with SessionLocal() as db:
        return sorted(e for e in db.execute(select(Person.email)).scalars().all() if e)


def _register(client, email: str, username: str):
    return client.post("/auth/password/register",
                       json={"username": username, "email": email, "password": _PW})


# -- registration ----------------------------------------------------------------------------------

def test_a_trailing_dot_address_is_refused_when_the_dotless_one_has_an_account(db_client):
    _seed("john@ikailo.com")
    r = _register(db_client, "john@ikailo.com.", "john-dot")
    assert r.status_code == 400, r.text
    assert _stored_emails() == ["john@ikailo.com"]


def test_a_trailing_dot_address_is_refused_when_no_one_holds_the_dotless_one(db_client):
    r = _register(db_client, "new@example.org.", "new-dot")
    assert r.status_code == 400, r.text
    assert _stored_emails() == []


def test_a_unicode_domain_is_refused_at_registration_rather_than_rewritten(db_client):
    r = _register(db_client, "a@bücher.de", "uni")
    assert r.status_code == 400, r.text
    assert _stored_emails() == []


def test_the_service_that_both_register_routes_call_refuses_a_non_canonical_address(db_client):
    """`/auth/authorize/register` and `/auth/password/register` both create through this."""
    from origin.db.session import SessionLocal
    from origin.services import person_service

    with SessionLocal() as db:
        for email in ("x@d.com.", "x@bücher.de", "x@d..com"):
            with pytest.raises(ValueError):
                person_service.create_user_with_password(
                    db, username=email, name="", password_hash="h", email=email)
    assert _stored_emails() == []


def test_case_and_surrounding_space_still_map_to_one_account(db_client):
    r = _register(db_client, "  Alice@Example.COM ", "alice")
    assert r.status_code == 200, r.text
    assert _stored_emails() == ["alice@example.com"]
    assert _register(db_client, "alice@example.com", "alice2").status_code == 400

    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        assert db_persons.get_by_email(db, " ALICE@example.com ").email == "alice@example.com"


# -- lookups ---------------------------------------------------------------------------------------

def test_an_idn_domain_stored_as_punycode_is_found_by_its_unicode_spelling(db_client):
    pid = _seed("anna@xn--bcher-kva.de")
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services import person_service

    with SessionLocal() as db:
        assert str(db_persons.get_by_email(db, "Anna@Bücher.de").id) == pid
        assert str(db_persons.get_by_email(db, "anna@bücher.de.").id) == pid
        assert str(person_service.get_or_create_user_by_email(db, "anna@bücher.de").id) == pid
        db.commit()
    assert _stored_emails() == ["anna@xn--bcher-kva.de"]


def test_a_code_requested_for_a_trailing_dot_address_reaches_the_one_account(db_client, monkeypatch):
    pid = _seed("x@d.com")
    from origin.services import otp_service

    monkeypatch.setattr(otp_service, "_generate_code", lambda: "123456")

    async def fake_hash(code):
        return "hash:" + code

    async def fake_verify(code, code_hash):
        return code_hash == "hash:" + code

    monkeypatch.setattr(otp_service, "_hash_code_async", fake_hash)
    monkeypatch.setattr(otp_service, "_verify_code_hash_async", fake_verify)
    sent = AsyncMock(return_value=True)
    with patch("origin.services.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=sent):
        r = db_client.post("/auth/otp/request", json={"email": "x@d.com."})
    assert r.status_code == 200, r.text
    sent.assert_called_once()
    assert sent.call_args.args[0] == "x@d.com"

    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        got = asyncio.run(otp_service.verify_otp(db, "X@D.com.", "123456"))
    assert got == pid
    assert _stored_emails() == ["x@d.com"]


def test_a_reset_requested_for_a_trailing_dot_address_reaches_the_one_account(db_client):
    _seed("r@d.com")
    send = AsyncMock(return_value=True)
    with patch("origin.services.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_password_reset", new=send):
        r = db_client.post("/auth/password/reset-request", json={"email": "r@d.com."})
    assert r.status_code == 200, r.text
    send.assert_called_once()
    assert send.call_args.args[0] == "r@d.com"
    assert _stored_emails() == ["r@d.com"]


def test_a_provider_s_trailing_dot_address_is_not_a_second_account(db_client):
    _seed("p@d.com")
    from origin.db.session import SessionLocal
    from origin.services import person_service

    with SessionLocal() as db:
        with pytest.raises(person_service.IdentityLinkRefused):
            person_service.get_or_create_user_by_oidc_identity(
                db, "google", "sub-1", "P@D.com.", "P", email_verified=True)
        db.rollback()
        made = person_service.get_or_create_user_by_oidc_identity(
            db, "google", "sub-2", "q@bücher.de.", "Q", email_verified=True)
        db.commit()
        assert made.email == "q@xn--bcher-kva.de"
    assert _stored_emails() == ["p@d.com", "q@xn--bcher-kva.de"]


# -- the rows stored before -----------------------------------------------------------------------

def test_a_stored_trailing_dot_row_is_never_what_the_canonical_address_finds(db_client):
    real = _seed("john@ikailo.com")
    _seed("john@ikailo.com.", username="john-dot")
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        assert str(db_persons.get_by_email(db, "john@ikailo.com").id) == real
        assert str(db_persons.get_by_email(db, "john@ikailo.com.").id) == real


def test_the_report_lists_a_stored_trailing_dot_address(db_client):
    real = _seed("john@ikailo.com")
    dotted = _seed("john@ikailo.com.", username="john-dot")
    from origin import admin

    said: list[str] = []
    assert admin.run(["person", "noncanonical"], out=said.append) == 0
    text = "\n".join(said)
    assert dotted in text and "email='john@ikailo.com.'" in text
    assert f"canonical_holder={real}" in text
    assert real not in text.replace(f"canonical_holder={real}", "")
