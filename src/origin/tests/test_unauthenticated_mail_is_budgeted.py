"""Every unauthenticated route that mails is charged to one budget.

Registration takes no proof of the address, so a caller can register any address they like and
then hold its password. Each route that mails such an address — a sign-in code, the confirmation
link sent on registration, and the one resent on a password sign-in to an unconfirmed account —
is therefore a way to have Origin mail a stranger. They share `guess_budget`'s mail budget: per
(address, client), per address, and per client across addresses.

An unconfirmed address is sent its confirmation link and never a sign-in code: entering a code
confirms the address, so a code would confirm it outside the sign-up gate.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI


def _setup(persons):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    import origin.db.session  # noqa: F401
    import origin.models  # noqa: F401
    import origin.routers.auth_router  # noqa: F401
    import origin.routers.otp_router  # noqa: F401
    from origin.db import persons as db_persons
    from origin.db.base import Base

    session_module = sys.modules["origin.db.session"]
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    with Session(engine) as s:
        for fields in persons:
            db_persons.create(s, fields)
        s.commit()

    app = FastAPI()
    app.include_router(sys.modules["origin.routers.otp_router"].otp_router)
    app.include_router(sys.modules["origin.routers.auth_router"].auth_router)

    def _db():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[session_module.get_db] = _db
    return app


@pytest.fixture
def mail(monkeypatch):
    """Verification required everywhere, mail configured, and both kinds of send recorded."""
    from origin.services import otp_service

    hashes = []

    async def fake_hash(code):
        hashes.append(code)
        return "$2b$04$" + "x" * 53

    monkeypatch.setattr(otp_service, "_hash_code_async", fake_hash)
    monkeypatch.setattr("origin.routers.auth_router.email_verification_required", lambda e: True)
    codes = AsyncMock(return_value=True)
    links = AsyncMock(return_value=True)
    with patch("origin.services.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=codes), \
            patch("origin.services.email_service.send_email_verification", new=links), \
            patch("origin.routers.auth_router.create_jwt_token", return_value="verify.jwt"):
        yield {"codes": codes, "links": links, "hashes": hashes}


@pytest.fixture
def small_client_cap(monkeypatch):
    """One client's cap across addresses, shrunk to one address's worth so a test can cross it."""
    from origin.services import guess_budget

    monkeypatch.setattr(guess_budget, "_MAIL_SEND_PEOPLE_PER_CLIENT", 1)
    return guess_budget.mail_send_client_cap()


def test_an_unconfirmed_address_gets_its_link_not_a_code(mail):
    from fastapi.testclient import TestClient

    app = _setup([{"email": "new@example.com", "name": "n", "email_verified": False}])
    r = TestClient(app).post("/auth/otp/request", json={"email": "new@example.com"})

    assert (r.status_code, r.json()) == (200, {"sent": True, "expires_in": 600})
    assert mail["codes"].await_count == 0, "a code was mailed to an unconfirmed address"
    assert mail["links"].await_count == 1
    assert len(mail["hashes"]) == 1, "the unconfirmed path must spend one code hash like the others"


def test_a_confirmed_address_still_gets_a_code(mail):
    from fastapi.testclient import TestClient

    app = _setup([{"email": "old@example.com", "name": "o", "email_verified": True}])
    TestClient(app).post("/auth/otp/request", json={"email": "old@example.com"})

    assert mail["codes"].await_count == 1
    assert mail["links"].await_count == 0


def test_one_client_cannot_mail_codes_to_unbounded_addresses(mail, small_client_cap):
    from fastapi.testclient import TestClient

    people = [{"email": f"p{i}@example.com", "name": "p", "email_verified": True}
              for i in range(small_client_cap + 3)]
    c = TestClient(_setup(people))
    answers = {c.post("/auth/otp/request", json={"email": p["email"]}).text for p in people}

    assert len(answers) == 1, f"a throttled request is answered differently: {answers}"
    assert mail["codes"].await_count == small_client_cap


def test_signing_in_to_an_unconfirmed_account_does_not_mail_without_bound(mail):
    """Whoever registered an address holds its password, and each sign-in on it resends the link."""
    from fastapi.testclient import TestClient
    from origin.services import guess_budget
    from origin.services.auth_service import hash_password

    app = _setup([{"email": "victim@example.com", "name": "v", "email_verified": False,
                   "password_hash": hash_password("correct-horse-battery")}])
    c = TestClient(app)
    cap = guess_budget.mail_send_cap()
    statuses = {c.post("/auth/password/login",
                       json={"identifier": "victim@example.com",
                             "password": "correct-horse-battery"}).status_code
                for _ in range(cap + 3)}

    assert statuses == {403}, statuses
    assert mail["links"].await_count == cap


def test_one_client_cannot_register_unbounded_confirmation_mails(mail, small_client_cap):
    from fastapi.testclient import TestClient

    c = TestClient(_setup([]))
    bodies = set()
    for i in range(small_client_cap + 3):
        r = c.post("/auth/password/register",
                   json={"username": f"r{i}@example.com", "email": f"r{i}@example.com",
                         "password": "correct-horse-battery-staple"})
        assert r.status_code == 200, r.text
        bodies.add(tuple(sorted(r.json())))

    assert len(bodies) == 1, f"a throttled registration is answered differently: {bodies}"
    assert mail["links"].await_count == small_client_cap


def test_an_address_on_a_dotless_domain_is_still_mailed(mail):
    """`admin@localhost` or `user@intranet` holds accounts; the budget must not read it as junk."""
    from fastapi.testclient import TestClient

    app = _setup([{"email": "admin@localhost", "name": "a", "email_verified": True}])
    TestClient(app).post("/auth/otp/request", json={"email": "admin@localhost"})

    assert mail["codes"].await_count == 1


def test_one_client_asking_for_codes_does_not_use_up_the_owners(mail):
    """A client spending its own (address, client) budget leaves the owner, elsewhere, a code."""
    from fastapi.testclient import TestClient
    from origin.services import guess_budget

    app = _setup([{"email": "owner@example.com", "name": "o", "email_verified": True}])
    other = TestClient(app, client=("198.51.100.9", 1))
    for _ in range(guess_budget.mail_send_cap() + 2):
        other.post("/auth/otp/request", json={"email": "owner@example.com"})
    before = mail["codes"].await_count
    TestClient(app, client=("203.0.113.7", 1)).post(
        "/auth/otp/request", json={"email": "owner@example.com"})

    assert before == guess_budget.mail_send_cap()
    assert mail["codes"].await_count == before + 1, "the owner was locked out of a code"
