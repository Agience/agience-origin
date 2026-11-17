"""FR-027: sign-up limits what one client can create, what one address is mailed, and how long an
unverified account lives, and it answers a refused sign-up exactly as an admitted one.

- Three sign-ups an hour from one address, twenty a day from one /24 (IPv6 /48).
- One confirmation link a day to an address, and none once the account is a week old.
- An account nobody verified within the week is deleted, unless something else holds it.
- The new-account notice is marked `[SPAM?]` with what looked like a bot; it blocks nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from origin.services import signup_guard

pytestmark = pytest.mark.real_signup_limits

_PW = "a-long-enough-password"


@pytest.fixture
def db_client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _register(client, email: str):
    return client.post("/auth/password/register", json={
        "username": email, "email": email, "password": _PW, "name": "Ada Lovelace",
        "verify_nonce": "n",
    })


def _persons(email: str) -> int:
    from origin.db.session import SessionLocal
    from origin.models.person import Person

    with SessionLocal() as db:
        return db.query(Person).filter(Person.email == email).count()


# ---------------------------------------------------------------------------
# Per-client and per-network caps
# ---------------------------------------------------------------------------
def test_one_address_signs_up_three_times_an_hour():
    t = 1_000_000.0
    assert [signup_guard.signup_from_admitted("203.0.113.5", now=t + i)[0] for i in range(4)] == \
        [True, True, True, False]
    assert signup_guard.signup_from_admitted("203.0.113.5", now=t + 3601)[0] is True


def test_a_second_sign_up_from_one_client_is_a_burst():
    assert signup_guard.signup_from_admitted("203.0.113.6", now=1.0) == (True, False)
    assert signup_guard.signup_from_admitted("203.0.113.6", now=2.0) == (True, True)


def test_one_network_signs_up_twenty_times_a_day():
    t = 1_000_000.0
    admitted = [signup_guard.signup_from_admitted(f"198.51.100.{i}", now=t + i)[0] for i in range(21)]
    assert admitted[:20] == [True] * 20 and admitted[20] is False
    # Another /24 is another network.
    assert signup_guard.signup_from_admitted("198.51.101.1", now=t + 30)[0] is True
    assert signup_guard.signup_from_admitted("198.51.100.99", now=t + 86401)[0] is True


def test_an_ipv6_network_is_its_48():
    assert signup_guard._network("2001:db8:1:2::5") == signup_guard._network("2001:db8:1:ffff::9")
    assert signup_guard._network("2001:db8:1::1") != signup_guard._network("2001:db8:2::1")
    assert signup_guard._network("testclient") == "testclient"


def test_a_refused_sign_up_answers_as_an_admitted_one_and_creates_nothing(db_client):
    sent = MagicMock()
    with patch("origin.routers.auth_router.email_verification_required", return_value=True), \
            patch("origin.routers.auth_router.email_service.send_email_verification", sent):
        answers = [_register(db_client, f"cap{i}@example.com") for i in range(4)]
    assert all(r.status_code == 200 for r in answers)
    assert answers[3].json() == {"verification_required": True, "email": "cap3@example.com"}
    assert {k for k in answers[0].json()} == {k for k in answers[3].json()}
    assert [_persons(f"cap{i}@example.com") for i in range(4)] == [1, 1, 1, 0]


# ---------------------------------------------------------------------------
# Confirmation mail
# ---------------------------------------------------------------------------
def test_an_address_gets_one_confirmation_link_a_day():
    t = 1_000_000.0
    assert signup_guard.verification_mail_admitted("Once@Example.com", now=t) is True
    assert signup_guard.verification_mail_admitted("once@example.com", now=t + 60) is False
    assert signup_guard.verification_mail_admitted("once@example.com", now=t + 86401) is True


def test_a_week_old_account_gets_no_link():
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=signup_guard.UNVERIFIED_DAYS)
    assert signup_guard.verification_mail_admitted("old@example.com", old, now=now.timestamp()) is False
    young = now - timedelta(days=1)
    assert signup_guard.verification_mail_admitted("old@example.com", young, now=now.timestamp()) is True


def test_asking_again_the_same_day_sends_no_second_link(db_client):
    sent = MagicMock()
    with patch("origin.routers.auth_router.email_verification_required", return_value=True), \
            patch("origin.routers.auth_router.email_service.is_configured", return_value=True), \
            patch("origin.routers.auth_router.email_service.send_email_verification", sent):
        assert _register(db_client, "twice@example.com").status_code == 200
        again = db_client.post("/auth/email/verify-request",
                               json={"email": "twice@example.com", "verify_nonce": "n"})
    assert again.status_code == 200 and again.json() == {"sent": True}
    assert sent.call_count == 1


# ---------------------------------------------------------------------------
# Soft signals and the notice
# ---------------------------------------------------------------------------
def test_soft_signals():
    assert signup_guard.soft_signals("ada@example.com", "ada@example.com", "Ada") == []
    assert signup_guard.soft_signals("ada@example.com", "ada", "Ada") == ["username copies the address"]
    got = signup_guard.soft_signals("info@example.com", "info@example.com", " ", burst=True)
    assert got == ["blank name", "role address", "several sign-ups from one client within the hour"]


def test_the_notice_is_marked_when_a_signal_trips():
    from origin.services.account_notify import _describe

    base = dict(email="a@example.com", username="a@example.com", name="", email_verified=False,
                created_time="", id="x")
    subject, body = _describe(SimpleNamespace(**base, _signup_signals=["blank name"]))
    assert "[SPAM?] New account: a@example.com" in subject and "signals   : blank name" in body
    subject, body = _describe(SimpleNamespace(**base))
    assert "[SPAM?]" not in subject and "signals" not in body


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------
def _make(email: str, days_old: float, verified: bool = False) -> str:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        p = db_persons.create(db, {"email": email, "name": "N", "email_verified": verified})
        p.created_time = datetime.now(timezone.utc) - timedelta(days=days_old)
        db.commit()
        return str(p.id)


def test_an_account_nobody_verified_in_a_week_is_deleted(db_client):
    import uuid

    from origin.db.session import SessionLocal
    from origin.models.person_identity import PersonIdentity
    from origin.services.person_service import expire_unverified

    _make("stale@example.com", 8)
    _make("young@example.com", 2)
    _make("proved@example.com", 30, verified=True)
    held = _make("held@example.com", 30)
    with SessionLocal() as db:
        db.add(PersonIdentity(person_id=uuid.UUID(held), method="oidc", provider="google",
                              subject="s-1"))
        db.commit()

    with patch("origin.services.auth_service.email_verification_required", return_value=True):
        with SessionLocal() as db:
            assert expire_unverified(db) == 1
    assert _persons("stale@example.com") == 0
    assert [_persons(e) for e in ("young@example.com", "proved@example.com", "held@example.com")] \
        == [1, 1, 1]


def test_an_address_that_needs_no_verification_is_never_expired(db_client):
    from origin.db.session import SessionLocal
    from origin.services.person_service import expire_unverified

    _make("exempt@example.com", 30)
    with patch("origin.services.auth_service.email_verification_required", return_value=False):
        with SessionLocal() as db:
            assert expire_unverified(db) == 0
    assert _persons("exempt@example.com") == 1
