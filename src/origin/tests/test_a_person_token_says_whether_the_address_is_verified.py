"""Every access token that names a person carries `email_verified`, and it is the stored fact.

Peers decide access from it: Mantle matches an email or domain invite only when the token asserts
`email_verified`, and reads its absence as false. A sign-in route that minted without it would
leave that person unable to claim any invite, and one that asserted it unconditionally would let an
unconfirmed address claim someone else's.

Each route is driven through the real app and asserted in both directions where the route can mint
for an unverified person, so a mint that hard-coded either value fails here.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

_PW = "a-long-enough-password"


@pytest.fixture
def db_client(origin_app):
    """The real app over in-memory SQLite with tables (see `test_authorize_local_methods.db_client`
    for why `create_all` runs inside the context)."""
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _make_person(*, email: str, email_verified: bool, password: str | None = None) -> str:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import hash_password

    with SessionLocal() as db:
        fields = {"email": email, "name": "Person", "email_verified": email_verified}
        if password:
            fields["password_hash"] = hash_password(password)
        person = db_persons.create(db, fields)
        db.commit()
        return str(person.id)


def _assert_carries(body: dict, expected: bool) -> None:
    """Both tokens of a grant, with the claim in the shape Mantle's `_claim_email_verified` reads:
    a real bool beside an `email` claim holding an address."""
    for kind in ("access_token", "refresh_token"):
        claims = _claims(body[kind])
        assert "email_verified" in claims, f"the {kind} does not say whether the address is verified"
        assert claims["email_verified"] is expected, f"{kind}: {claims['email_verified']!r}"
        assert isinstance(claims["email"], str) and "@" in claims["email"]


# ---------------------------------------------------------------------------
# Password sign-in and registration
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("verified", [True, False])
def test_password_login_states_the_stored_fact(db_client, monkeypatch, verified):
    import origin.routers.auth_router as ar

    # Unverified sign-in is refused where verification is required; here it is not, so the route
    # mints for an unverified person and the token must say so.
    monkeypatch.setattr(ar, "email_verification_required", lambda _email: False)
    _make_person(email=f"login-{verified}@example.com", email_verified=verified, password=_PW)
    r = db_client.post("/auth/password/login",
                       json={"identifier": f"login-{verified}@example.com", "password": _PW})
    assert r.status_code == 200, r.text
    _assert_carries(r.json(), verified)


def test_password_registration_without_required_verification_is_verified(db_client, monkeypatch):
    """Where no confirmation is required the account is created verified, and the token says so."""
    import origin.routers.auth_router as ar

    monkeypatch.setattr(ar, "email_verification_required", lambda _email: False)
    r = db_client.post("/auth/password/register",
                       json={"username": "reg@example.com", "email": "reg@example.com",
                             "password": _PW})
    assert r.status_code == 200, r.text
    _assert_carries(r.json(), True)


def test_a_confirmed_link_signs_in_with_a_verified_token(db_client):
    from unittest.mock import MagicMock, patch
    from urllib.parse import parse_qs, urlparse

    sent = MagicMock()
    with patch("origin.routers.auth_router.email_verification_required", return_value=True), \
            patch("origin.routers.auth_router.email_service.send_email_verification", sent):
        r = db_client.post("/auth/password/register", json={
            "username": "confirm@example.com", "email": "confirm@example.com", "password": _PW,
            "verify_nonce": "the-nonce",
        })
    assert r.json()["verification_required"] is True
    token = parse_qs(urlparse(sent.call_args.args[1]).query)["token"][0]

    r = db_client.post("/auth/email/verify-confirm",
                       json={"token": token, "verify_nonce": "the-nonce", "password": _PW})
    assert r.status_code == 200, r.text
    _assert_carries(r.json(), True)


# ---------------------------------------------------------------------------
# OTP and passkey
# ---------------------------------------------------------------------------
def test_an_otp_sign_in_is_verified_because_the_code_reached_the_mailbox(db_client, monkeypatch):
    from origin.services import otp_service

    person_id = _make_person(email="otp@example.com", email_verified=False)

    async def _accept(_db, _email, _code):
        return person_id

    monkeypatch.setattr(otp_service, "verify_otp", _accept)
    r = db_client.post("/auth/otp/verify", json={"email": "otp@example.com", "code": "123456"})
    assert r.status_code == 200, r.text
    _assert_carries(r.json(), True)


@pytest.mark.parametrize("verified", [True, False])
def test_a_passkey_sign_in_states_the_stored_fact(db_client, monkeypatch, verified):
    """A passkey proves the credential, not the mailbox: the token repeats what is stored."""
    from origin.services import passkey_service

    person_id = _make_person(email=f"pk-{verified}@example.com", email_verified=verified)
    monkeypatch.setattr(passkey_service, "verify_authentication", lambda **_kw: person_id)
    r = db_client.post("/auth/passkey/login-complete", json={"credential": {}, "challenge": "c"})
    assert r.status_code == 200, r.text
    _assert_carries(r.json(), verified)


# ---------------------------------------------------------------------------
# The authorization-code grant, and a refresh of it
# ---------------------------------------------------------------------------
def _code_grant(client, *, email: str, email_verified: bool) -> dict:
    import origin.routers.auth_router as ar
    from origin import config

    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    ar.authorization_codes["code-" + email] = {
        "user_info": {"provider": "google", "sub": "sub-" + email, "email": email,
                      "name": "Person", "picture": None, "email_verified": email_verified},
        "client_id": config.PLATFORM_CLIENT_ID,
        "redirect_uri": "http://localhost:8080/cb",
        "scope": "read write",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "timestamp": datetime.now(timezone.utc),
    }
    r = client.post("/auth/token", data={
        "grant_type": "authorization_code", "code": "code-" + email,
        "redirect_uri": "http://localhost:8080/cb", "client_id": config.PLATFORM_CLIENT_ID,
        "code_verifier": verifier,
    })
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("verified", [True, False])
def test_the_code_grant_states_the_stored_fact_and_a_refresh_carries_it(db_client, verified):
    body = _code_grant(db_client, email=f"code-{verified}@example.com", email_verified=verified)
    _assert_carries(body, verified)

    r = db_client.post("/auth/token",
                       data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]})
    assert r.status_code == 200, r.text
    assert _claims(r.json()["access_token"])["email_verified"] is verified


# ---------------------------------------------------------------------------
# The operator's first tokens
# ---------------------------------------------------------------------------
def _stored_verified(email: str) -> bool:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        return bool(db_persons.get_by_email(db, email).email_verified)


def test_the_setup_wizard_operator_token_states_the_stored_fact(db_client, monkeypatch):
    from origin.routers import setup_router as sr

    monkeypatch.setattr(sr, "get_setup_token", lambda: "tok")
    monkeypatch.setattr(sr, "delete_setup_token", lambda: None)
    monkeypatch.setattr(sr.platform_settings, "needs_setup", lambda: True)
    monkeypatch.setattr(sr.platform_settings, "set_many", lambda db, items, updated_by=None: None)
    r = db_client.post("/setup/complete", headers={"X-Setup-Token": "tok"}, json={
        "settings": [], "operator": {"email": "op@example.com", "name": "Op", "password": _PW},
    })
    assert r.status_code == 200, r.text
    _assert_carries(r.json(), _stored_verified("op@example.com"))
