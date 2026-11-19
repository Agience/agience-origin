"""The account page shows the account Origin holds, never only what the browser's token says.

A token from a store that no longer holds the account, or for an account since deactivated, is
refused at `/auth/userinfo`, and the page signs out on that refusal.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_PW = "a-long-enough-password"
_WEB = Path(__file__).resolve().parents[1] / "web"


@pytest.fixture
def db_client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _make_person(email: str) -> str:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import hash_password

    with SessionLocal() as db:
        person = db_persons.create(db, {"email": email, "name": "Grace Hopper", "email_verified": True,
                                        "password_hash": hash_password(_PW)})
        db.commit()
        return str(person.id)


def _token(client, email: str) -> str:
    r = client.post("/auth/password/login", json={"identifier": email, "password": _PW})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _me(client, token: str):
    return client.get("/auth/userinfo", headers={"Authorization": "Bearer " + token})


def test_origin_answers_who_is_signed_in_from_its_own_store(db_client):
    pid = _make_person("who1@example.com")
    r = _me(db_client, _token(db_client, "who1@example.com"))
    assert r.status_code == 200
    assert r.json()["id"] == pid and r.json()["name"] == "Grace Hopper"


def test_a_token_for_an_account_the_store_no_longer_holds_is_refused(db_client):
    from origin.db.session import SessionLocal
    from origin.models.person import Person

    pid = _make_person("who2@example.com")
    token = _token(db_client, "who2@example.com")
    with SessionLocal() as db:
        db.query(Person).filter(Person.id == uuid.UUID(pid)).delete()
        db.commit()
    assert _me(db_client, token).status_code == 404


def test_a_token_minted_before_deactivation_reads_no_account(db_client):
    from origin import admin
    from origin.services.auth_service import DEACTIVATED_DETAIL

    _make_person("who3@example.com")
    token = _token(db_client, "who3@example.com")
    assert admin.run(["person", "deactivate", "who3@example.com", "--reason", "r"], out=lambda s: None) == 0
    r = _me(db_client, token)
    assert r.status_code == 403 and r.json()["detail"] == DEACTIVATED_DETAIL


def test_the_page_asks_origin_and_signs_out_on_a_refusal():
    js = (_WEB / "account-page.js").read_text(encoding="utf-8-sig")
    assert "decodeJwt(" not in js, "the page shows nothing decoded from the browser's token"
    assert 'fetch("/auth/userinfo"' in js
    assert "r.status === 401" in js and 'clearToken(); location.replace("/logout")' in js
