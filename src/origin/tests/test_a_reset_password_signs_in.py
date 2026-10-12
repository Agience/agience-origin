"""A password set through the emailed reset link is the password sign-in accepts, and the old one
stops working: the whole loop, over the real routes and a real database.

2026-10-11: a tester reported that after resetting, password sign-in still answered 401. The stored
hash had changed at the reset; this pins that the server's half of the loop holds.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from urllib.parse import parse_qs, urlparse

_OLD = "the-old-password-1"
_NEW = "the-new-password-2"


@pytest.fixture
def db_client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


@pytest.mark.parametrize("email", ["tester@outlook.example", "someone+test1@gmail.example"])
def test_the_reset_password_signs_in_and_the_old_one_does_not(db_client, monkeypatch, email):
    import origin.routers.auth_router as ar
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services import email_service
    from origin.services.auth_service import hash_password

    with SessionLocal() as db:
        db_persons.create(db, {"email": email, "username": email, "name": "T", "email_verified": True,
                               "password_hash": hash_password(_OLD)})
        db.commit()
    links: list[str] = []
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "send_password_reset", lambda to, url, context="": links.append(url))
    monkeypatch.setattr(ar, "_mail_send_admitted", lambda request, e, what: "tag")

    def login(pw):
        return db_client.post("/auth/password/login", json={"identifier": email, "password": pw})
    assert login(_OLD).status_code == 200

    assert db_client.post("/auth/password/reset-request", json={"email": email}).json() == {"sent": True}
    (link,) = links
    query = parse_qs(urlparse(link).query)
    token = query["token"][0]
    assert "email" not in query, "the link names no account; the token does"
    # 2026-10-12: the reset mail went to Outlook's junk while the code mail did not; the link carried
    # a ~600-character signed token. It is now short and random, and only its hash is stored.
    assert len(token) <= 40 and "." not in token, token
    from origin.models.password_reset import PasswordReset
    with SessionLocal() as db:
        stored = [r.token_hash for r in db.query(PasswordReset).all()]
    assert token not in stored and len(stored) == 1
    named = db_client.post("/auth/password/reset-check", json={"token": token})
    assert named.status_code == 200 and named.json() == {"email": email}
    r = db_client.post("/auth/password/reset-confirm", json={"token": token, "new_password": _NEW})
    assert r.status_code == 200, r.text

    assert login(_NEW).status_code == 200, "the password just set signs in"
    assert login(_OLD).status_code == 401, "the replaced password does not"
    again = db_client.post("/auth/password/reset-confirm", json={"token": token, "new_password": "x" * 12})
    assert again.status_code == 400, "the link works once"
    used = db_client.post("/auth/password/reset-check", json={"token": token})
    assert used.status_code == 400, "a used link names nothing"
    assert db_client.post("/auth/password/reset-check", json={"token": "forged.token.x"}).status_code == 400
    with SessionLocal() as db:
        assert db.query(PasswordReset).count() == 0, "using a link spends every link for the account"


def test_an_expired_link_is_refused(db_client, monkeypatch):
    from datetime import datetime, timedelta, timezone

    import origin.routers.auth_router as ar
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.models.password_reset import PasswordReset
    from origin.services import email_service
    from origin.services.auth_service import hash_password

    email = "late@example.invalid"
    with SessionLocal() as db:
        db_persons.create(db, {"email": email, "username": email, "name": "T", "email_verified": True,
                               "password_hash": hash_password(_OLD)})
        db.commit()
    links: list[str] = []
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "send_password_reset", lambda to, url, context="": links.append(url))
    monkeypatch.setattr(ar, "_mail_send_admitted", lambda request, e, what: "tag")
    db_client.post("/auth/password/reset-request", json={"email": email})
    token = parse_qs(urlparse(links[0]).query)["token"][0]
    with SessionLocal() as db:
        db.query(PasswordReset).update({"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
        db.commit()
    assert db_client.post("/auth/password/reset-check", json={"token": token}).status_code == 400
    r = db_client.post("/auth/password/reset-confirm", json={"token": token, "new_password": _NEW})
    assert r.status_code == 400
