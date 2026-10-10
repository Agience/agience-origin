"""An OTP request says nothing about whether an address holds an account.

`/auth/otp/request` and `/auth/authorize/otp/request` are reachable without authentication. Each
answers `{"sent": true}` for an unknown address, for a known one, and for a known one whose limits
refuse another code; each spends one code hash on every one of those paths; and a code is mailed
after the response, so a mail server's latency is not part of what a caller can time.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI


def _setup():
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
        db_persons.create(s, {"email": "known@example.com", "name": "k"})
        s.commit()

    app = FastAPI()
    app.include_router(sys.modules["origin.routers.otp_router"].otp_router)

    def _db():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[session_module.get_db] = _db
    return app


def _hash_counter(monkeypatch):
    """Count code hashes without spending bcrypt time on them."""
    from origin.services import otp_service

    calls = []

    async def fake_hash(code):
        calls.append(code)
        return "$2b$04$" + "x" * 53

    monkeypatch.setattr(otp_service, "_hash_code_async", fake_hash)
    return calls


def test_a_capped_known_address_is_answered_as_an_unknown_one(monkeypatch):
    from fastapi.testclient import TestClient
    from origin.services import otp_service

    _hash_counter(monkeypatch)
    app = _setup()
    send = AsyncMock(return_value=True)
    with patch("origin.routers.otp_router.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=send):
        c = TestClient(app)
        cap = otp_service._window_cap()
        known = [c.post("/auth/otp/request", json={"email": "known@example.com"})
                 for _ in range(cap + 2)]
        unknown = [c.post("/auth/otp/request", json={"email": "nobody@example.com"})
                   for _ in range(cap + 2)]

    answers = {(r.status_code, r.text) for r in known + unknown}
    assert len(answers) == 1, f"the answers differ: {answers}"
    assert send.await_count == cap, "the cap no longer holds: the refused requests were mailed"


def test_every_path_spends_one_code_hash(monkeypatch):
    """Unknown, issued and refused requests each hash once, so none is the fast one."""
    from fastapi.testclient import TestClient
    from origin.services import otp_service

    calls = _hash_counter(monkeypatch)
    app = _setup()
    with patch("origin.routers.otp_router.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=AsyncMock(return_value=True)):
        c = TestClient(app)
        cap = otp_service._window_cap()
        per_path = []
        for email in ["nobody@example.com"] + ["known@example.com"] * (cap + 1):
            before = len(calls)
            c.post("/auth/otp/request", json={"email": email})
            per_path.append(len(calls) - before)
    assert per_path == [1] * len(per_path), per_path


def test_a_failed_mail_send_does_not_change_the_answer(monkeypatch):
    """The mail goes out after the response; a mail server that refuses it cannot turn a known
    address's answer into something an unknown address never gets."""
    from fastapi.testclient import TestClient

    _hash_counter(monkeypatch)
    app = _setup()
    with patch("origin.routers.otp_router.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=AsyncMock(return_value=False)):
        c = TestClient(app)
        r = c.post("/auth/otp/request", json={"email": "known@example.com"})
    assert (r.status_code, r.json()) == (200, {"sent": True, "expires_in": 600})
