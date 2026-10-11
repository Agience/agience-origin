"""A deactivated account signs in nowhere and is mailed nothing; reactivating restores it exactly.

2026-10-11: two probe accounts had been "deactivated" by clearing their password hashes, because
Origin had no such state. Their owner then saw sign-in fail with "wrong password" after a reset
that reached a different account. Deactivation is now a state every route honours with one 403,
and `python -m origin.admin person reactivate` undoes it, putting back a removed hash on request.
"""

from __future__ import annotations

import json

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


def _make_person(email: str, password: str | None = _PW, username: str | None = None) -> str:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import hash_password

    with SessionLocal() as db:
        fields = {"email": email, "name": "Person", "email_verified": True, "username": username}
        if password:
            fields["password_hash"] = hash_password(password)
        person = db_persons.create(db, fields)
        db.commit()
        return str(person.id)


def _admin(*argv: str) -> tuple[int, str]:
    from origin import admin

    said: list[str] = []
    return admin.run(list(argv), out=said.append), "\n".join(said)


def _login(client, who: str, password: str = _PW):
    return client.post("/auth/password/login", json={"identifier": who, "password": password})


def test_a_deactivated_account_is_refused_with_one_clear_answer_and_reactivation_restores_it(db_client):
    from origin.services.auth_service import DEACTIVATED_DETAIL

    _make_person("d1@example.com")
    assert _login(db_client, "d1@example.com").status_code == 200

    code, said = _admin("person", "deactivate", "d1@example.com", "--reason", "looked like a probe")
    assert code == 0 and "deactivated=20" in said and "looked like a probe" in said
    r = _login(db_client, "d1@example.com")
    assert r.status_code == 403 and r.json()["detail"] == DEACTIVATED_DETAIL
    assert _login(db_client, "d1@example.com", "the-wrong-password-x").status_code == 401, \
        "only the password's holder learns the account is deactivated"

    code, said = _admin("person", "reactivate", "d1@example.com")
    assert code == 0 and "deactivated=no" in said and "password=set" in said
    assert _login(db_client, "d1@example.com").status_code == 200, "reactivation restores it exactly"


def test_a_deactivated_account_cannot_refresh(db_client):
    _make_person("d2@example.com")
    refresh = _login(db_client, "d2@example.com").json()["refresh_token"]
    _admin("person", "deactivate", "d2@example.com", "--reason", "r")
    r = db_client.post("/auth/token", data={"grant_type": "refresh_token", "refresh_token": refresh})
    assert r.status_code == 403
    _admin("person", "reactivate", "d2@example.com")
    r = db_client.post("/auth/token", data={"grant_type": "refresh_token", "refresh_token": refresh})
    assert r.status_code == 200


def test_a_deactivated_account_is_mailed_no_code_and_no_reset(db_client, monkeypatch):
    import origin.routers.auth_router as ar
    from origin.services import email_service, otp_service

    sent: list[str] = []
    monkeypatch.setattr(otp_service, "deliver_otp", lambda email, code: sent.append(f"code:{email}"))
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "send_password_reset", lambda to, url: sent.append(f"reset:{to}"))
    monkeypatch.setattr(ar, "_mail_send_admitted", lambda request, email, what: "tag")

    _make_person("d3@example.com")
    _admin("person", "deactivate", "d3@example.com", "--reason", "r")
    assert db_client.post("/auth/otp/request", json={"email": "d3@example.com"}).status_code == 200
    assert db_client.post("/auth/password/reset-request", json={"email": "d3@example.com"}).json() == {"sent": True}
    assert sent == [], "a deactivated account is mailed nothing, with the reply an unknown address gets"

    _admin("person", "reactivate", "d3@example.com")
    db_client.post("/auth/password/reset-request", json={"email": "d3@example.com"})
    assert sent == ["reset:d3@example.com"]


def test_a_hash_removed_by_hand_is_restored_from_its_backup_and_only_then(db_client, tmp_path):
    pid = _make_person("d4@example.com", password=None, username="audit_probe_x")
    from origin.services.auth_service import hash_password

    backup = tmp_path / "cleared.json"
    backup.write_text(json.dumps([{"id": pid, "username": "audit_probe_x",
                                   "password_hash": hash_password(_PW)}]), encoding="utf-8")
    _admin("person", "deactivate", "audit_probe_x", "--reason", "probe")
    code, said = _admin("person", "reactivate", "audit_probe_x", "--restore-password-from", str(backup))
    assert code == 0 and "password=set" in said and "deactivated=no" in said
    assert _login(db_client, "audit_probe_x").status_code == 200

    code, said = _admin("person", "reactivate", "audit_probe_x", "--restore-password-from", str(backup))
    assert code == 2 and "already has a password" in said


def test_show_never_prints_a_hash_and_names_an_unknown_person(db_client):
    _make_person("d5@example.com")
    code, said = _admin("person", "show", "d5@example.com")
    assert code == 0 and "password=set" in said and "$" not in said
    assert _admin("person", "show", "nobody@example.com")[0] == 1
