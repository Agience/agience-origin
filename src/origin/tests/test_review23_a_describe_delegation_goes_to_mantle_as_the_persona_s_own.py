"""Review 23, L1: a persona sends Mantle its own copy of a describe delegation, never the one it
was sent.

Crystal's describe delegation is addressed to the persona that runs the describe, and the persona
forwarded it to Mantle on its calls there, so Mantle could call the persona with it. The persona
now exchanges it at Origin (`POST /internal/describe-delegation/for-mantle`, signed with its own
key) for a copy addressed to Mantle and asked for by the persona itself (`act.iss`), which no
persona takes inbound (review 22). Tokens come from Origin's own issuer.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

PATH = "/internal/describe-delegation/for-mantle"
SYSTEM = "sys-principal-1"


@pytest.fixture
def client(origin_app):
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine
        Base.metadata.create_all(get_engine())
        yield c


def _as(c, name, actor=None):
    from origin.services.dependencies import AuthContext, get_auth
    c.app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=name, principal_type="service", user_id=None, actor=actor)


def _describe(persona="iris", **over):
    import secrets

    from origin.services.auth_service import issue_system_delegation_token
    kw = dict(actor=f"agience-server-{persona}", scope="platform.describe",
              audience=f"agience-server-{persona}", jti=secrets.token_hex(16))
    kw.update(over)
    return issue_system_delegation_token(SYSTEM, **kw)


def test_the_persona_gets_its_own_copy_addressed_to_mantle(client):
    _as(client, "iris")
    try:
        r = client.post(PATH, json={"subject_token": _describe()})
    finally:
        client.app.dependency_overrides.clear()
    assert r.status_code == 200, r.text
    got = jose_jwt.get_unverified_claims(r.json()["token"])
    assert (got["aud"], got["act"], got["scope"], got["sub"]) == (
        "mantle", {"sub": "agience-server-iris", "iss": "iris"}, "platform.describe", SYSTEM)


@pytest.mark.parametrize("caller,subject", [
    ("lumen", None),                                 # another persona's describe delegation
    ("mantle", None),                                # not a persona
    ("iris", {"scope": "platform.email.send"}),      # another purpose
    ("iris", {"audience": "mantle"}),                # not the one sent to the persona
])
def test_nothing_else_is_exchanged(client, caller, subject):
    _as(client, caller)
    try:
        r = client.post(PATH, json={"subject_token": _describe(**(subject or {}))})
    finally:
        client.app.dependency_overrides.clear()
    assert r.status_code in (400, 401, 403)
