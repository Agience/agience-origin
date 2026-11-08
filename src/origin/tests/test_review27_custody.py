"""Review 27 at Origin.

HIGH. Origin's replica says who is a person (`principal-kinds`, for Mantle's counts), and a root's
Admin may grant `platform.custody` and `platform.rekey` over that root's master key.

MEDIUM 1. A persona's server delegation (actor `agience-server-<persona>`) releases no key and is
no person's credential on the ledger, whoever signed its exchange; the delegation exchange takes
only a delegation narrowed to the asking persona.

MEDIUM 2. A reader's split that stopped after Origin stored its share can be finished: by any
reader restating that very share (Mantle now derives its shares from Origin's), and by the first
share's storer replacing it while it is still pending.

LOW 1. The operator's `platform.custody` grant names only the platform user, the system principal
or a persona's server principal.

INFO. Marking a share for re-key is refused off isolated production, and a service token with no
`exp` is no token.
"""
from __future__ import annotations

import base64
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_a_share_release_needs_the_callers_credential as base
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review26_custody as r26
from origin.tests.test_background_work_runs_on_a_job_grant import _later, _mint

custody_client = r21.custody_client
unsealed_world = r26.unsealed_world
notes = r26.notes
world = base.world
ALL = r26.ALL


def _server_delegation(sub: str, *, persona: str = "iris", signer: str = "iris") -> str:
    """A persona's server delegation as `/internal/delegation-token` mints it, recorded with the
    signer that asked."""
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import SERVER_DELEGATION_AUDIENCE, issue_delegation_token

    jti = secrets.token_hex(16)
    tok = issue_delegation_token(f"agience-server-{persona}", sub, 300, signer=signer, jti=jti)
    with SessionLocal() as db:
        db.add(DelegationRecord(jti=jti, subject=sub, audience=SERVER_DELEGATION_AUDIENCE,
                                signer=signer,
                                expires_at=datetime.now(timezone.utc) + timedelta(seconds=300)))
        db.commit()
    return tok


# -- MEDIUM 1 -----------------------------------------------------------------------------------

def test_a_persona_s_server_delegation_releases_no_key(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    tok = _server_delegation(world["live"])
    with SessionLocal() as db, pytest.raises(share_credentials.CredentialRefused):
        share_credentials.verify_share_credential(db, tok)
    assert base._release(custody_client, tok, principal=world["live"]).status_code == 403


@pytest.mark.parametrize("entry", [af.root("r27-root"), af.grant("g-r27", "x", "notes-b", ALL)])
def test_a_chorus_signed_server_delegation_makes_no_entry(notes, unsealed_world, entry):
    c, _alice, bob = notes
    tok = _server_delegation(bob[0], signer="chorus")
    r = af.submit(c, tok, entry, batch="y", via_session=False)
    assert r.status_code == 403, r.text


def _as_service(origin_app, name):
    from origin.services.dependencies import AuthContext, get_auth
    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=name, principal_type="service", user_id=None)


@pytest.fixture()
def exchange(client, origin_app):
    from origin.db.base import Base
    from origin.db.session import get_engine
    from origin.services.dependencies import get_auth

    Base.metadata.create_all(get_engine())
    yield client, origin_app
    origin_app.dependency_overrides.pop(get_auth, None)


def _claims(**extra):
    import time
    from origin import config
    return {"sub": str(uuid.uuid4()), "exp": time.time() + 600, "aud": config.AUTHORITY_ISSUER,
            **extra}


def test_the_exchange_takes_only_a_delegation_narrowed_to_the_persona(exchange):
    from unittest.mock import patch

    from origin.routers import auth_router

    client, app = exchange
    narrowed = _claims(principal_type="delegation", narrowed=True, aud="lumen",
                       act={"sub": "lumen"}, scope="persona:lumen")
    for who, claims, want in (("lumen", _claims(), 403),          # a person's own token
                              ("chorus", _claims(), 403),         # the shared host, for anyone
                              ("lumen", narrowed, 200)):
        _as_service(app, who)
        with patch.object(auth_router, "verify_token", return_value=claims):
            r = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-lumen", "subject_token": "a.b.c"})
        assert r.status_code == want, (who, r.text)


# -- MEDIUM 2 -----------------------------------------------------------------------------------

def _other_y() -> str:
    raw = bytearray(base64.b64decode(_shares.SHARE_Y))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


@pytest.fixture()
def team(custody_client):
    c = custody_client
    alice, bob, carol = af.person("Alice"), af.person("Bob"), af.person("Carol")
    af.ok(af.submit(c, alice[1], af.root("K"), batch="a"))
    af.ok(af.submit(c, alice[1], af.grant("g-k", alice[0], "K", ALL), batch="a"))
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read"]), batch="b"))
    af.ok(af.submit(c, alice[1], af.grant("g-ck", carol[0], "K", ["read"]), batch="c"))
    assert af.store_share(c, "ck:K", credential=bob[1]).status_code == 200   # then interrupted
    return c, alice, bob, carol


def test_any_reader_finishes_the_split_by_restating_origin_s_share(team):
    c, _alice, _bob, carol = team
    assert af.store_share(c, "ck:K", credential=carol[1]).status_code == 200


def test_the_storer_may_replace_its_pending_first_share(team):
    c, _alice, bob, carol = team
    assert af.store_share(c, "ck:K", credential=carol[1], y=_other_y()).status_code == 403
    assert af.store_share(c, "ck:K", credential=bob[1], y=_other_y()).status_code == 200


# -- HIGH: who is a person, and a root's Admin grants over its key --------------------------------

def _kinds(c, ids):
    from origin.services.authority_ledger import canonical
    import hashlib
    body = {"ids": ids}
    digest = hashlib.sha256(canonical(body).encode()).hexdigest()
    tok = _shares._token("POST", "-", htu="/internal/authority/principal-kinds",
                         body_sha256=digest)
    return c.post("/internal/authority/principal-kinds", json=body,
                  headers={"Authorization": f"Bearer {tok}"})


def test_origin_says_who_is_a_person(custody_client):
    c = custody_client
    alice = af.person("Alice")
    team_id = str(uuid.uuid4())
    af.ok(af.submit(c, alice[1], af.root(team_id), batch="t"))
    r = _kinds(c, [alice[0], team_id, "ck:" + team_id, "never-seen"])
    assert r.status_code == 200, r.text
    assert r.json()["kinds"] == {alice[0]: "person", team_id: "root",
                                 "ck:" + team_id: "collection_key", "never-seen": "unknown"}


def test_a_root_s_admin_grants_custody_and_rekey_over_its_master_key(custody_client):
    c = custody_client
    alice, bob = af.person("Alice"), af.person("Bob")
    team_id = str(uuid.uuid4())
    af.ok(af.submit(c, alice[1], af.root(team_id), batch="t"))
    af.ok(af.submit(c, alice[1], af.grant("g-t", alice[0], team_id, ALL), batch="t"))
    af.ok(af.submit(c, alice[1], af.grant("g-tb", bob[0], team_id, ["read"]), batch="t2"))
    for job in ("platform.custody", "platform.rekey"):
        g = {"kind": "job_grant", "grant_id": "jg-" + secrets.token_hex(4), "job": job,
             "principal": team_id, "collections": [], "expires_at": _later(), "state": "active"}
        assert af.page(alice[0], g).status_code == 200
        assert _mint(c, team_id, job).status_code == 200
        assert af.page(bob[0], {**g, "grant_id": "jg-" + secrets.token_hex(4)}).status_code == 403


# -- LOW 1 ----------------------------------------------------------------------------------------

def test_the_operator_s_custody_grant_names_only_the_platform_s_own_principals(custody_client,
                                                                              monkeypatch):
    from origin import config, service_identity

    c = custody_client
    af.operator(monkeypatch)
    monkeypatch.setattr(service_identity, "get_system_principal_id",
                        lambda: "00000000-0000-0000-0000-00000000005e")
    other_root = str(uuid.uuid4())
    r26._bootstrap_roots(c, [config.AGIENCE_PLATFORM_USER_ID, "agience-server-lumen",
                             "agience-server-nobody", other_root])
    for principal, want in ((config.AGIENCE_PLATFORM_USER_ID, 200),
                            ("agience-server-lumen", 200),
                            ("agience-server-nobody", 403),
                            (other_root, 403)):
        r = oc.call(c, "POST", "/oracle/job-grants",
                    json={"job": "platform.custody", "hours": 2, "principal": principal})
        assert r.status_code == want, (principal, r.text)


# -- INFO -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("plane, want", [("production", 200), ("home", 403)])
def test_marking_a_share_for_rekey_is_refused_off_isolated_production(custody_client,
                                                                      monkeypatch, plane, want):
    from origin import service_identity
    from origin.services import custody_plane

    c = custody_client
    alice = af.person("Alice")
    af.ok(af.submit(c, alice[1], af.root(alice[0]), batch="a"))
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    monkeypatch.setattr(service_identity, "get_system_principal_id",
                        lambda: "00000000-0000-0000-0000-00000000005e")
    af.operator(monkeypatch)
    seed = oc.call(c, "POST", "/oracle/seed-credential",
                   json={"minutes": 10, "rekey_shares": [alice[0]]})
    assert seed.status_code == 200, seed.text
    if plane != "production":
        monkeypatch.setattr(custody_plane, "TEST_OVERRIDE", None)
        monkeypatch.setenv("AGIENCE_PLANE", plane)
    path = f"/internal/key-shares/{alice[0]}/rekey-pending"
    tok = _shares._token("POST", alice[0], htu=path)
    r = c.post(path, headers={"Authorization": f"Bearer {tok}",
                              "X-Acting-Credential": seed.json()["token"]})
    assert r.status_code == want, r.text


def test_a_service_token_with_no_exp_is_no_token(custody_client):
    from origin.services.auth_verifier import verify_token
    assert verify_token(_shares._token("GET", "p-1", htu="/x")) is not None   # with exp
    assert verify_token(_shares._token("GET", "p-1", htu="/x", drop=("exp",))) is None
