"""Origin releases a key share only for a live credential it issued itself, naming who acts.

Mantle's bound service token says "Mantle is calling"; it cannot say for whom, and Mantle holding
it is exactly the case threshold custody exists to defeat. So every release also carries the acting
caller's own credential (`X-Acting-Credential`): a person's access token, a delegation Origin
issued for a person, or a background delegation Origin minted for one principal, which it mints
only while the operator's background authority is in force. Origin verifies it here (signature,
issuer, audience, expiry, the person still active, the delegation and the authority not
withdrawn) and records each release by the credential's reference, never the token. Who the
credential reaches is the next rule (`test_a_release_is_decided_by_origin_s_own_walk.py`); a
person here opens their own key, and a background delegation the key it was minted for.
"""
from __future__ import annotations

import pytest

from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

_put, _token = _shares._put, _shares._token
custody_client = _shares.custody_client          # the fixture, shared

SYSTEM = "00000000-0000-0000-0000-00000000aaaa"
OPERATOR = "00000000-0000-0000-0000-0000000000aa"


@pytest.fixture
def world(custody_client, monkeypatch):
    """A live person, a deactivated one, the operator, a stored share, and the system principal."""
    from datetime import datetime, timezone

    from origin import service_identity
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.platform_settings_service import settings as platform_settings

    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: SYSTEM)
    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw:
                        OPERATOR if k == "platform.operator_id" else real_get(k, *a, **kw))
    with SessionLocal() as db:
        live = db_persons.create(db, {"email": "live@x.test", "name": "Live", "username": "live"})
        gone = db_persons.create(db, {"email": "gone@x.test", "name": "Gone", "username": "gone",
                                      "deactivated_at": datetime.now(timezone.utc)})
        db_persons.create(db, {"id": OPERATOR, "email": "op@x.test", "name": "Op",
                               "username": "op"})
        ids = {"live": str(live.id), "gone": str(gone.id)}
        db.commit()
    _put(custody_client, "p-1")
    for who in ("live", "gone"):               # each person's own key: theirs to open
        _put(custody_client, ids[who])
    # Storing those minted their owners' credentials under job grants; the tests here start with
    # none, as a node does before anyone grants a job.
    from origin.models.authority_ledger import AuthorityJobGrant
    with SessionLocal() as db:
        db.query(AuthorityJobGrant).delete()
        db.commit()
    return ids


def _person_token(sub, **extra):
    from origin import config
    from origin.services.auth_service import create_jwt_token

    return create_jwt_token({"sub": sub, "email": "x@x.test", "name": "X", "client_id": "platform",
                             "aud": config.AUTHORITY_ISSUER, **extra})


def _delegation(sub, *, aud="mantle", **kw):
    from origin.services.auth_service import issue_system_delegation_token

    if "scope" in kw:
        return issue_system_delegation_token(sub, actor="crystal", scope=kw["scope"], audience=aud)
    return _recorded_delegation(aud, sub, **kw)


def _recorded_delegation(aud, sub, *, ttl=300, record=True, revoked=False):
    """A person's delegation as `/internal/delegation-token` issues it: with a `jti` recorded."""
    import secrets
    from datetime import datetime, timedelta, timezone

    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import issue_delegation_token

    jti = secrets.token_hex(16)
    tok = issue_delegation_token(aud, sub, ttl, jti=jti)
    if record:
        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            db.add(DelegationRecord(jti=jti, subject=sub, audience=aud, signer="",
                                    expires_at=now + timedelta(seconds=ttl),
                                    revoked_at=now if revoked else None))
            db.commit()
    return tok


def _release(c, credential=None, principal="p-1"):
    headers = {"Authorization": f"Bearer {_token('GET', principal)}"}
    if credential is not None:
        headers["X-Acting-Credential"] = credential
    return c.get(f"/internal/key-shares/{principal}", headers=headers)


def _operator_headers():
    return {"Authorization": f"Bearer {_person_token(OPERATOR)}"}


# -- what opens a share --------------------------------------------------------------------------

def test_a_person_s_access_token_opens_it_and_the_release_is_recorded(custody_client, world):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyRelease

    tok = _person_token(world["live"])
    r = _release(custody_client, tok, principal=world["live"])
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        rec = db.query(KeyCustodyRelease).filter_by(credential_kind="access").one()
    assert (rec.principal_id, rec.subject) == (world["live"], world["live"])
    assert rec.credential_ref and tok not in rec.credential_ref and len(rec.credential_ref) <= 64


def test_a_delegation_origin_issued_for_a_person_opens_it(custody_client, world):
    assert _release(custody_client, _delegation(world["live"]),
                    principal=world["live"]).status_code == 200


@pytest.mark.parametrize("spoil", [{"record": False}, {"revoked": True}, {"ttl": 3600}])
def test_a_delegation_with_no_record_revoked_or_long_is_refused(custody_client, world, spoil):
    """A person's delegation acts at a release only if Origin recorded it at issue, has not
    revoked it, and it lives ten minutes at most."""
    r = _release(custody_client, _recorded_delegation("mantle", world["live"], **spoil))
    assert r.status_code == 403


JOB = "test.job"


def _grant_job(principal="p-1", job=JOB):
    """A live job grant for `principal`, written as a co-signed `job_grant` leaves it."""
    import json
    from datetime import datetime, timedelta, timezone

    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant

    gid = f"jg-{job}-{principal}"
    with SessionLocal() as db:
        db.add(AuthorityJobGrant(grant_id=gid, job=job, principal=principal,
                                 collections=json.dumps([]),
                                 expires_at=(datetime.now(timezone.utc)
                                             + timedelta(hours=1)).isoformat(),
                                 state="active", created_by="", seq=0))
        db.commit()
    from origin.tests import authority_fixtures as af
    af.HELD_FOR_TESTS.add(gid)                     # stated with no grantor to check
    return gid


def _mint(c, principal, job=JOB):
    from origin.tests.test_a_key_share_is_released_only_to_mantle import _token as tok

    return c.post(f"/internal/custody-delegations/{principal}", json={"job": job}, headers={
        "Authorization": "Bearer " + tok("POST", principal, job=job,
                                         htu=f"/internal/custody-delegations/{principal}")})


def test_a_minted_background_delegation_opens_its_principal_until_its_grant_is_revoked(
        custody_client, world):
    from jose import jwt as jose_jwt

    grant = _grant_job()
    r = _mint(custody_client, "p-1")
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    claims = jose_jwt.get_unverified_claims(tok)
    assert claims["sub"] == "p-1" and claims["exp"] - claims["iat"] <= 600
    assert _release(custody_client, tok).status_code == 200
    from origin.tests import operator_console_fixtures as oc

    listed = oc.call(custody_client, "GET", "/oracle/job-grants").json()
    assert [g["grant_id"] for g in listed["grants"]] == [grant]
    assert oc.call(custody_client, "POST", f"/oracle/job-grants/{grant}/revoke",
                   json={}).status_code == 200
    assert _release(custody_client, tok).status_code == 403          # revoked: at once
    assert _mint(custody_client, "p-1").status_code == 403


def test_a_background_delegation_opens_no_other_principal(custody_client, world):
    _grant_job()
    _put(custody_client, "p-2")
    tok = _mint(custody_client, "p-1").json()["token"]
    r = _release(custody_client, tok, principal="p-2")
    assert r.status_code == 403 and "another principal" in r.json()["detail"]


def test_no_background_delegation_is_minted_without_a_job_grant(custody_client, world):
    r = _mint(custody_client, "p-1")
    assert r.status_code == 403 and "job grant" in r.json()["detail"]


def test_no_delegation_is_minted_for_an_id_origin_knows_no_key_for(custody_client, world):
    """A person's id, or any other, is not a key principal until the ledger says so."""
    _grant_job("no-such-key")
    r = _mint(custody_client, "no-such-key")
    assert r.status_code == 403 and "no key principal" in r.json()["detail"]


def test_a_minting_token_is_bound_to_its_principal_and_its_job(custody_client, world):
    from origin.tests.test_a_key_share_is_released_only_to_mantle import _token as tok

    _grant_job()
    r = custody_client.post("/internal/custody-delegations/p-1", json={"job": JOB}, headers={
        "Authorization": "Bearer " + tok("POST", "p-2", job=JOB,
                                         htu="/internal/custody-delegations/p-1")})
    assert r.status_code == 401
    r = custody_client.post("/internal/custody-delegations/p-1", json={"job": JOB}, headers={
        "Authorization": "Bearer " + tok("POST", "p-1", job="another.job",
                                         htu="/internal/custody-delegations/p-1")})
    assert r.status_code == 401


# -- what does not -------------------------------------------------------------------------------

def test_no_credential_is_refused(custody_client, world):
    """Mantle's service token alone: the case the rule exists for."""
    assert _release(custody_client).status_code == 401


def test_a_credential_origin_did_not_sign_is_refused(custody_client, world):
    from jose import jwt as jose_jwt

    from origin.tests.test_a_key_share_is_released_only_to_mantle import _KEYS, _pem
    from origin import config

    forged = jose_jwt.encode({"sub": world["live"], "iss": config.AUTHORITY_ISSUER,
                              "aud": config.AUTHORITY_ISSUER, "exp": 9999999999},
                             _pem(_KEYS["impostor"]), algorithm="RS256")
    assert _release(custody_client, forged).status_code == 403


@pytest.mark.parametrize("spoil", [
    {"token_type": "refresh"},
    {"aud": "some-mcp-client"},
    {"principal_type": "mcp_client"},
    {"exp": 1000},
])
def test_a_person_token_that_is_not_a_live_access_token_is_refused(custody_client, world, spoil):
    assert _release(custody_client, _person_token(world["live"], **spoil)).status_code == 403


def test_a_deactivated_person_is_refused(custody_client, world):
    assert _release(custody_client, _person_token(world["gone"])).status_code == 403
    assert _release(custody_client, _delegation(world["gone"])).status_code == 403


def test_a_person_unknown_to_origin_is_refused(custody_client, world):
    assert _release(custody_client,
                    _person_token("00000000-0000-0000-0000-00000000ffff")).status_code == 403


def test_a_platform_service_token_is_not_a_credential(custody_client, world):
    assert _release(custody_client, _token("GET", "p-1")).status_code == 403


def test_a_system_delegation_for_another_purpose_is_refused(custody_client, world):
    """Crystal's describe delegation names the system principal too; it was not issued for
    share release, and only the operator issues that."""
    tok = _delegation(SYSTEM, aud="seraph", scope="platform.describe")
    assert _release(custody_client, tok).status_code == 403


def test_a_background_delegation_origin_did_not_mint_is_refused(custody_client, world):
    _grant_job()
    tok = _delegation("p-1", aud="origin", scope="custody.share.release")
    assert _release(custody_client, tok).status_code == 403


def test_only_the_operator_console_lists_grants_or_revokes_job_grants(custody_client, world):
    for other in ({"Authorization": f"Bearer {_person_token(world['live'])}"},
                  _operator_headers()):           # the operator's own access token, too
        assert custody_client.post("/oracle/job-grants", headers=other,
                                   json={"job": "x", "hours": 1}).status_code == 403
        assert custody_client.post("/oracle/job-grants/x/revoke", headers=other,
                                   json={}).status_code == 403


def test_storing_a_share_needs_no_acting_credential(custody_client, world):
    """A store releases nothing; Mantle's bound service token is enough for it."""
    assert _put(custody_client, "p-2").status_code == 200
