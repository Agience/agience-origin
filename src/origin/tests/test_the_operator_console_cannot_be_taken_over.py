"""The operator's ordinary access token (which Mantle receives) cannot take over the console.

The third review's two scenarios, end to end on the real routes:
  * enrolling a passkey on the operator's account with that token, then signing in to the console
    with it and granting background authority;
  * moving `platform.operator_id` through the settings routes.
And what still works: a person enrols a passkey through the real routes and signs in with it; the
operator enrols their first passkey with a one-time code from Origin's host, and further ones only
through the console with a step-up. Background authority lasts a day at most.

Passkeys here are a real P-256 software authenticator (`operator_console_fixtures`); registration
uses "none" attestation, as a platform authenticator does.
"""
import base64
import hashlib
import json

import cbor2

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _registration(opts: dict, auth: oc.Authenticator, *, fmt: str = "packed",
                  verified: bool = True) -> dict:
    """A registration: "packed" self attestation (signed by the credential's own key), or
    "none"; user verification set unless `verified` is False."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from origin.services import passkey_service

    rp_hash = hashlib.sha256(opts["rp"]["id"].encode()).digest()
    att_cred = b"\x00" * 16 + len(auth.cred_id).to_bytes(2, "big") + auth.cred_id + auth.cose_key()
    flags = 0x45 if verified else 0x41                     # UP, (UV), AT
    auth_data = rp_hash + bytes([flags]) + (0).to_bytes(4, "big") + att_cred
    cdj = json.dumps({"type": "webauthn.create", "challenge": opts["challenge"],
                      "origin": passkey_service.expected_origin(),
                      "crossOrigin": False}).encode()
    if fmt == "packed":
        sig = auth.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        att_obj = cbor2.dumps({"fmt": "packed", "attStmt": {"alg": -7, "sig": sig},
                               "authData": auth_data})
    else:
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    return {"id": _b64(auth.cred_id), "rawId": _b64(auth.cred_id), "type": "public-key",
            "response": {"clientDataJSON": _b64(cdj), "attestationObject": _b64(att_obj)}}


def _enrol(c, token, auth, extra=None, step=None, **registration):
    """Register `auth` through `/auth/passkey/register-*` on `token`'s account. `extra` headers
    go on both calls; `step(path, body)` adds a fresh step-up per call."""
    base = {"Authorization": f"Bearer {token}", **(extra or {})}
    h = dict(base, **(step("/auth/passkey/register-options", b"") if step else {}))
    opts = c.post("/auth/passkey/register-options", headers=h)
    if opts.status_code != 200:
        return opts
    o = opts.json()["options"]
    body = json.dumps({"credential": _registration(o, auth, **registration), "challenge": o["challenge"],
                       "device_name": "test"}).encode()
    h = dict(base, **(step("/auth/passkey/register-complete", body) if step else {}),
             **{"Content-Type": "application/json"})
    return c.post("/auth/passkey/register-complete", content=body, headers=h)


# -- what still works ----------------------------------------------------------------------------

def _person_step(c, tok, pid):
    """A person's first passkey: re-authentication at Origin for the options call, which the
    completion's challenge is bound to."""
    def step(path, body):
        if path != "/auth/passkey/register-options":
            return {}
        return {"X-Step-Up": oc.person_reauth(c, tok, pid, "POST", path, body)}
    return step


def test_a_person_enrols_a_passkey_through_the_routes_and_signs_in_with_it(custody_client):
    pid, tok = af.person("pia", email="pia@x.test")
    auth = oc.Authenticator()
    assert _enrol(custody_client, tok, auth).status_code == 403      # a token alone enrols nothing
    r = _enrol(custody_client, tok, auth, step=_person_step(custody_client, tok, pid))
    assert r.status_code == 200, r.text
    opts = custody_client.post("/auth/passkey/login-options", json={"email": "pia@x.test"}).json()
    r = custody_client.post("/auth/passkey/login-complete", json={
        "credential": auth.assertion(opts["options"]), "challenge": opts["options"]["challenge"]})
    assert r.status_code == 200 and r.json()["access_token"]


# -- scenario 1: a passkey planted with the operator's access token ------------------------------

def test_the_operator_s_access_token_cannot_enrol_a_passkey(custody_client, monkeypatch):
    op = af.operator(monkeypatch)
    planted = oc.Authenticator()
    r = _enrol(custody_client, op, planted)
    assert r.status_code == 403
    opts = custody_client.post("/oracle/console/sign-in-options")
    assert opts.status_code == 409                       # the operator has no passkey at all


def test_the_first_operator_passkey_needs_a_one_time_code_from_origin_s_host(custody_client,
                                                                             monkeypatch):
    from origin.db.session import SessionLocal
    from origin.services import operator_console

    op = af.operator(monkeypatch)
    with SessionLocal() as db:
        code = operator_console.issue_enrolment_code(db, af.OPERATOR)
    hdr = {operator_console.ENROLMENT_HEADER: code}
    assert _enrol(custody_client, op, oc.Authenticator(), {
        operator_console.ENROLMENT_HEADER: "guessed"}).status_code == 403
    first = oc.Authenticator()
    r = _enrol(custody_client, op, first, hdr)
    assert r.status_code == 200, r.text
    assert _enrol(custody_client, op, oc.Authenticator(), hdr).status_code == 403    # spent
    with SessionLocal() as db:
        again = operator_console.issue_enrolment_code(db, af.OPERATOR)
    assert _enrol(custody_client, op, oc.Authenticator(), {          # a passkey exists now
        operator_console.ENROLMENT_HEADER: again}).status_code == 403
    token = oc.sign_in(custody_client, first)                         # the real one opens it

    def step(path, body):
        return {operator_console.CONSOLE_HEADER: token,
                operator_console.STEP_UP_HEADER: oc.step_up(custody_client, token, first, "POST",
                                                            path, body)}

    assert _enrol(custody_client, op, oc.Authenticator(), step=step).status_code == 200


def test_an_expired_enrolment_code_is_refused(custody_client, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from origin.db.session import SessionLocal
    from origin.models.key_custody import OperatorEnrolmentCode
    from origin.services import operator_console

    op = af.operator(monkeypatch)
    with SessionLocal() as db:
        code = operator_console.issue_enrolment_code(db, af.OPERATOR)
        db.get(OperatorEnrolmentCode, hashlib.sha256(code.encode()).hexdigest()).expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1))
        db.commit()
    assert _enrol(custody_client, op, oc.Authenticator(), {
        operator_console.ENROLMENT_HEADER: code}).status_code == 403


def test_the_operator_s_passkey_is_deleted_only_through_the_console(custody_client, monkeypatch):
    op = af.operator(monkeypatch)
    auth, _token = oc.console(custody_client)
    r = custody_client.delete(f"/auth/passkey/credentials/{_b64(auth.cred_id)}",
                              headers={"Authorization": f"Bearer {op}"})
    assert r.status_code == 403


# -- scenario 2: the operator id moved through the settings routes -------------------------------

def test_the_settings_routes_cannot_move_the_operator(custody_client, monkeypatch):
    from origin.services.platform_settings_service import settings as ps

    op = af.operator(monkeypatch)
    for key in ("platform.operator_id", "oracle.some-secret"):
        r = custody_client.patch("/system/settings", headers={"Authorization": f"Bearer {op}"},
                                 json={"settings": [{"key": key, "value": "attacker"}]})
        assert r.status_code == 403, (key, r.text)
    assert ps._values.get("platform.operator_id") != "attacker"
    r = oc.call(custody_client, "PUT", "/oracle/settings/platform.operator_id",
                json={"value": af.OPERATOR})
    assert r.status_code == 200, r.text


# -- background work: no standing authority, job grants a month at most -------------------------

def test_there_is_no_standing_background_authority_and_a_job_grant_is_bounded(custody_client,
                                                                             monkeypatch):
    from datetime import datetime, timedelta, timezone

    from origin import service_identity

    af.operator(monkeypatch)
    monkeypatch.setattr(service_identity, "get_system_principal_id",
                        lambda: "00000000-0000-0000-0000-00000000005e")
    assert oc.call(custody_client, "POST", "/oracle/custody-background",
                   json={}).status_code == 404
    r = oc.call(custody_client, "POST", "/oracle/job-grants",
                json={"job": "ledger.retry", "hours": 100000})
    assert r.status_code == 200, r.text
    grant = oc.call(custody_client, "GET", "/oracle/job-grants").json()["grants"][0]
    until = datetime.fromisoformat(grant["expires_at"])
    assert until <= datetime.now(timezone.utc) + timedelta(days=30, minutes=1)


def test_an_enrolment_code_is_spent_by_the_attempt_it_authorizes(custody_client, monkeypatch):
    """A failed enrolment spends its code too: it serves one attempt."""
    from origin.db.session import SessionLocal
    from origin.services import operator_console

    op = af.operator(monkeypatch)
    with SessionLocal() as db:
        code = operator_console.issue_enrolment_code(db, af.OPERATOR)
    hdr = {"Authorization": f"Bearer {op}", operator_console.ENROLMENT_HEADER: code}
    opts = custody_client.post("/auth/passkey/register-options", headers=hdr).json()["options"]
    bad = custody_client.post("/auth/passkey/register-complete", headers=hdr, json={
        "credential": {"id": "x", "rawId": "x", "type": "public-key", "response": {}},
        "challenge": opts["challenge"], "device_name": "x"})
    assert bad.status_code in (400, 422)
    assert _enrol(custody_client, op, oc.Authenticator(), {
        operator_console.ENROLMENT_HEADER: code}).status_code == 403


def test_the_operator_s_passkey_needs_user_verification_and_an_attestation(custody_client,
                                                                          monkeypatch):
    """Ordinary people keep "none" attestation; the operator's account refuses it, and refuses a
    registration without user verification."""
    from origin.db.session import SessionLocal
    from origin.services import operator_console

    op = af.operator(monkeypatch)
    for spoil in ({"fmt": "none"}, {"verified": False}):
        with SessionLocal() as db:
            code = operator_console.issue_enrolment_code(db, af.OPERATOR)
        r = _enrol(custody_client, op, oc.Authenticator(),
                   {operator_console.ENROLMENT_HEADER: code}, **spoil)
        assert r.status_code == 400, (spoil, r.text)
    pid, tok = af.person("nia")
    assert _enrol(custody_client, tok, oc.Authenticator(), fmt="none",
                  step=_person_step(custody_client, tok, pid)).status_code == 200
