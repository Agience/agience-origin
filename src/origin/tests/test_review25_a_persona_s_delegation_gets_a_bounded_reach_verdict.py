"""Review 25, M1: the delegation a persona calls Mantle on gets a reach verdict, bounded.

A persona's server delegation carries its narrowing (`scope` `persona:<name>`), and Iris's
platform mail runs on the system delegation for `platform.email.send`. Origin's reach verdict took
neither, so under threshold custody every persona call, `/use` included, stopped. `/reach` now
verifies them with the same definition as the use verdict (`use_verdict.verify_persona_credential`)
and answers only the actions such a delegation may take. Key release never takes them.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
world = r21.world
SYSTEM = "sys-principal-1"


def _record(jti, sub, aud="mantle", signer="iris"):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    with SessionLocal() as db:
        db.add(DelegationRecord(jti=jti, subject=sub, audience=aud, signer=signer,
                                expires_at=datetime.now(timezone.utc) + timedelta(seconds=300)))
        db.commit()


def _narrowed(sub):
    from origin.services.auth_service import issue_delegation_token
    jti = secrets.token_hex(16)
    tok = issue_delegation_token(r21.IRIS, sub, 300, signer="iris", jti=jti,
                                 narrowed_scope="persona:iris")
    _record(jti, sub)
    return tok


def _mail(monkeypatch):
    import origin.service_identity as ksi
    from origin.services.auth_service import issue_system_delegation_token
    monkeypatch.setattr(ksi, "get_system_principal_id", lambda: SYSTEM)
    jti = secrets.token_hex(16)
    tok = issue_system_delegation_token(SYSTEM, actor=r21.IRIS, signer="iris",
                                        scope="platform.email.send", audience="mantle", jti=jti)
    _record(jti, SYSTEM)
    return tok


def _reach(c, credential, resource, action):
    tok = r21._shares._token("GET", "-", htu="/internal/authority/reach",
                             resource_id=resource, action=action)
    return c.get("/internal/authority/reach", params={"resource_id": resource, "action": action},
                 headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


@pytest.mark.parametrize("action", ["invoke", "read"])
def test_a_narrowed_server_delegation_gets_a_reach_verdict(world, action):
    c, _alice, bob = world
    r = _reach(c, _narrowed(bob[0]), r21.CARD, action)
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is (action == "invoke")         # Bob holds Invoke only


@pytest.mark.parametrize("action", ["admin", "share", "delete", "evict"])
def test_it_asks_no_verdict_outside_what_a_persona_does(world, action):
    c, _alice, bob = world
    assert _reach(c, _narrowed(bob[0]), r21.CARD, action).status_code == 403


def test_the_platform_mail_delegation_gets_a_read_and_invoke_verdict(world, monkeypatch):
    c, alice, _bob = world
    tok = _mail(monkeypatch)
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, r21.SHELF, ["read", "invoke"]),
                    batch="sys"))
    assert _reach(c, tok, r21.CARD, "invoke").json() == {"allowed": True}
    assert _reach(c, tok, r21.CARD, "update").status_code == 403


def test_no_key_share_is_released_on_them(world, monkeypatch):
    c, _alice, bob = world
    assert af.release(c, f"ck:{r21.SHELF}", _narrowed(bob[0])).status_code == 403
    assert af.release(c, f"ck:{r21.SHELF}", _mail(monkeypatch)).status_code == 403
