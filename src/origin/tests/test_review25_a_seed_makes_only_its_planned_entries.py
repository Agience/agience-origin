"""Review 25, M4: a seed credential makes only the entries its pass planned, each one alerted.

A seed credential, handed to Mantle for one pass, let Mantle make any lasting grant inside the
seed's window, with no alert. The operator now mints it with the digests of the pass's planned
entries (`plan`, each `authority_ledger.body_digest` of an entry), and Origin refuses any entry
outside the plan, or any entry at all on a seed minted with none. Every grant made on a seed
raises an operator alert (`seed_grant`).
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
SYSTEM = "00000000-0000-0000-0000-00000000aaaa"


@pytest.fixture(autouse=True)
def _system(monkeypatch):
    from origin import service_identity
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: SYSTEM)


def _seed(c, monkeypatch, plan=None):
    af.operator(monkeypatch)
    body = {"minutes": 10, **({"plan": plan} if plan is not None else {})}
    r = oc.call(c, "POST", "/oracle/seed-credential", json=body)
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _alerts():
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import OperatorAlert
    with SessionLocal() as db:
        return [a.resource_id for a in db.query(OperatorAlert).filter_by(kind="seed_grant")]


def test_a_planned_grant_is_made_and_alerted(unsealed_world, monkeypatch):
    from origin.services.authority_ledger import body_digest

    c, alice, _bob = unsealed_world
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, r21.SHELF, r21.ALL), batch="s"))
    planned = af.grant("g-seed-carol", carol[0], r21.SHELF, ["read"])
    seed = _seed(c, monkeypatch, plan=[body_digest(planned)])
    af.ok(af.submit(c, seed, planned, batch="seed"))
    assert _alerts() == ["g-seed-carol"]


def test_an_entry_outside_the_plan_is_refused(unsealed_world, monkeypatch):
    from origin.services.authority_ledger import body_digest

    c, alice, _bob = unsealed_world
    carol, mal = af.person("Carol"), af.person("Mal")
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, r21.SHELF, r21.ALL), batch="s"))
    planned = af.grant("g-seed-carol", carol[0], r21.SHELF, ["read"])
    seed = _seed(c, monkeypatch, plan=[body_digest(planned)])
    r = af.submit(c, seed, af.grant("g-seed-mal", mal[0], r21.SHELF, r21.ALL), batch="seed")
    assert r.status_code == 403 and "plan" in r.text
    assert _alerts() == []


def test_a_seed_with_no_plan_makes_no_entry(unsealed_world, monkeypatch):
    c, alice, _bob = unsealed_world
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, r21.SHELF, r21.ALL), batch="s"))
    seed = _seed(c, monkeypatch)
    r = af.submit(c, seed, af.grant("g-seed-carol", carol[0], r21.SHELF, ["read"]), batch="seed")
    assert r.status_code == 403
