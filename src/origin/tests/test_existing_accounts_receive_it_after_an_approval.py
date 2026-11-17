"""Existing accounts receive what "New accounts receive" lists only after an approval (BUG-091).

The dry run is an invoke on the collection: it lists every grant an account does not hold yet and
files the list as one request on the collection, one step per grant. Whoever holds update on the
collection decides; the run spends the note once per step and makes each grant as the operator's
own entry. Nothing is granted before the decision, and a second run grants nothing more.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_new_account_receives_what_the_collection_lists as _new

_grants = _new._grants
custody_client = _new.custody_client
platform = _new.platform


@pytest.fixture()
def people(platform):
    """A runner who reaches invoke on N, an approver who reaches update on it, and two accounts. The
    operator shares its root, the collection's parent, with each."""
    c, _n, op_token = platform
    runner, approver = af.person("runner"), af.person("approver")
    af.ok(af.submit(c, op_token, af.grant("g-run", runner[0], af.OPERATOR, ["read", "invoke"]),
                    batch="p"))
    af.ok(af.submit(c, op_token, af.grant("g-approver", approver[0], af.OPERATOR, ["read", "update"]),
                    batch="p"))
    return runner[0], approver[0], af.person("alice")[0], af.person("bob")[0]


def _approve(req_id, approver):
    from origin.db.session import SessionLocal
    from origin.services import decision_notes as notes
    with SessionLocal() as db:
        req = notes.get_request(db, req_id)
        notes.approve(db, req, person_id=approver, digest=req.digest,
                      auth_time=datetime.now(timezone.utc), amr=["pop"])


def _file(who):
    from origin.db.session import SessionLocal
    from origin.services import new_accounts_backfill as B
    with SessionLocal() as db:
        return B.file(db, who, who)


def _run(who, req_id):
    from origin.db.session import SessionLocal
    from origin.services import new_accounts_backfill as B
    with SessionLocal() as db:
        return B.run(db, who, req_id)


def test_the_dry_run_lists_and_files_and_grants_nothing(people):
    runner, approver, alice, bob = people
    out = _file(runner)
    listed = {(g["person"], g["resource"], ",".join(g["actions"])) for g in out["grants"]}
    for p in (alice, bob):
        assert (p, "C-ops", "invoke,read") in listed and (p, "S-seed", "read") in listed
    assert out["request"] and _grants(alice) == []


def test_the_run_grants_after_the_approval_and_once(people):
    from origin.services.new_accounts_backfill import BackfillRefused
    runner, approver, alice, bob = people
    out = _file(runner)
    with pytest.raises(BackfillRefused) as e:
        _run(runner, out["request"])
    assert e.value.status == 409 and _grants(alice) == []
    _approve(out["request"], approver)
    done = _run(runner, out["request"])
    assert done["granted"] == len(out["grants"]) and done["refused"] == []
    assert _grants(alice) == [("C-ops", "invoke,read"), ("S-seed", "read")]
    again = _run(runner, out["request"])
    assert again["granted"] == 0 and again["held"] == len(out["grants"])


def test_one_without_invoke_on_the_collection_cannot_file(people):
    from origin.services.new_accounts_backfill import BackfillRefused
    _runner, approver, alice, _bob = people
    for who in (approver, alice):
        with pytest.raises(BackfillRefused) as e:
            _file(who)
        assert e.value.status == 403


def test_only_the_one_the_note_is_for_runs_it(people, platform):
    from origin.services.new_accounts_backfill import BackfillRefused
    runner, approver, alice, _bob = people
    c, _n, op_token = platform
    other = af.person("other")[0]
    af.ok(af.submit(c, op_token, af.grant("g-other", other, af.OPERATOR, ["read", "invoke"]),
                    batch="o"))
    out = _file(runner)
    _approve(out["request"], approver)
    with pytest.raises(BackfillRefused) as e:
        _run(other, out["request"])
    assert e.value.status == 403 and _grants(alice) == []


def test_nothing_to_grant_files_nothing(people):
    runner, approver, _alice, _bob = people
    out = _file(runner)
    _approve(out["request"], approver)
    _run(runner, out["request"])
    assert _file(runner) == {"collection": out["collection"], "grants": [], "request": None}


def test_the_dry_run_is_taken_in_the_runner_s_origin_session(people, platform):
    from origin import config
    from origin.tests.test_an_admin_approves_on_origin_s_page import _session
    runner, _approver, alice, _bob = people
    c = platform[0]
    _session(c, runner)
    r = c.post("/auth/me/authority/new-accounts-receive/backfill", json={},
               headers={"Origin": config.ORIGIN_URI, "X-Origin-Session": "1"})
    assert r.status_code == 200, r.text
    assert r.json()["request"] and _grants(alice) == []
