"""A workflow's Run now takes a one-shot job grant (John, 2026-11-10).

`lumen.run.<workflow>.<nonce>`: made at Origin's page with a step-up, over the person's own key,
naming its reach; it ends within minutes, and only one delegation is ever minted under it, to
Crystal, carrying the reach. A second is refused, as is one for Lumen, and so is every key outside
the reach.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_background_work_runs_on_a_job_grant as _jobs
from origin.tests.test_a_timer_runs_on_its_job_grant import _ask
from origin.tests.test_background_work_runs_on_a_job_grant import _root, job_grant

custody_client = _jobs.custody_client
people = _jobs.people

RUN = "lumen.run.wf-1.n1"


def _run_grant(gid, person, minutes=10, reach=("wf-1", "op-1", "note-1")):
    until = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
    return {**job_grant(gid, RUN, person, expires_at=until), "reach": list(reach)}


def test_a_run_grant_names_its_reach_and_ends_within_minutes(custody_client, people):
    alice = people["alice"]
    _root(custody_client, alice, alice[0])
    assert af.page(alice[0], _run_grant("jg-long", alice[0], minutes=60)).status_code == 400
    assert af.page(alice[0], {**_run_grant("jg-none", alice[0]), "reach": []}).status_code == 400
    af.ok(af.page(alice[0], _run_grant("jg-r", alice[0])))


def test_one_delegation_to_crystal_and_never_another(custody_client, people):
    c, alice = custody_client, people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], _run_grant("jg-r", alice[0])))
    assert _ask(c, alice[0], job=RUN, grant="jg-r", audience="lumen").status_code == 400
    first = _ask(c, alice[0], job=RUN, grant="jg-r", audience="crystal")
    assert first.status_code == 200, first.text
    claims = jose_jwt.get_unverified_claims(first.json()["access_token"])
    assert claims["aud"] == "crystal" and claims["job_reach"] == ["note-1", "op-1", "wf-1"]
    assert claims["exp"] - claims["iat"] <= 300
    again = _ask(c, alice[0], job=RUN, grant="jg-r", audience="crystal")
    assert again.status_code == 403 and "its one run" in again.text


def test_a_run_s_delegation_opens_only_the_keys_its_reach_lists(custody_client, people):
    from origin.tests.test_a_job_s_delegation_opens_only_its_grant_s_artifacts import _job_delegation
    c, alice = custody_client, people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], _run_grant("jg-r", alice[0])))
    af.store_share(c, alice[0], alice[1])
    tok = _job_delegation(alice[0], reach=("note-1", "op-1", "wf-1"), grant="jg-r", persona="crystal")
    assert af.release(c, alice[0], tok, artifact="note-1").status_code == 200
    assert af.release(c, alice[0], tok, artifact="elsewhere").status_code == 403


def test_a_run_grant_releases_no_background_key_share(custody_client, people):
    from origin.tests.test_background_work_runs_on_a_job_grant import _mint
    c, alice = custody_client, people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], _run_grant("jg-r", alice[0])))
    assert _mint(c, alice[0], RUN).status_code == 403


def test_a_run_is_claimed_once_even_when_asked_for_twice_at_once(custody_client, people, monkeypatch):
    """The review's race (2026-11-10): two requests that both read 'no delegation yet' each minted.
    The run is claimed by a row keyed on its grant; the second claim fails on that key."""
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyDelegation
    c, alice = custody_client, people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], _run_grant("jg-r", alice[0])))
    # The other request's claim, already written when this one arrives.
    with SessionLocal() as db:
        db.add(KeyCustodyDelegation(jti="run:jg-r", subject=alice[0], issued_by="x", job_grant_id="jg-r",
                                    job=RUN, collections="[]",
                                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
        db.commit()
    r = _ask(c, alice[0], job=RUN, grant="jg-r", audience="crystal")
    assert r.status_code == 403 and "its one run" in r.text
