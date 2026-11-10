"""A timer runs on an Origin job grant (John, 2026-11-10, BUG-024 and BUG-035).

Arming a timer is a job grant the person makes at Origin's page, in their Origin session with a
step-up: job `lumen.timer.<timer id>`, over their own key, naming what the timer reaches (`reach`)
and nothing else. Lumen, on its own key, asks Origin for a firing's delegation under it: narrowed to
Lumen or Crystal, five minutes, carrying the reach (`job_reach`), which every exchange from it
keeps. A revoked grant mints nothing, and a timer's grant mints no background delegation: its
firing opens the person's key only for the artifacts it lists
(`test_a_job_s_delegation_opens_only_its_grant_s_artifacts`).
"""
from __future__ import annotations

from contextlib import contextmanager

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_background_work_runs_on_a_job_grant as _jobs
from origin.tests.test_background_work_runs_on_a_job_grant import _mint, _root, job_grant

custody_client = _jobs.custody_client
people = _jobs.people

TIMER = "lumen.timer.t-1"


def _timer_grant(gid, person, reach=("t-1", "ws-1"), **kw):
    return {**job_grant(gid, TIMER, person, **kw), "reach": list(reach)}


@contextmanager
def _as(c, name):
    from origin.services.dependencies import AuthContext, get_auth
    c.app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=name, principal_type="service", user_id=None)
    try:
        yield
    finally:
        c.app.dependency_overrides.pop(get_auth, None)


def _ask(c, person, *, audience="lumen", job=TIMER, who="lumen", grant="jg-t"):
    with _as(c, who):
        return c.post("/internal/job-delegation",
                      json={"principal": person, "job": job, "audience": audience,
                            "job_grant": grant})


def test_a_timer_s_grant_names_its_reach_and_only_a_timer_s_does(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _root(c, alice, alice[0])
    assert af.page(alice[0], job_grant("jg-0", TIMER, alice[0])).status_code == 400
    assert af.page(alice[0], {**job_grant("jg-1", "platform.reindex", alice[0]),
                              "reach": ["a"]}).status_code == 400
    assert af.page(bob[0], _timer_grant("jg-2", alice[0])).status_code == 403
    af.ok(af.page(alice[0], _timer_grant("jg-3", alice[0], reach=("ws-1", "t-1", "t-1"))))
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al
    with SessionLocal() as db:
        view = next(g for g in al.person_job_grants(db, alice[0]) if g["grant_id"] == "jg-3")
    assert view["reach"] == ["t-1", "ws-1"]


def test_an_entry_without_a_reach_keeps_its_shape():
    from origin.services import authority_ledger as al
    plain = al.normalise(job_grant("jg-1", "platform.reindex", "p"))
    assert "reach" not in plain
    assert "reach" not in al.normalise({**job_grant("jg-1", "platform.reindex", "p"), "reach": []})


def test_lumen_mints_a_firing_s_delegation_under_a_live_grant_only(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _root(c, alice, alice[0])
    assert _ask(c, alice[0]).status_code == 403                       # no grant yet
    af.ok(af.page(alice[0], _timer_grant("jg-t", alice[0])))
    for audience in ("lumen", "crystal"):
        r = _ask(c, alice[0], audience=audience)
        assert r.status_code == 200, r.text
        claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
        assert claims["sub"] == alice[0] and claims["aud"] == audience
        assert claims["scope"] == f"persona:{audience}" and claims["narrowed"] is True
        assert claims["job_reach"] == ["t-1", "ws-1"] and claims["job_grant"] == "jg-t"
        assert claims["exp"] - claims["iat"] <= 300
    for who in ("sage", "chorus", "mantle"):                          # Lumen's own key alone
        assert _ask(c, alice[0], who=who).status_code == 403, who
    assert _ask(c, alice[0], audience="sage").status_code == 400
    assert _ask(c, alice[0], job="platform.reindex").status_code == 400
    assert _ask(c, alice[0], job="lumen.timer.other").status_code == 403
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al
    with SessionLocal() as db:
        al.page_revoke_job_grant(db, alice[0], "jg-t")
    assert _ask(c, alice[0]).status_code == 403                       # revoked: nothing


def test_a_firing_draws_only_on_the_grant_its_timer_was_armed_on(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _root(c, alice, alice[0])
    _root(c, bob, bob[0])
    af.ok(af.page(alice[0], _timer_grant("jg-wide", alice[0], reach=("t-1", "ws-1", "y"))))
    af.ok(af.page(alice[0], _timer_grant("jg-narrow", alice[0], reach=("t-1",))))
    r = _ask(c, alice[0], grant="jg-narrow")
    assert r.status_code == 200, r.text
    assert jose_jwt.get_unverified_claims(r.json()["access_token"])["job_reach"] == ["t-1"]
    assert _ask(c, alice[0], grant="jg-nope").status_code == 403
    af.ok(af.page(bob[0], _timer_grant("jg-bob", bob[0])))
    assert _ask(c, alice[0], grant="jg-bob").status_code == 403       # another person's grant


def test_a_grant_s_delegations_are_counted_by_the_minute(custody_client, people, monkeypatch):
    from origin.services import share_credentials
    c = custody_client
    alice = people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], _timer_grant("jg-t", alice[0])))
    monkeypatch.setattr(share_credentials, "JOB_ISSUANCE_PER_MINUTE", 3)
    assert [_ask(c, alice[0]).status_code for _ in range(4)] == [200, 200, 200, 429]


def test_a_timer_s_grant_releases_no_key_share(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], _timer_grant("jg-t", alice[0])))
    r = _mint(c, alice[0], TIMER)
    assert r.status_code == 403 and "releases no key share" in r.text


def test_every_exchange_from_a_firing_s_delegation_keeps_its_reach(custody_client, people):
    from origin.services import auth_service
    c = custody_client
    alice = people["alice"]
    narrowed = auth_service.issue_narrow_delegation(
        alice[0], "lumen", ["persona:lumen"], job_reach=["t-1"], job_grant="jg-t")
    with _as(c, "lumen"):
        server = c.post("/internal/delegation-token",
                        json={"server_client_id": "agience-server-lumen",
                              "subject_token": narrowed})
        hop = c.post("/internal/narrow-hop", json={"subject_token": narrowed, "audience": "sage"})
    assert server.status_code == 200, server.text
    assert hop.status_code == 200, hop.text
    for token in (server.json()["token"], hop.json()["access_token"]):
        claims = jose_jwt.get_unverified_claims(token)
        assert claims["job_reach"] == ["t-1"] and claims["job_grant"] == "jg-t"
    # One with no reach gains none.
    plain = auth_service.issue_narrow_delegation(alice[0], "lumen", ["persona:lumen"])
    with _as(c, "lumen"):
        r = c.post("/internal/delegation-token",
                   json={"server_client_id": "agience-server-lumen", "subject_token": plain})
    assert "job_reach" not in jose_jwt.get_unverified_claims(r.json()["token"])


def test_the_approval_page_answers_only_the_app_it_serves(custody_client, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "APP_URI", "https://my.agience.test")
    monkeypatch.setattr(config, "FACET_URIS", [])
    assert custody_client.get("/job-grant", params={"back": "https://evil.test"}).status_code == 400
    assert custody_client.get("/job-grant").status_code == 400
    r = custody_client.get("/job-grant", params={"back": "https://my.agience.test"})
    assert r.status_code == 200 and "job-grant-page.js" in r.text
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
