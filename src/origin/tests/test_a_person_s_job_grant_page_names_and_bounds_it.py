"""A person's job grant, made at Origin's own page, is named on its confirm page and bounded.

* The step-up for `POST /auth/me/job-grants` carries the request's body, so Origin's confirm page
  names the job, the collections and the expiry the person is about to grant, as a link's names
  the identity it joins. A step-up asked for with the body's digest alone is refused: Origin would
  have nothing to show. A revoke's page names the grant it stops.
* A job grant made there lives at most `JOB_GRANT_MAX_DAYS` (30): one asked for longer is refused,
  the same bound the operator console's grants keep
  (`test_the_operator_console_cannot_be_taken_over`).
"""
from __future__ import annotations

import hashlib
import json

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import _root
from origin.tests.test_the_ninth_review_s_job_grant_cases import PATH, _days, _page_grant

custody_client = _shares.custody_client


def _options(c, who, method, path, raw: bytes, *, with_body: bool):
    oc.origin_page_session(c, who[0])
    body = {"method": method, "path": path, "body_sha256": hashlib.sha256(raw).hexdigest()}
    if with_body:
        body["body"] = raw.decode()
    return c.post("/auth/me/step-up-options", json=body,
                  headers={"Authorization": f"Bearer {who[1]}"})


def _local_identity(person_id):
    from origin.db import person_identities as db_identities
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        db_identities.add(db, person_id=person_id, method="oidc", provider="local",
                          subject=str(person_id), verified=True)
        db.commit()


def test_the_confirm_page_names_the_job_its_collections_and_its_expiry(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _local_identity(alice[0])
    until = _days(7)
    raw = json.dumps({"job": "platform.reindex", "expires_at": until,
                      "collections": ["col-1", "col-2"]}).encode()
    r = _options(c, alice, "POST", PATH, raw, with_body=True)
    assert r.status_code == 200 and r.json()["kind"] == "reauth", r.text
    page = c.get("/auth/reauth/start", params={"ticket": r.json()["ticket"]}).text
    assert "platform.reindex" in page and "col-1, col-2" in page and until in page
    assert "?" not in page.split("<strong>")[1].split("</strong>")[0]


def test_a_job_grant_step_up_without_its_body_is_refused(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _local_identity(alice[0])
    raw = json.dumps({"job": "platform.reindex", "expires_at": _days(7)}).encode()
    r = _options(c, alice, "POST", PATH, raw, with_body=False)
    assert r.status_code == 400, r.text


def test_a_revoke_s_confirm_page_names_the_grant_it_stops(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    gid = _page_grant(c, alice, {"job": "platform.reindex", "expires_at": _days(7)}).json()[
        "grant_id"]
    r = _options(c, alice, "POST", f"{PATH}/{gid}/revoke", b"", with_body=False)
    assert r.status_code == 200, r.text
    page = c.get("/auth/reauth/start", params={"ticket": r.json()["ticket"]}).text
    action = page.split("<strong>")[1].split("</strong>")[0]
    assert "platform.reindex" in action and "stop" in action and "?" not in action


def test_a_person_s_job_grant_lives_at_most_thirty_days(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    long = _page_grant(c, alice, {"job": "platform.reindex", "expires_at": _days(31)})
    assert long.status_code == 400 and "within 30 days" in long.text, long.text
    ok = _page_grant(c, alice, {"job": "platform.reindex", "expires_at": _days(29)})
    assert ok.status_code == 200, ok.text
