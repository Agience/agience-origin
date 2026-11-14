"""Grant keys are minted, listed and revoked at Origin's own page (John, 2026-11-14).

A key is a `key` ledger entry (the token's sha256 and last four characters, never the token) and
one `grant` per member, whose grantee (type `grant`) is the key. It is made only in the person's
Origin session, ends within 90 days, carries only what the person may grant (Admin on each
resource, nothing they do not hold), and is revoked by the person who minted it. `agent` names the
agent it is for (FR-028).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import _root

custody_client = _shares.custody_client
PATH = "/auth/me/keys"


def _days(d):
    return (datetime.now(timezone.utc) + timedelta(days=d)).isoformat()


def _post(c, who, path, body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    step = oc.person_reauth(c, who[1], who[0], "POST", path, raw)
    headers = {"Authorization": f"Bearer {who[1]}", "X-Step-Up": step}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return c.post(path, content=raw, headers=headers)


def _mint(c, who, **over):
    body = {"name": "backlog reader", "expires_at": _days(30),
            "members": [{"resource_id": who[0], "actions": ["read"]}], **over}
    return _post(c, who, PATH, body)


def _keys(c, who):
    r = c.get(PATH, headers={"Authorization": f"Bearer {who[1]}"})
    assert r.status_code == 200, r.text
    return r.json()["keys"]


def _people(c):
    alice = af.person("alice", email="alice@team.test")
    bob = af.person("bob", email="bob@team.test")
    _root(c, alice, alice[0])
    _root(c, bob, bob[0])
    oc.origin_page_session(c, alice[0])
    return alice, bob


def test_a_key_is_minted_once_and_listed_without_its_token(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityKey
    c = custody_client
    alice, _ = _people(c)
    r = _mint(c, alice, agent="chair-bot")
    assert r.status_code == 201, r.text
    out = r.json()
    token = out["token"]
    assert token.startswith("agk_") and r.headers.get("cache-control") == "no-store"
    with SessionLocal() as db:
        row = db.get(AuthorityKey, out["grant_id"])
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert row.created_by == alice[0] and row.agent == "chair-bot"
    [k] = _keys(c, alice)
    assert k["hint"] == token[-4:] and k["state"] == "active" and k["agent"] == "chair-bot"
    assert "token_hash" not in k and token not in json.dumps(k)
    assert k["members"] == [{"resource_id": alice[0], "actions": ["read"], "state": "active"}]


def test_a_key_ends_within_ninety_days(custody_client):
    c = custody_client
    alice, _ = _people(c)
    assert _mint(c, alice, expires_at=_days(91)).status_code == 400
    assert _mint(c, alice, expires_at=_days(-1)).status_code == 400
    assert _mint(c, alice, expires_at=_days(89)).status_code == 201


def test_a_member_the_person_may_not_grant_leaves_no_live_key(custody_client):
    c = custody_client
    alice, bob = _people(c)
    r = _mint(c, alice, members=[{"resource_id": alice[0], "actions": ["read"]},
                                 {"resource_id": bob[0], "actions": ["read"]}])
    assert r.status_code == 403 and "admin" in r.text, r.text
    assert all(k["state"] == "revoked" for k in _keys(c, alice))


def test_a_key_is_never_made_on_a_token_mantle_holds(custody_client):
    c = custody_client
    alice, _ = _people(c)
    entry = {"kind": "key", "grant_id": "k-mantle", "token_hash": "0" * 64, "hint": "abcd",
             "name": "x", "expires_at": _days(7), "state": "active"}
    r = af.submit(c, alice[1], entry, batch=None)
    assert r.status_code == 403 and "Origin's own page" in r.text, r.text
    member = af.grant("m-mantle", "k-mantle", alice[0], grantee_type="grant")
    r = af.submit(c, alice[1], member, batch=None)
    assert r.status_code == 403, r.text


def test_only_the_person_who_minted_it_revokes_it_and_it_stays_revoked(custody_client):
    c = custody_client
    alice, bob = _people(c)
    kid = _mint(c, alice).json()["grant_id"]
    oc.origin_page_session(c, bob[0])
    assert _post(c, bob, f"{PATH}/{kid}/revoke").status_code == 404
    oc.origin_page_session(c, alice[0])
    r = _post(c, alice, f"{PATH}/{kid}/revoke")
    assert r.status_code == 200 and r.json()["revoked"] is True, r.text
    assert _keys(c, alice)[0]["state"] == "revoked"
    assert _post(c, alice, f"{PATH}/{kid}/revoke").status_code == 200    # unchanged, still revoked


def test_a_key_route_needs_the_person_s_session(custody_client):
    c = custody_client
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    r = c.post(PATH, json={"name": "x", "expires_at": _days(7),
                           "members": [{"resource_id": alice[0], "actions": ["read"]}]},
               headers={"Authorization": f"Bearer {alice[1]}"})
    assert r.status_code == 403, r.text


def test_the_key_page_answers_only_the_app_that_opened_it(custody_client, monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "APP_URI", "https://my.agience.test")
    monkeypatch.setattr(config, "FACET_URIS", [])
    c = custody_client
    assert c.get("/key", params={"back": "https://evil.test"}).status_code == 400
    assert c.get("/key").status_code == 400
    r = c.get("/key", params={"back": "https://my.agience.test"})
    assert r.status_code == 200 and "key-page.js" in r.text
    assert r.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
