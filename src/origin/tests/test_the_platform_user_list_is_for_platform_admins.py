"""`GET /internal/authority/platform-users`: Origin's own identity records, listed for a platform
admin, decided by Origin's own replica.

Origin already knows every sign-up, so the platform's user list reads its person records rather
than a card in Mantle (John, 2026-11-02). Who may list them is unchanged from Mantle's rule
(`dependencies.is_platform_admin`): a person holding an active allow grant carrying Admin on the
platform's Authorities collection, or the operator while no one does yet (someone has to appoint
the first admin). Origin decides it from its own replica, never from Mantle's say-so:

* Mantle's service token, bound to this method, path, `limit` and `offset`, single-use;
* the caller's own credential (`X-Acting-Credential`): a person's access token or delegation, never
  a background, seed or bootstrap one;
* the Authorities collection Origin checks is its own setting, `platform.authority_collection_id`,
  which only the operator console changes; Mantle cannot name another collection.
"""
from __future__ import annotations

import uuid

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

PATH = "/internal/authority/platform-users"


def _authorities(c, monkeypatch, founder_token, actions=("read",)):
    """The Authorities collection at Origin, made by `founder` in one batch with a creation grant
    carrying `actions`, and pinned. A founder whose grant carries Admin is a platform admin."""
    from jose import jwt as jose_jwt

    from origin.services.platform_settings_service import settings as platform_settings

    founder = jose_jwt.get_unverified_claims(founder_token)["sub"]
    aid = f"authorities-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, founder_token, af.root(aid), batch=aid))
    af.ok(af.submit(c, founder_token, af.grant(f"g-{aid}", founder, aid, actions=actions),
                    batch=aid))
    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw: aid
                        if k == "platform.authority_collection_id" else real_get(k, *a, **kw))
    return aid


def _list(c, credential, *, limit=50, offset=0, token=None):
    claims = {"htu": PATH, "limit": limit, "offset": offset}
    tok = token or _shares._token("GET", "-", **claims)
    headers = {"Authorization": f"Bearer {tok}"}
    if credential:
        headers["X-Acting-Credential"] = credential
    return c.get(PATH, params={"limit": limit, "offset": offset}, headers=headers)


def test_a_platform_admin_lists_every_person(custody_client, monkeypatch):
    c = custody_client
    af.operator(monkeypatch)
    ada, ada_token = af.person("Ada", email="ada@x.test")
    bo, _ = af.person("Bo", email="bo@x.test")
    _authorities(c, monkeypatch, ada_token, actions=("read", "admin"))
    r = _list(c, ada_token)
    assert r.status_code == 200, r.text
    body = r.json()
    ids = {u["id"] for u in body["users"]}
    assert {ada, bo} <= ids and body["total"] == len(body["users"])
    one = next(u for u in body["users"] if u["id"] == bo)
    assert one["email"] == "bo@x.test" and one["name"] == "Bo" and "password_hash" not in one


def test_pages_are_taken_at_origin(custody_client, monkeypatch):
    c = custody_client
    af.operator(monkeypatch)
    ada, ada_token = af.person("Ada")
    for _ in range(3):
        af.person()
    _authorities(c, monkeypatch, ada_token, actions=("read", "admin"))
    whole = _list(c, ada_token).json()
    page = _list(c, ada_token, limit=2, offset=1).json()
    assert page["total"] == whole["total"] and len(page["users"]) == 2
    assert [u["id"] for u in page["users"]] == [u["id"] for u in whole["users"]][1:3]


def test_a_person_who_is_no_admin_is_refused(custody_client, monkeypatch):
    c = custody_client
    op = af.operator(monkeypatch)
    _authorities(c, monkeypatch, op)
    _p, token = af.person("P")
    assert _list(c, token).status_code == 403


def test_the_operator_lists_only_while_no_one_is_admin(custody_client, monkeypatch):
    c = custody_client
    op = af.operator(monkeypatch)
    _authorities(c, monkeypatch, op)                            # the operator holds Read only
    assert _list(c, op).status_code == 200                      # the first admin is appointed
    _ada, ada_token = af.person("Ada")
    _authorities(c, monkeypatch, ada_token, actions=("read", "admin"))
    assert _list(c, op).status_code == 403                      # then only by grant


def test_with_no_authorities_pinned_only_the_operator_lists(custody_client, monkeypatch):
    c = custody_client
    op = af.operator(monkeypatch)
    _p, token = af.person("P")
    assert _list(c, op).status_code == 200
    assert _list(c, token).status_code == 403


def test_a_caller_with_no_credential_or_a_background_one_is_refused(custody_client, monkeypatch):
    c = custody_client
    op = af.operator(monkeypatch)
    aid = _authorities(c, monkeypatch, op)
    assert _list(c, None).status_code == 401
    background = _shares.own_credential(aid)
    assert _list(c, background).status_code == 403


def test_a_token_not_bound_to_this_page_or_spent_is_refused(custody_client, monkeypatch):
    c = custody_client
    op = af.operator(monkeypatch)
    _authorities(c, monkeypatch, op)
    other = _shares._token("GET", "-", htu=PATH, limit=50, offset=50)
    assert _list(c, op, token=other).status_code == 401          # bound to another page
    tok = _shares._token("GET", "-", htu=PATH, limit=50, offset=0)
    assert _list(c, op, token=tok).status_code == 200
    assert _list(c, op, token=tok).status_code == 401            # single-use
    assert c.get(PATH, headers={"X-Acting-Credential": op}).status_code in (401, 403)


def test_only_the_console_pins_the_authorities_collection():
    from origin.services.platform_settings_service import is_console_key

    assert is_console_key("platform.authority_collection_id")
