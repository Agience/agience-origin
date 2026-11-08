# ruff: noqa: F811 — `world` is a pytest fixture, imported and named as a parameter
"""Review 14's cases, each refused on Origin's own rules.

H1: a resource is "deleted in this batch" only when the batch removes its own creation edge (a
co-signed creation `edge.add` for that very pair). A secondary edge added and removed proves
nothing, and a root, which never has a creation edge, is never deleted this way: no token Mantle
holds retires a deny or another's grant on it.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, _grant_row, world)

custody_client = _shares.custody_client


def _carol_workspace(c, carol, cid):
    carol_id, tok = carol
    af.ok(af.submit(c, tok, af.root(cid), batch="mk", via_session=False))
    af.ok(af.submit(c, tok, af.grant(f"g-{cid}", carol_id, cid, ALL), batch="mk",
                    via_session=False))


def test_a_secondary_edge_removed_lifts_no_deny_on_a_root(custody_client, world):
    c = custody_client
    bob_id, bob = world["bob"]
    carol = world["carol"]
    alice = world["alice"][1]
    af.ok(af.submit(c, alice, af.grant("g-deny-b", bob_id, "W", ["read"], effect="deny")))
    af.store_share(c, "ck:W")
    _carol_workspace(c, carol, "CW")
    af.ok(af.submit(c, carol[1], af.edge("CW", "W", origin=False), batch="a", via_session=False))
    af.ok(af.submit(c, carol[1], af.unedge("CW", "W"), batch="z", via_session=False))
    r = af.submit(c, carol[1], af.grant("g-deny-b", bob_id, "W", ["read"], effect="deny",
                                        state="deleted"), batch="z", via_session=False)
    assert r.status_code == 403, r.text
    assert _grant_row("g-deny-b").state == "active"
    assert af.release(c, "ck:W", bob, collection="W").status_code == 403


def test_a_secondary_edge_removed_retires_no_one_s_admin_on_a_root(custody_client, world):
    c = custody_client
    alice_id = world["alice"][0]
    carol = world["carol"]
    _carol_workspace(c, carol, "CW2")
    af.ok(af.submit(c, carol[1], af.edge("CW2", "W", origin=False), batch="a",
                    via_session=False))
    af.ok(af.submit(c, carol[1], af.unedge("CW2", "W"), batch="z", via_session=False))
    r = af.submit(c, carol[1], af.grant("g-aw", alice_id, "W", ALL, state="deleted"),
                  batch="z", via_session=False)
    assert r.status_code == 403, r.text
    assert _grant_row("g-aw").state == "active"


def test_a_real_deletion_still_retires_the_grants_on_its_member(custody_client, world):
    """Control: removing the member's own creation edge, on Delete, retires its grants in the
    same batch."""
    c = custody_client
    alice_id, alice = world["alice"]
    af.ok(af.submit(c, alice, af.edge("W", "M1"), batch="m", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-am1", alice_id, "M1", ["read", "delete"]), batch="m",
                    via_session=False))
    af.ok(af.submit(c, alice, af.unedge("W", "M1"), batch="d", via_session=False))
    r = af.submit(c, alice, af.grant("g-am1", alice_id, "M1", ["read", "delete"],
                                     state="deleted"), batch="d", via_session=False)
    assert r.status_code == 200, r.text
    assert _grant_row("g-am1").state == "deleted"


def test_a_grant_names_only_a_known_persona_server(custody_client, world):
    """A persona server is a grantee only if Origin knows it (its persona list or the authority
    manifest): `agience-server-<anything>` is not someone."""
    c = custody_client
    alice_id, alice = world["alice"]
    r = af.session_submit(c, alice_id, af.grant("g-nobody", "agience-server-nobody", "W",
                                                ["read"]))
    assert r.status_code == 403 and "does not exist" in r.text, r.text
    ok = af.session_submit(c, alice_id, af.grant("g-lumen", "agience-server-lumen", "W",
                                                 ["read"]))
    assert ok.status_code == 200, ok.text


# -- M1: on https only the __Host- names are Origin's ----------------------------------------------

import asyncio  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture
def https(monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://my.agience.ai", raising=False)
    return {"Origin": "https://my.agience.ai", "X-Origin-Session": "1"}


class _Req:
    def __init__(self, cookie):
        from starlette.datastructures import Headers
        self.headers = Headers(raw=[(b"cookie", cookie.encode())])


def _session(pid):
    from origin.db.session import SessionLocal
    from origin.services import origin_session
    with SessionLocal() as db:
        raw = origin_session.issue(db, pid)
        db.commit()
    return raw


def test_on_https_the_reader_ignores_an_unprefixed_cookie(custody_client, https):
    """Reader side, alone: on https `_raw` reads only `__Host-origin_session`; a cookie a sibling
    host could set (no prefix) is not the session."""
    from origin.services import origin_session
    assert origin_session._raw(_Req("origin_session=tossed")) == ""
    assert origin_session._raw(_Req("__Host-origin_session=mine; origin_session=tossed")) == "mine"


def test_on_https_a_tossed_unprefixed_cookie_neither_fixes_nor_locks_a_session(custody_client,
                                                                                https):
    c = custody_client
    mal_id, _ = af.person("mal", email="mal@x.test")
    bob_id, _ = af.person("bob2", email="bob2@x.test")
    mal_raw, bob_raw = _session(mal_id), _session(bob_id)
    c.cookies.clear()
    r = c.get("/auth/me/authority/grants", params={"resource_id": "nothing"},
              headers={**https, "Cookie": f"origin_session={mal_raw}"})
    assert r.status_code == 401, r.text                      # no fixation: Mal's is not read
    r = c.post("/auth/me/authority/grants/g-anything/revoke",
               headers={**https,
                        "Cookie": f"__Host-origin_session={bob_raw}; origin_session=tossed"})
    assert r.status_code == 404, r.text                      # no lock-out: Bob's session runs


def test_raw_alone_refuses_two_values_of_the_session_cookie(https):
    """`_raw` refuses on its own, whatever the middleware does."""
    from origin.services import origin_session
    with pytest.raises(origin_session.TossedCookie):
        origin_session._raw(_Req("__Host-origin_session=a; __Host-origin_session=b"))


def _through_middleware(cookie):
    from origin.services.origin_session import RefuseTossedCookies
    seen = {}

    async def app(scope, receive, send):
        seen["headers"] = [v.decode() for k, v in scope["headers"] if k == b"cookie"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "GET", "path": "/", "headers": [(b"cookie", cookie.encode())]}
    asyncio.run(RefuseTossedCookies(app)(scope, receive, send))
    return sent[0]["status"], seen.get("headers")


def test_the_middleware_alone_refuses_two_sign_in_cookies(https):
    """The middleware is the only guard on the sign-in flow's own cookie: on its own it refuses
    two values of `__Host-session`, before the app runs."""
    status, seen = _through_middleware("__Host-session=a; __Host-session=b")
    assert status == 400 and seen is None


def test_on_https_the_middleware_drops_unprefixed_cookies_before_the_app(https):
    status, seen = _through_middleware("__Host-session=a; session=tossed; origin_session=t2")
    assert status == 200
    assert seen == ["__Host-session=a"]


# -- M4: Origin echoes what the invite is for -----------------------------------------------------

def test_the_invite_answer_and_mail_echo_the_resource_and_the_name_the_owner_confirmed(
        custody_client, monkeypatch):
    from origin import config
    from origin.services import email_service
    from origin.tests import operator_console_fixtures as oc

    sent = []

    async def send_invite(to_email, from_name, resource_name, claim_url, message=None):
        sent.append((to_email, resource_name, claim_url))
        return True

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "send_invite", send_invite)
    c = custody_client
    alice_id, alice = af.person("alice", email="alice@team.test")
    af.ok(af.submit(c, alice, af.root("R1"), batch="r", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-r1", alice_id, "R1", ALL), batch="r",
                    via_session=False))
    oc.origin_page_session(c, alice_id)
    hdr = {"X-Origin-Session": "1", "Origin": config.APP_URI or config.ORIGIN_URI}
    seen = c.post("/auth/me/authority/preview", json={"resource_id": "R1"},
                  headers=hdr).json()["preview"]
    r = c.post("/auth/me/authority/invites",
               json={"resource_id": "R1", "resource_name": "Quarterly plan",
                     "actions": ["read"], "email": "bob@team.test", "preview": seen},
               headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["resource_id"] == "R1" and r.json()["resource_name"] == "Quarterly plan"
    assert sent and sent[0][1] == "Quarterly plan"


# -- low: a hop assertion is single-use, current and bound to its subject ---------------------------

from origin.tests.test_the_twelfth_review_s_token_cases import (  # noqa: E402,F401
    _endpoint_hop, _exchange, crystal_key)


def _bound(key, subject, *, jti="j-1", iat_shift=0, ttl=60, digest=None):
    import hashlib
    import time

    from jose import jwt as jose_jwt

    from origin import config
    from origin.tests import test_a_key_share_is_released_only_to_mantle as shares
    now = int(time.time()) + iat_shift
    return jose_jwt.encode(
        {"iss": "crystal", "sub": "crystal",
         "aud": f"{config.ORIGIN_URI.rstrip('/')}/auth/token", "principal_type": "service",
         "iat": now, "exp": now + ttl, "jti": jti,
         "subject_digest": digest or hashlib.sha256(subject.encode()).hexdigest()},
        shares._pem(key), algorithm="RS256", headers={"kid": "crystal-1"})


def test_a_hop_assertion_is_used_once(custody_client, crystal_key):
    c = custody_client
    _p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    a = _bound(crystal_key, crystal, jti="once")
    assert _endpoint_hop(c, crystal, "sage", a).status_code == 200
    assert _endpoint_hop(c, crystal, "sage", a).status_code == 401


def test_a_hop_assertion_from_the_future_or_living_long_is_refused(custody_client, crystal_key):
    c = custody_client
    _p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    assert _endpoint_hop(c, crystal, "sage",
                         _bound(crystal_key, crystal, jti="f", iat_shift=3600)).status_code == 401


def test_a_hop_assertion_is_bound_to_its_subject_token(custody_client, crystal_key):
    c = custody_client
    _p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    other = _bound(crystal_key, crystal, jti="b", digest="0" * 64)
    assert _endpoint_hop(c, crystal, "sage", other).status_code == 401
    unbound = _bound(crystal_key, crystal, jti="u")
    from jose import jwt as jose_jwt
    claims = jose_jwt.get_unverified_claims(unbound)
    assert claims["subject_digest"]


# -- low: a targeted invite is claimed only on an address that was proven ------------------------

from origin.tests.test_the_thirteenth_review_s_session_cases import (  # noqa: E402,F401
    _invite as _invite13, _own as _own13, _token_of, mail, people)


def test_a_password_account_made_with_verification_off_cannot_claim_its_address_s_invite(
        custody_client, people, mail, monkeypatch):
    """Where the plane does not ask for verification, a password sign-up proves nothing about its
    address, so the address is not recorded as verified and an invite targeted at it is refused."""
    from origin import config
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.tests import operator_console_fixtures as oc

    c = custody_client
    monkeypatch.setattr(config, "EMAIL_VERIFICATION_ENABLED", False, raising=False)
    r = c.post("/auth/password/register", json={"username": "squat", "email": "carol@team.test",
                                                "password": "a-long-password-1", "name": "Sq"})
    assert r.status_code in (200, 201), r.text
    with SessionLocal() as db:
        squat = db_persons.get_by_email(db, "carol@team.test")
        sid, verified = str(squat.id), bool(squat.email_verified)
    assert verified is False
    alice = people["alice"]
    _own13(c, alice)
    af.ok(_invite13(c, alice, "carol@team.test"))
    c.cookies.clear()
    oc.origin_page_session(c, sid)
    r = c.post("/auth/me/authority/claim", json={"token": _token_of(mail[0][1])},
               headers={"Origin": config.APP_URI or config.ORIGIN_URI, "X-Origin-Session": "1"})
    assert r.status_code == 403, r.text
