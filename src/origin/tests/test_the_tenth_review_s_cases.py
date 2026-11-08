"""Review 10's Origin cases (2026-11-02).

Ember under custody (John): Origin takes Ember's narrowed delegation as an acting credential for
its scoped acts only, and never to release a content key.
  ember:memory  the root and creation grant of the person's own memory collection, a creation edge
                from it to a member made in the same batch, that member's creation grant, the
                collection's first key share and its first drop key;
  ember:share   one Read grant, on a single artifact, to a person, expiring within
                `EMBER_SHARE_MAX_DAYS`, where the person may give it (Share or Admin);
  ember:read    a reach verdict.
  ember:share is issued only when the exchange asks for it.
Info  Origin's own routes refuse a narrowed delegation, except the ones that list it.
R4    A job grant over a collection needs Read on it as well as Admin; the operator's, the
      platform principal's Read and Admin.
R5    Sign-out and sign-out-everywhere end access tokens at Origin (a per-person not-before);
      sign-out-everywhere also ends legacy refresh tokens.
R6    A used refresh token presented again revokes its family: there is no grace.
R10   The link flow: a per-attempt state bound to the Origin session and to the code's PKCE.
Signing-key rollover: the next key is minted, accepted by the operator, published beside the old,
and every session and refresh family ends.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_the_eighth_review_s_sign_in_cases import _exchange, _refresh, _signed_in

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]
EMBER = {"ember": ["ember:memory", "ember:share", "ember:read"]}


def _memory_id(person):
    from origin.services import authority_ledger
    return authority_ledger.memory_collection_id(person)


def _ember(c, monkeypatch, token, scope=None):
    from origin import config
    monkeypatch.setattr(config, "NARROW_AUDIENCES", EMBER, raising=False)
    r = _exchange(c, token, "ember", scope)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _scopes(tok):
    return set((jose_jwt.get_unverified_claims(tok).get("scope") or "").split())


def _later(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# -- token exchange: ember:share is opt-in --------------------------------------------------------

def test_ember_share_is_never_issued(custody_client, monkeypatch):
    """Review 10 issued `ember:share` when asked. John removed Ember's share (2026-11-02):
    sharing happens only in the person's own session, so no exchange issues it."""
    c = custody_client
    _a, tok = af.person("Ada")
    assert _scopes(_ember(c, monkeypatch, tok)) == {"ember:memory", "ember:read"}
    assert _exchange(c, tok, "ember", "ember:share").status_code == 400


# -- ember:memory ---------------------------------------------------------------------------------

def _memory(c, ada, tok, batch="m"):
    """The person's memory collection, made on their own token (at sign-in); Ember makes none
    (review 11)."""
    mid = _memory_id(ada)
    af.ok(af.submit(c, tok, af.root(mid), batch=batch))
    af.ok(af.submit(c, tok, af.grant(f"g-{mid}", ada, mid, ALL), batch=batch))
    return mid


def test_ember_creates_the_person_s_memory_collection_and_a_member_in_it(custody_client,
                                                                        monkeypatch):
    c = custody_client
    ada, tok = af.person("Ada")
    e = _ember(c, monkeypatch, tok)
    mid = _memory(c, ada, tok)
    member = f"mem-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, e, af.edge(mid, member), batch="n"))
    af.ok(af.submit(c, e, af.grant(f"g-{member}", ada, member, ["read", "update", "delete"]),
                    batch="n"))


def test_ember_memory_reaches_nothing_but_the_memory_collection(custody_client, monkeypatch):
    c = custody_client
    ada, tok = af.person("Ada")
    e = _ember(c, monkeypatch, tok)
    other = f"col-{uuid.uuid4().hex[:8]}"
    assert af.submit(c, e, af.root(other), batch=None).status_code == 403
    af.ok(af.submit(c, tok, af.root(other), batch="own"))
    af.ok(af.submit(c, tok, af.grant(f"g-{other}", ada, other, ALL), batch="own"))
    assert af.submit(c, e, af.edge(other, f"x-{uuid.uuid4().hex[:6]}"),
                     batch=None).status_code == 403                    # Ada's Admin, not Ember's
    assert af.submit(c, e, af.grant("g-bob", str(uuid.uuid4()), other, ["read"],
                                    expires_at=_later(1)), batch=None).status_code == 403


def test_ember_never_releases_a_content_key(custody_client, monkeypatch):
    c = custody_client
    ada, tok = af.person("Ada")
    e = _ember(c, monkeypatch, tok)
    mid = _memory(c, ada, tok)
    assert af.store_share(c, f"ck:{mid}", credential=e).status_code == 403   # stores no share
    assert af.store_share(c, f"ck:{mid}", credential=tok).status_code == 200  # Ada's first share
    assert af.release(c, f"ck:{mid}", tok, collection=mid).status_code == 200  # Ada herself
    r = af.release(c, f"ck:{mid}", e, collection=mid)
    assert r.status_code == 403 and '"y"' not in r.text
    assert af.release(c, ada, e).status_code == 403                          # her master key
    assert af.store_share(c, f"ck:{mid}", credential=e,
                          y=_shares.OTHER_Y).status_code == 403               # no replacement


# -- ember:share ----------------------------------------------------------------------------------

def _a_member(c, ada, tok):
    col = f"col-{uuid.uuid4().hex[:8]}"
    member = f"art-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, tok, af.root(col), batch="c"))
    af.ok(af.submit(c, tok, af.grant(f"g-{col}", ada, col, ALL), batch="c"))
    af.ok(af.submit(c, tok, af.edge(col, member), batch="c2"))
    return col, member


def test_ember_shares_nothing_at_all(custody_client, monkeypatch):
    """John, 2026-11-02 (review 11): Ember's share is removed. Sharing is the person's own act,
    in their own session; an Ember delegation makes no grant, whatever it is asked."""
    c = custody_client
    ada, tok = af.person("Ada")
    bob, _ = af.person("Bob")
    col, member = _a_member(c, ada, tok)
    e = _ember(c, monkeypatch, tok)
    for why, entry in {
        "one artifact to a person": af.grant("g-s1", bob, member, ["read"], expires_at=_later(1)),
        "a collection": af.grant("g-s2", bob, col, ["read"], expires_at=_later(1)),
        "public": af.grant("g-s3", "public", member, ["read"], expires_at=_later(1)),
        "an invite": af.invite("g-s4", "tok", member, ["read"], expires_at=_later(1)),
    }.items():
        r = af.submit(c, e, entry, batch=None)
        assert r.status_code == 403, (why, r.text)


# -- ember:read: verdicts only --------------------------------------------------------------------

def test_ember_gets_a_reach_verdict(custody_client, monkeypatch):
    c = custody_client
    ada, tok = af.person("Ada")
    col, member = _a_member(c, ada, tok)
    e = _ember(c, monkeypatch, tok)
    path = "/internal/authority/reach"
    t = _shares._token("GET", "-", htu=path, resource_id=member, action="read")
    r = c.get(path, params={"resource_id": member, "action": "read"},
              headers={"Authorization": f"Bearer {t}", "X-Acting-Credential": e})
    assert r.status_code == 200 and r.json() == {"allowed": True}, r.text


# -- Origin's own routes refuse a narrowed delegation ---------------------------------------------

def test_a_narrowed_delegation_opens_only_the_routes_that_list_it(custody_client, monkeypatch):
    c = custody_client
    _a, tok = af.person("Ada")
    e = _ember(c, monkeypatch, tok)
    h = {"Authorization": f"Bearer {e}"}
    assert c.get("/auth/userinfo", headers=h).status_code == 200
    assert c.get("/auth/me/preferences", headers=h).status_code == 401
    assert c.get("/auth/me/job-grants", headers=h).status_code == 401


# -- R4 -------------------------------------------------------------------------------------------

def test_a_job_grant_over_a_collection_needs_read_as_well_as_admin(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger

    c = custody_client
    ada, tok = af.person("Ada")
    bob, _ = af.person("Bob")
    col = f"col-{uuid.uuid4().hex[:8]}"
    af.ok(af.submit(c, tok, af.root(col), batch="c"))
    af.ok(af.submit(c, tok, af.grant(f"g-{col}", ada, col, ALL), batch="c"))
    af.ok(af.submit(c, tok, af.grant("g-bob-admin", bob, col, ["admin"]), batch="c2"))
    with SessionLocal() as db:
        assert not authority_ledger._job_scope(authority_ledger.reach(db), bob, f"ck:{col}",
                                               [col])                     # Admin, no Read
    af.ok(af.submit(c, tok, af.grant("g-bob-read", bob, col, ["read"]), batch="c3"))
    with SessionLocal() as db:
        assert authority_ledger._job_scope(authority_ledger.reach(db), bob, f"ck:{col}", [col])


# -- R5 -------------------------------------------------------------------------------------------

def test_sign_out_everywhere_ends_the_access_token_as_an_acting_credential(custody_client):
    import pytest
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    c = custody_client
    _p, tok = af.person("Sam")
    assert c.post("/auth/sign-out-everywhere",
                  headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    with SessionLocal() as db, pytest.raises(share_credentials.CredentialRefused):
        share_credentials.verify_share_credential(db, tok)
    assert c.get("/auth/userinfo", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_sign_out_everywhere_ends_a_legacy_refresh_token(custody_client):
    from origin.services.auth_service import create_jwt_token

    c = custody_client
    p, tok = af.person("Lee")
    legacy = create_jwt_token({"sub": p, "token_type": "refresh", "client_id": "platform",
                               "aud": "platform"})
    assert c.post("/auth/sign-out-everywhere",
                  headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert _refresh(c, legacy).status_code == 400


def test_sign_out_ends_access_tokens_and_leaves_other_families(custody_client):
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services import refresh_tokens
    from origin.services.auth_service import person_token_claims

    c = custody_client
    p, rt = _signed_in(c)
    with SessionLocal() as db:
        other = refresh_tokens.issue(db, person_token_claims(db_persons.get_by_id(db, p),
                                                             client_id="platform"))
        access = __import__("origin.services.auth_service", fromlist=["x"]).create_jwt_token(
            {"sub": p, "email": "r@x.test", "name": "R", "client_id": "platform",
             "aud": __import__("origin.config", fromlist=["x"]).AUTHORITY_ISSUER})
        db.commit()
    assert c.post("/auth/sign-out", data={"refresh_token": rt}).status_code == 200
    assert c.get("/auth/userinfo", headers={"Authorization": f"Bearer {access}"}).status_code \
        == 401
    nxt = _refresh(c, other)
    assert nxt.status_code == 200
    assert c.get("/auth/userinfo", headers={
        "Authorization": f"Bearer {nxt.json()['access_token']}"}).status_code == 200


def test_legacy_refresh_tokens_end_on_production_with_no_cut_off(custody_client, monkeypatch):
    from origin import config
    from origin.services.auth_service import create_jwt_token

    c = custody_client
    p, _rt = _signed_in(c)
    monkeypatch.setattr(config, "REFRESH_LEGACY_CUTOFF", "", raising=False)
    monkeypatch.setenv("AGIENCE_PLANE", "production")
    legacy = create_jwt_token({"sub": p, "token_type": "refresh", "client_id": "platform",
                               "aud": "platform"})
    assert _refresh(c, legacy).status_code == 400


# -- R6 -------------------------------------------------------------------------------------------

def test_a_replayed_refresh_token_revokes_the_family_at_once(custody_client):
    c = custody_client
    _p, rt = _signed_in(c)
    legit = _refresh(c, rt)
    assert legit.status_code == 200
    assert _refresh(c, rt).status_code == 400                         # no grace
    assert _refresh(c, legit.json()["refresh_token"]).status_code == 400   # family gone


def test_a_refresh_token_presented_by_another_client_is_refused(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.refresh_token import RefreshToken

    c = custody_client
    _p, rt = _signed_in(c)
    jti = jose_jwt.get_unverified_claims(rt)["jti"]
    with SessionLocal() as db:
        db.get(RefreshToken, jti).client_id = "another-client"
        db.commit()
    assert _refresh(c, rt).status_code == 400


# -- R10 ------------------------------------------------------------------------------------------

def test_a_link_needs_the_attempt_s_state_in_the_session_and_its_pkce(custody_client):
    from origin.tests import test_the_eighth_review_s_sign_in_cases as e8
    from origin.tests import test_a_sign_in_method_changes_only_with_a_fresh_step_up as t

    c = custody_client
    ada, tok = af.person("Ada", email="ada@team.test")
    t._identity(ada, "google", "ada-google")
    e8._session(c, ada)
    verifier = "v" * 43
    challenge = __import__("base64").urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    att = c.post("/auth/me/link-attempts", json={"code_challenge": challenge},
                 headers={"Authorization": f"Bearer {tok}"})
    assert att.status_code == 200, att.text
    state = att.json()["state"]
    code = t._code("google", "ada-work", "ada@work.test")
    from origin.routers import auth_router
    auth_router.authorization_codes[code].update({"code_challenge": challenge,
                                                  "code_challenge_method": "S256"})
    body = {"code": code, "code_verifier": verifier, "redirect_uri": "https://app.test/cb"}
    # No state: refused before any step-up is looked at.
    r = c.post(t.LINK, json=body, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403 and "state" in r.text
    # A state, but a code minted without PKCE.
    bare = t._code("google", "ada-work2", "ada2@work.test")
    r = c.post(t.LINK, json={**body, "code": bare, "state": state},
               headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403 and "PKCE" in r.text
    # Another attempt's challenge: refused.
    other = c.post("/auth/me/link-attempts", json={"code_challenge": "x" * 43},
                   headers={"Authorization": f"Bearer {tok}"}).json()["state"]
    r = c.post(t.LINK, json={**body, "state": other}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403
    # Without the Origin session the attempt is not started at all.
    c.cookies.clear()
    assert c.post("/auth/me/link-attempts", json={"code_challenge": challenge},
                  headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_the_passkey_step_up_names_what_is_linked(custody_client):
    from origin.tests import test_the_eighth_review_s_sign_in_cases as e8
    from origin.tests import operator_console_fixtures as oc
    from origin.tests import test_a_sign_in_method_changes_only_with_a_fresh_step_up as t

    c = custody_client
    ada, tok = af.person("Ada", email="ada@team.test")
    oc.Authenticator().register(ada)
    e8._session(c, ada)
    code = t._code("google", "ada-work", "ada@work.test")
    body = t._link_body(code)
    r = e8._page_options(c, tok, "POST", t.LINK, body)
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "passkey" and "ada@work.test" in r.json()["action"]


def test_the_page_links_only_after_a_confirm():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "web" / "passkey-page.js").read_text("utf-8")
    assert "linkFinish(q.get(\"code\"))" not in js
    assert "confirmLink" in js


# -- the signing key ------------------------------------------------------------------------------

def test_the_signing_key_rolls_over_on_the_operator_s_acceptance(custody_client, tmp_path,
                                                                 monkeypatch):
    """Run on a copy of the keys folder, so the session's own keys are left as they were."""
    import shutil

    from origin.scripts import rotate_signing_key as rot
    from origin.services import signing_keys

    monkeypatch.setattr(signing_keys, "_active_dir", None)
    shutil.copytree(signing_keys.keys_dir(), tmp_path / "keys")
    keys = tmp_path / "keys"
    c = custody_client
    p, rt = _signed_in(c)
    _q, access = af.person("Quinn")
    old_kid = jose_jwt.get_unverified_header(access)["kid"]
    nxt = rot.mint_next(keys)
    assert nxt["kid"] != old_kid and nxt["fingerprint"]
    assert {k["kid"] for k in c.get("/.well-known/jwks.json").json()["keys"]} == {old_kid}
    import pytest
    with pytest.raises(rot.RotationRefused):
        rot.accept("not-the-kid", keys)
    rot.accept(nxt["kid"], keys)
    kids = {k["kid"] for k in c.get("/.well-known/jwks.json").json()["keys"]}
    assert kids == {old_kid, nxt["kid"]}                          # both, until old ones expire
    assert _refresh(c, rt).status_code == 400                     # every family ended
    assert c.get("/auth/userinfo", headers={"Authorization": f"Bearer {access}"}).status_code \
        == 401                                                    # every session ended
    _r, fresh = af.person("Rae")
    assert jose_jwt.get_unverified_header(fresh)["kid"] == nxt["kid"]
    assert c.get("/auth/userinfo", headers={"Authorization": f"Bearer {fresh}"}).status_code \
        == 200
