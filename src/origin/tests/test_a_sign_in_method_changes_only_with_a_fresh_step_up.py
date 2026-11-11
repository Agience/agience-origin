"""Linking or unlinking a sign-in method, and registering or deleting a passkey, needs a fresh
step-up at Origin by a method the person already has, bound to that one request.

Mantle holds people's live access tokens. On an access token alone it could post another person's
sign-in code to `/auth/me/link-provider` and leave that identity signing in as the victim after
the token and the compromise are gone; or enrol its own passkey. So an access token is never
enough:

* a person with a passkey steps up with a passkey assertion, with user verification, over a
  single-use challenge bound to the request's method, path and body (`POST /auth/me/step-up-options`,
  then `X-Step-Up`);
* a person with none re-authenticates through a method already theirs, at Origin's own pages
  (`/auth/reauth/start`, the ordinary sign-in, `/auth/reauth/complete`). The completing code is
  minted only by an interactive sign-in and consumed at Origin; Mantle relays nothing and no token
  it holds proves a ticket.

A new sign-in identity whose verified email matches an existing account no longer joins it: that
link is the account's own act, made this way.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

LINK = "/auth/me/link-provider"


def _code(provider, sub, email, redirect="https://app.test/cb"):
    from origin.routers import auth_router

    code = "code-" + hashlib.sha256(f"{provider}{sub}{datetime.now()}".encode()).hexdigest()[:24]
    auth_router.authorization_codes[code] = {
        "user_info": {"provider": provider, "sub": sub, "email": email, "name": "N",
                      "picture": None, "email_verified": True},
        "client_id": "platform", "redirect_uri": redirect, "scope": "openid",
        "code_challenge": None, "code_challenge_method": None,
        "timestamp": datetime.now(timezone.utc)}
    return code


def _options(c, token, method, path, body: bytes):
    r = c.post("/auth/me/step-up-options",
               json={"method": method, "path": path,
                     "body_sha256": hashlib.sha256(body).hexdigest()},
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r.json()


def _passkey_step(c, token, authn, method, path, body: bytes, *, verified=True):
    opts = _options(c, token, method, path, body)
    assert opts["kind"] == "passkey", opts
    step = {"challenge": opts["options"]["challenge"],
            "credential": authn.assertion(opts["options"], verified=verified)}
    return base64.urlsafe_b64encode(json.dumps(step).encode()).rstrip(b"=").decode()


def _send(c, method, path, token, body: bytes, step=None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if step:
        headers["X-Step-Up"] = step
    return c.request(method, path, content=body or None, headers=headers)


def _resolves_to(provider, sub, email):
    from origin.db.session import SessionLocal
    from origin.services import person_service

    with SessionLocal() as db:
        who = person_service.get_user_by_oidc_identity(db, provider, sub)
        return str(who.id) if who else None


def link_redirect():
    """Where Origin's own page sends a sign-in through the method to be linked: `/passkey`."""
    from origin.services import person_step_up
    return person_step_up.link_uri()


def _link_body(code):
    return json.dumps({"code": code, "code_verifier": "x",
                       "redirect_uri": "https://app.test/cb"}).encode()


def _attempted_body(c, token, code, verifier="v" * 43):
    """A link body for an attempt begun on Origin's own page, in the Origin session the client
    already holds (review 10, R10): its state, and the code made with its PKCE challenge."""
    import base64

    from origin.routers import auth_router

    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())         .decode().rstrip("=")
    r = c.post("/auth/me/link-attempts", json={"code_challenge": challenge},
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    from origin import config
    auth_router.authorization_codes[code].update({"code_challenge": challenge,
                                                  "code_challenge_method": "S256",
                                                  "redirect_uri": link_redirect(),
                                                  "client_id": config.PLATFORM_CLIENT_ID})
    return json.dumps({"code": code, "code_verifier": verifier, "state": r.json()["state"],
                       "redirect_uri": link_redirect()}).encode()


# -- an access token alone ----------------------------------------------------------------------

def test_a_live_access_token_cannot_link_another_sign_in(custody_client):
    """The probe: Mal's own Google code, posted on Alice's live token."""
    c = custody_client
    alice, alice_token = af.person("Alice", email="alice@team.test")
    body = _link_body(_code("google", "mal-sub", "mal@evil.test"))
    r = _send(c, "POST", LINK, alice_token, body)
    assert r.status_code == 403, r.text
    assert _resolves_to("google", "mal-sub", "mal@evil.test") != alice


def test_unlinking_needs_a_step_up(custody_client):
    c = custody_client
    _alice, alice_token = af.person("Alice")
    r = _send(c, "DELETE", f"{LINK}/google", alice_token, b"")
    assert r.status_code == 403


# -- with a passkey -----------------------------------------------------------------------------

def _identity(person, provider, subject):
    from origin.db import person_identities as db_identities
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        db_identities.add(db, person_id=person, method="oidc", provider=provider,
                          subject=subject, verified=True)
        db.commit()


def test_a_passkey_step_up_by_the_person_links_and_unlinks(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    _identity(alice, "local", alice)                 # a method to keep when one is removed
    authn = oc.Authenticator().register(alice)
    oc.origin_page_session(c, alice)                 # on Origin's own page (review 8, R1)
    body = _attempted_body(c, alice_token, _code("google", "alice-2nd", "a2@team.test"))
    step = _passkey_step(c, alice_token, authn, "POST", LINK, body)
    r = _send(c, "POST", LINK, alice_token, body, step)
    assert r.status_code == 200, r.text
    assert _resolves_to("google", "alice-2nd", "a2@team.test") == alice
    again = _send(c, "POST", LINK, alice_token, _link_body(_code("google", "x", "x@t.test")), step)
    assert again.status_code == 403                                   # spent, and another body
    step = _passkey_step(c, alice_token, authn, "DELETE", f"{LINK}/google", b"")
    assert _send(c, "DELETE", f"{LINK}/google", alice_token, b"", step).status_code == 200


def test_a_step_up_for_another_request_or_without_verification_is_refused(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    authn = oc.Authenticator().register(alice)
    mine = _link_body(_code("google", "alice-2nd", "a2@team.test"))
    theirs = _link_body(_code("google", "mal-sub", "mal@evil.test"))
    step = _passkey_step(c, alice_token, authn, "POST", LINK, mine)
    assert _send(c, "POST", LINK, alice_token, theirs, step).status_code == 403
    step = _passkey_step(c, alice_token, authn, "POST", LINK, theirs, verified=False)
    assert _send(c, "POST", LINK, alice_token, theirs, step).status_code == 403
    assert _resolves_to("google", "mal-sub", "mal@evil.test") is None


def test_another_person_s_passkey_is_no_step_up(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    mal, mal_token = af.person("Mal")
    oc.Authenticator().register(alice)
    mals = oc.Authenticator().register(mal)
    body = _link_body(_code("google", "mal-sub", "mal@evil.test"))
    step = _passkey_step(c, mal_token, mals, "POST", LINK, body)          # Mal's own step-up
    assert _send(c, "POST", LINK, alice_token, body, step).status_code == 403


def test_a_person_with_a_passkey_cannot_step_up_by_re_authentication(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    oc.Authenticator().register(alice)
    opts = _options(c, alice_token, "POST", LINK, b"{}")
    assert opts["kind"] == "passkey"


# -- passkeys, for ordinary people --------------------------------------------------------------

def test_registering_or_deleting_a_passkey_needs_a_step_up(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    authn = oc.Authenticator().register(alice)
    oc.origin_page_session(c, alice)                 # on Origin's own page (review 8, R1)
    assert _send(c, "POST", "/auth/passkey/register-options", alice_token, b"").status_code == 403
    rid = authn.assertion({"challenge": "AA", "rpId": "x"})["id"]
    path = f"/auth/passkey/credentials/{rid}"
    assert _send(c, "DELETE", path, alice_token, b"").status_code == 403
    step = _passkey_step(c, alice_token, authn, "POST", "/auth/passkey/register-options", b"")
    r = _send(c, "POST", "/auth/passkey/register-options", alice_token, b"", step)
    assert r.status_code == 200, r.text
    step = _passkey_step(c, alice_token, authn, "DELETE", path, b"")
    assert _send(c, "DELETE", path, alice_token, b"", step).status_code == 200


# -- without a passkey: re-authentication at Origin's own pages ---------------------------------

def _reauth(c, token, method, path, body):
    opts = _options(c, token, method, path, body)
    assert opts["kind"] == "reauth", opts
    return opts["ticket"], opts["url"]


def _complete(c, ticket, provider, sub, email):
    from origin import config
    from origin.services import person_step_up

    redirect = person_step_up.complete_uri()
    code = _code(provider, sub, email, redirect=redirect)
    challenge = person_step_up.code_challenge(ticket)
    from origin.routers import auth_router
    auth_router.authorization_codes[code].update(
        {"code_challenge": challenge, "code_challenge_method": "S256",
         "client_id": config.PLATFORM_CLIENT_ID})
    return c.get("/auth/reauth/complete", params={"code": code, "state": ticket})


def _page_reauth(c, token, person, method, path, body):
    """A re-authentication as Origin's own page starts it (review 8, R1): in the person's Origin
    session, the action shown on the start page and confirmed there. Returns the ticket."""
    oc.origin_page_session(c, person)
    r = c.post("/auth/me/step-up-options",
               json={"method": method, "path": path, "body": body.decode() if body else "",
                     "body_sha256": hashlib.sha256(body).hexdigest()},
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["kind"] == "reauth", r.text
    ticket = r.json()["ticket"]
    start = c.get("/auth/reauth/start", params={"ticket": ticket})
    csrf = start.text.split('name="csrf" value="')[1].split('"')[0]
    c.post("/auth/reauth/start", data={"ticket": ticket, "csrf": csrf}, follow_redirects=False)
    return ticket


def _complete_fresh(c, ticket, provider, sub, email):
    from origin.routers import auth_router
    from origin.services import person_step_up

    from origin import config
    code = _code(provider, sub, email, redirect=person_step_up.complete_uri())
    auth_router.authorization_codes[code].update(
        {"code_challenge": person_step_up.code_challenge(ticket), "code_challenge_method": "S256",
         "client_id": config.PLATFORM_CLIENT_ID,
         "auth_time": int(datetime.now(timezone.utc).timestamp())})
    return c.get("/auth/reauth/complete", params={"code": code, "state": ticket})


def test_a_token_alone_starts_no_re_authentication(custody_client):
    """Review 8, R1: what this file's earlier version allowed (a ticket started on Alice's token
    alone, for a body Mantle chose) is refused; the page flow is the only start."""
    c = custody_client
    _alice, alice_token = af.person("Alice", email="alice@team.test")
    body = _link_body(_code("google", "alice-2nd", "a2@team.test"))
    r = c.post("/auth/me/step-up-options",
               json={"method": "POST", "path": LINK,
                     "body_sha256": hashlib.sha256(body).hexdigest()},
               headers={"Authorization": f"Bearer {alice_token}"})
    assert r.status_code == 403


def test_without_a_passkey_the_person_re_authenticates_on_origin_s_page(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice", email="alice@team.test")
    _identity(alice, "google", "alice-google")
    oc.origin_page_session(c, alice)
    body = _attempted_body(c, alice_token, _code("google", "alice-2nd", "a2@team.test"))
    ticket = _page_reauth(c, alice_token, alice, "POST", LINK, body)
    assert _send(c, "POST", LINK, alice_token, body, f"reauth:{ticket}").status_code == 403
    done = _complete_fresh(c, ticket, "google", "alice-google", "alice@team.test")
    assert done.status_code == 200
    # It goes back to the Origin page that asked (BUG-037), by Origin's own script, never inline.
    assert '<script src="/web/reauth-complete.js"></script>' in done.text
    csp = done.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert c.get("/web/reauth-complete.js").status_code == 200
    r = _send(c, "POST", LINK, alice_token, body, f"reauth:{ticket}")
    assert r.status_code == 200, r.text
    assert _send(c, "POST", LINK, alice_token, body, f"reauth:{ticket}").status_code == 403


def test_a_re_authentication_by_someone_else_proves_nothing(custody_client):
    c = custody_client
    alice, alice_token = af.person("Alice")
    af.person("Mal")
    body = _link_body(_code("google", "mal-sub", "mal@evil.test"))
    ticket = _page_reauth(c, alice_token, alice, "POST", LINK, body)
    done = _complete_fresh(c, ticket, "google", "mal-sub", "mal@evil.test")
    assert done.status_code == 403
    assert _send(c, "POST", LINK, alice_token, body, f"reauth:{ticket}").status_code == 403


def test_no_token_proves_a_ticket(custody_client):
    """There is no route that proves a ticket from a token: only a sign-in's code, at Origin."""
    c = custody_client
    alice, alice_token = af.person("Alice")
    ticket = _page_reauth(c, alice_token, alice, "DELETE", f"{LINK}/google", b"")
    r = c.get("/auth/reauth/complete", params={"state": ticket},
              headers={"Authorization": f"Bearer {alice_token}"})
    assert r.status_code in (400, 422)


# -- a sign-in that matches an existing account by email ------------------------------------------

def test_a_new_identity_does_not_join_an_account_by_email(custody_client):
    import pytest

    from origin.db.session import SessionLocal
    from origin.services import person_service

    alice, _token = af.person("Alice", email="alice@team.test")
    with SessionLocal() as db:
        with pytest.raises(person_service.IdentityLinkRefused):
            person_service.get_or_create_user_by_oidc_identity(
                db, oidc_provider="google", oidc_subject="someone", email="alice@team.test",
                name="A", email_verified=True)
        db.rollback()
    assert _resolves_to("google", "someone", "alice@team.test") is None


def test_a_job_grant_s_step_up_goes_straight_to_sign_in(custody_client):
    """BUG-055 (John, 2026-11-10: one ask per decision). A job grant is approved on Origin's own
    page, which names it; its re-authentication goes straight to the sign-in, already confirmed, and
    no start page asks again. A change to how one signs in still shows its start page."""
    c = custody_client
    alice, alice_token = af.person("Alice")
    oc.origin_page_session(c, alice)
    body = json.dumps({"job": "lumen.timer.t-1", "expires_at": "2099-01-01T00:00:00Z", "reach": ["t-1"]}).encode()
    r = c.post("/auth/me/step-up-options",
               json={"method": "POST", "path": "/auth/me/job-grants", "body": body.decode(),
                     "body_sha256": hashlib.sha256(body).hexdigest()},
               headers={"Authorization": f"Bearer {alice_token}"})
    assert r.status_code == 200 and r.json()["kind"] == "reauth", r.text
    assert "/auth/authorize?" in r.json()["url"] and "reauth/start" not in r.json()["url"]
    other = c.post("/auth/me/step-up-options",
                   json={"method": "DELETE", "path": f"{LINK}/google", "body": "",
                         "body_sha256": hashlib.sha256(b"").hexdigest()},
                   headers={"Authorization": f"Bearer {alice_token}"})
    assert other.status_code == 200 and "/auth/reauth/start?" in other.json()["url"]


def test_a_step_up_s_sign_in_asks_only_for_the_password(custody_client):
    """BUG-055 follow-up (2026-11-10): the step-up's sign-in asked for the email again. It names
    the person (OIDC `login_hint`), and Origin's page fills it in and asks for the password."""
    from urllib.parse import parse_qs, urlsplit
    c = custody_client
    alice, alice_token = af.person("Alice")
    oc.origin_page_session(c, alice)
    body = json.dumps({"job": "lumen.timer.t-1", "expires_at": "2099-01-01T00:00:00Z", "reach": ["t-1"]}).encode()
    r = c.post("/auth/me/step-up-options",
               json={"method": "POST", "path": "/auth/me/job-grants", "body": body.decode(),
                     "body_sha256": hashlib.sha256(body).hexdigest()},
               headers={"Authorization": f"Bearer {alice_token}"})
    url = r.json()["url"]
    q = parse_qs(urlsplit(url).query)
    email = q.get("login_hint", [""])[0]
    assert email and "@" in email, url
    page = c.get(urlsplit(url).path + "?" + urlsplit(url).query)
    assert page.status_code == 200 and 'id="identifier"' in page.text, page.status_code
    assert f'value="{email}"' in page.text and "autofocus" in page.text, page.text[:400]
