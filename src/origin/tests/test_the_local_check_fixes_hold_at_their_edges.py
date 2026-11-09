"""The edges of the local-check fixes (the review of that round, 2026-11-08).

* The web app's token for Mantle names the person the web app signed in: `mantle-token` takes
  `expect_sub` and answers 409 when the browser's Origin session is someone else's.
* Mantle's origin is never a redirect base on a loopback install, however loopback is spelled.
* Mantle's origin is never an SSO return or the app's address, from any setting.
* Deactivating a person ends their Origin sessions, and no session route serves them.
* A job grant's confirm page names its expiry and its collections, or no step-up is started.
* Only a grantee of the item itself is named; a person's display name is never their address's
  local part; and a grant to a person Origin does not know is refused.
* Origin refuses to start on https when the web app's origin is Origin's own.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_the_thirteenth_review_s_session_cases as _thirteenth
from origin.tests.test_the_ninth_review_s_job_grant_cases import PATH as JOB_PATH, _days
from origin.tests.test_the_thirteenth_review_s_session_cases import BASE, _as, _hdr, _own, _seen

custody_client = _thirteenth.custody_client
people = _thirteenth.people


# -- MEDIUM: the token for Mantle names the person the web app signed in ---------------------------

def _mantle_token(c, body):
    return c.post(f"{BASE}/mantle-token", json=body, headers=_hdr())


def test_mantle_token_refuses_when_the_session_is_another_person_s(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _as(c, bob[0])                                   # the browser's session is Bob's
    r = _mantle_token(c, {"expect_sub": alice[0]})   # the web app has Alice signed in
    assert r.status_code == 409, r.text
    ok = _mantle_token(c, {"expect_sub": bob[0]})
    assert ok.status_code == 200, ok.text


# -- LOW 1: loopback spellings of Mantle's origin -----------------------------------------------

@pytest.mark.parametrize("mantle,uri", [
    ("http://localhost:8082", "http://127.0.0.1:8082/cb"),
    ("http://localhost:8082", "http://[::1]:8082/cb"),
    ("http://127.0.0.1:8082", "http://localhost:8082/cb"),
    ("http://[::1]:8082", "http://127.0.0.1:8082/cb"),
])
@pytest.mark.parametrize("platform", [True, False])
def test_mantle_s_loopback_origin_is_refused_however_spelled(monkeypatch, mantle, uri, platform):
    """Mantle's loopback origin is refused however spelled, even when listed: for a first-party
    client, whose list is exact (the URI and another port both named), and for a registered one,
    whose loopback entries admit any port (RFC 8252 §7.3)."""
    from origin import config
    from origin.services.auth_service import (is_client_redirect_allowed,
                                              is_registered_redirect_allowed)

    registered = ["http://127.0.0.1/cb", "http://localhost/cb", "http://[::1]/cb"]
    first_party = [uri, "http://127.0.0.1:8083/cb"]
    monkeypatch.setattr(config, "MANTLE_URI", mantle, raising=False)
    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {"platform": first_party}, raising=False)

    def allowed(u):
        return (is_client_redirect_allowed(u, client_id="platform") if platform
                else is_registered_redirect_allowed(u, registered))

    assert allowed(uri) is False
    assert allowed("http://127.0.0.1:8083/cb")


# -- LOW 2: Mantle is never an SSO return or the app -----------------------------------------------

def test_mantle_s_origin_is_never_published_as_a_return(monkeypatch):
    from origin import config
    from origin.routers import auth_router

    monkeypatch.setattr(config, "MANTLE_URI", "https://mantle.agience.ai", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://MANTLE.agience.ai.", raising=False)
    monkeypatch.setattr(config, "SSO_RETURN_URIS",
                        ["https://mantle.agience.ai:443/", "https://sp.agience.ai/cb"],
                        raising=False)
    assert auth_router._app_uri() is None
    assert auth_router._sso_return_uris() == ["https://sp.agience.ai/cb"]


# -- LOW 3: deactivation ends Origin sessions --------------------------------------------------

def test_deactivating_a_person_ends_their_origin_sessions(custody_client, people):
    from origin.db.session import SessionLocal
    from origin.services import person_service

    c = custody_client
    alice = people["alice"]
    _as(c, alice[0])
    assert _mantle_token(c, {}).status_code == 200
    with SessionLocal() as db:
        person_service.deactivate(db, alice[0], "test")
        db.commit()
    from origin.models.origin_session import OriginSession
    with SessionLocal() as db:
        live = (db.query(OriginSession).filter(OriginSession.person_id == alice[0],
                                               OriginSession.revoked_time.is_(None)).count())
    assert live == 0
    assert _mantle_token(c, {}).status_code == 401


def test_a_session_route_refuses_a_deactivated_person_whose_session_survives(custody_client,
                                                                              people):
    from origin.db.session import SessionLocal
    from origin.models.person import Person

    c = custody_client
    bob = people["bob"]
    _as(c, bob[0])
    with SessionLocal() as db:              # deactivated by hand, the session row left as it was
        db.get(Person, uuid.UUID(bob[0])).deactivated_at = __import__("datetime").datetime.now()
        db.commit()
    for path, body in (("/mantle-token", {}), ("/narrow", {"audience": "ember"}),
                       ("/preview", {"resource_id": "W"})):
        r = c.post(f"{BASE}{path}", json=body, headers=_hdr())
        assert r.status_code in (401, 403), (path, r.status_code, r.text)


# -- LOW 4: the job grant's confirm page fits ------------------------------------------------------

def _job_options(c, who, body: dict):
    raw = json.dumps(body).encode()
    oc.origin_page_session(c, who[0])
    return c.post("/auth/me/step-up-options",
                  json={"method": "POST", "path": JOB_PATH,
                        "body_sha256": hashlib.sha256(raw).hexdigest(), "body": raw.decode()},
                  headers={"Authorization": f"Bearer {who[1]}"})


def _identity(person_id):
    from origin.db import person_identities as db_identities
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        db_identities.add(db, person_id=person_id, method="oidc", provider="local",
                          subject=str(person_id), verified=True)
        db.commit()


def test_many_collections_are_counted_and_the_expiry_is_kept(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _identity(alice[0])
    until = _days(7)
    cols = [f"collection-{i:03d}-{uuid.uuid4()}" for i in range(12)]
    r = _job_options(c, alice, {"job": "platform.reindex", "expires_at": until,
                                "collections": cols})
    assert r.status_code == 200, r.text
    page = c.get("/auth/reauth/start", params={"ticket": r.json()["ticket"]}).text
    action = page.split("<strong>")[1].split("</strong>")[0]
    assert until in action and cols[0] in action
    assert "more" in action and cols[-1] not in action


def test_a_job_grant_too_long_to_name_starts_no_step_up(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _identity(alice[0])
    r = _job_options(c, alice, {"job": "j" * 300, "expires_at": _days(7)})
    assert r.status_code == 400, r.text


# -- LOW 5: names ------------------------------------------------------------------------------

def test_only_a_grantee_of_the_item_itself_is_named(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice, "P")
    af.ok(af.submit(c, alice[1], af.edge("P", "K"), batch="own", via_session=False))
    af.ok(af.submit(c, alice[1], af.grant("g-K-own", alice[0], "K", _thirteenth.ALL),
                    batch="own", via_session=False))
    _as(c, alice[0])
    made = c.post(f"{BASE}/grants", json={"resource_id": "P", "grantee_id": bob[0],
                                          "actions": ["read"], "preview": _seen(c, "P")},
                  headers=_hdr())
    assert made.status_code == 200, made.text
    shown = c.post(f"{BASE}/preview", json={"resource_id": "K"}, headers=_hdr()).json()
    on_parent = [g for g in shown["grantees"] if g["resource_id"] == "P"]
    assert on_parent and all("grantee_name" not in g for g in on_parent)
    on_item = [g for g in shown["grantees"] if g["resource_id"] == "K"]
    assert on_item and all(g.get("grantee_name") == "alice" for g in on_item)


def test_a_new_account_s_name_is_not_its_address(custody_client, monkeypatch):
    from origin.tests.conftest import PKCE
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal

    monkeypatch.setattr("origin.routers.auth_router.email_verification_required",
                        lambda *_a, **_k: False)
    c = custody_client
    c.cookies.clear()
    from origin import config
    page = c.get("/auth/authorize", params={
        "response_type": "code", "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "redirect_uri": f"{config.ORIGIN_URI.rstrip('/')}/", "provider": "local", **PKCE})
    assert page.status_code == 200, page.text[:300]
    state = page.text.split('data-state="')[1].split('"')[0]
    reg = c.post("/auth/authorize/register", json={"oauth_state": state,
                                                    "email": "quietname@example.test",
                                                    "password": "a-long-enough-password-1"})
    assert reg.status_code == 200, reg.text
    with SessionLocal() as db:
        assert (db_persons.get_by_email(db, "quietname@example.test").name or "") == ""


def test_a_grant_to_a_person_origin_does_not_know_is_refused(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    _as(c, alice[0])
    r = c.post(f"{BASE}/grants", json={"resource_id": "W", "grantee_id": str(uuid.uuid4()),
                                       "actions": ["read"], "preview": _seen(c, "W")},
               headers=_hdr())
    assert r.status_code in (400, 403, 404), r.text


# -- INFO: the web app is never Origin's own origin on https --------------------------------------

@pytest.mark.parametrize("app,origin,issuer,refused", [
    ("https://origin.agience.ai", "https://origin.agience.ai", "https://origin.agience.ai", True),
    ("https://agience.ai", "https://origin.agience.ai", "https://agience.ai", True),
    ("https://my.agience.ai", "https://origin.agience.ai", "https://origin.agience.ai", False),
    ("http://localhost:8080", "http://localhost:8080", "http://localhost:8080", False),
])
def test_origin_refuses_to_start_on_https_with_the_app_at_its_own_origin(monkeypatch, app, origin,
                                                                         issuer, refused):
    from origin import config
    from origin.main import _refuse_app_at_origin_s_own_origin

    monkeypatch.setattr(config, "APP_URI", app, raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", origin, raising=False)
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", issuer, raising=False)
    if refused:
        with pytest.raises(RuntimeError):
            _refuse_app_at_origin_s_own_origin()
    else:
        _refuse_app_at_origin_s_own_origin()
