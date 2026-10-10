"""A person sent here by the app to sign up ends up back in the app, and nobody else's link can
sign them in.

The hosted flow is `my.agience.ai` → `/login?redirect_uri=…&state=…` → create account → verify by
email → the app. The contract, server half:

* A verification link verifies the address it was minted for. It signs the redeeming browser in
  only when that browser presents the nonce the starting browser generated, whose hash the link
  carries (`vnh`). A link forwarded from someone else's mailbox, or opened on another device,
  verifies and mints nothing, so it cannot be used to sign a victim in as the attacker.
* `/auth/providers` publishes `app_uri`, from `APP_URI` / `branding.app_uri` only, and only a bare
  origin that is neither loopback nor Origin itself, so the account page can offer "Continue to
  Agience". It also publishes `sso_return_uris`, the exact https return URIs a signed-in visitor
  is handed back to without a click; every other target gets the sign-in form.
* Both registration endpoints refuse with one sentence for every cause, naming the way forward for
  someone who already has an account.
* A link redeemed a second time says "already verified" — only when the account's current address
  is the one the link was minted for — with `error: already_verified`, and still mints nothing.
* `/auth/email/verify-request` is throttled per (address, client) and, more loosely, per address
  and per client, with the same 200 body whether or not it sent. Its stores never forget a live
  window to make room; full, they refuse.
* The unverified-login 403 carries `error: email_unverified`, and every verification is recorded
  as an event whether or not it signs in.

The page half is asserted behaviourally by `js/app_js.test.cjs` and `js/page_scripts.test.cjs`,
both run through `test_app_js_behaviour.py`.
"""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from origin import config
from origin.db.session import get_db
from origin.main import _WEB_DIR
from origin.routers.auth_router import _email_fingerprint, auth_router
from origin.services import guess_budget

_REFUSED = "Couldn't create that account. If you already have one, sign in or reset your password."
_ALREADY_VERIFIED = "This email is already verified — sign in."


def _anon_client() -> TestClient:
    app = FastAPI()
    app.include_router(auth_router)

    def _override_db():
        yield MagicMock()

    app.dependency_overrides[get_db] = _override_db
    return TestClient(app)


def _person(**overrides):
    base = dict(
        id="person-1", username="alice", email="alice@example.com", name="Alice", picture=None,
        password_hash="HASH", email_verified=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _vnh(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()


# ---------------------------------------------------------------------------
# `app_uri` — where "Continue to Agience" goes when no return is stashed
# ---------------------------------------------------------------------------
class TestAppUri:
    def _providers(self, monkeypatch, *, app, facet="https://origin.agience.ai", facets=(),
                   origin="https://origin.agience.ai", sso=()):
        monkeypatch.setattr(config, "APP_URI", app)
        monkeypatch.setattr(config, "SSO_RETURN_URIS", list(sso))
        monkeypatch.setattr(config, "FACET_URI", facet)
        monkeypatch.setattr(config, "FACET_URIS", list(facets))
        monkeypatch.setattr(config, "ORIGIN_URI", origin)
        monkeypatch.setattr(config, "AUTHORITY_ISSUER", origin, raising=False)
        with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True):
            resp = _anon_client().get("/auth/providers")
        assert resp.status_code == 200
        return resp.json()

    def _app_uri(self, monkeypatch, **kw):
        return self._providers(monkeypatch, **kw)["app_uri"]

    def test_the_configured_app_is_published(self, monkeypatch):
        assert self._app_uri(monkeypatch, app="https://my.agience.ai") == "https://my.agience.ai/"
        assert self._app_uri(monkeypatch, app="https://My.Agience.AI.:443/") == "https://my.agience.ai/"

    @pytest.mark.parametrize("app", [
        "https://my.agience.ai/some/path", "https://my.agience.ai/?x=1", "https://my.agience.ai/#f",
        "https://user:pw@my.agience.ai/",
    ])
    def test_a_value_that_is_more_than_an_origin_is_refused_not_trimmed(self, monkeypatch, app):
        assert self._app_uri(monkeypatch, app=app) is None

    def test_the_production_facet_shape_alone_publishes_nothing(self, monkeypatch):
        """`FACET_URI` is Origin and `FACET_URIS` lists mantle first; neither says which is the
        app, so without `APP_URI` there is no link rather than a link to the wrong front end."""
        assert self._app_uri(
            monkeypatch, app="", facet="https://origin.agience.ai",
            facets=["https://mantle.agience.ai", "https://my.agience.ai"],
        ) is None

    @pytest.mark.parametrize("app", [
        "http://localhost:8080", "http://LOCALHOST.", "http://app.localhost", "http://127.0.0.1:5173",
        "http://127.8.9.10", "http://[::1]:8080", "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/",
        "http://[::]/",
    ])
    def test_loopback_is_refused(self, monkeypatch, app):
        assert self._app_uri(monkeypatch, app=app) is None

    @pytest.mark.parametrize("app", [
        "https://origin.agience.ai", "HTTPS://ORIGIN.AGIENCE.AI.", "https://origin.agience.ai:443/",
    ])
    def test_origin_itself_is_refused_however_spelled(self, monkeypatch, app):
        assert self._app_uri(monkeypatch, app=app) is None

    @pytest.mark.parametrize("app", ["javascript:alert(1)", "//my.agience.ai", "my.agience.ai",
                                     "https://my.agience.ai:99999/"])
    def test_a_value_that_is_not_an_http_url_is_refused(self, monkeypatch, app):
        assert self._app_uri(monkeypatch, app=app) is None


class TestSsoReturnUris:
    """The exact targets silent SSO may hand a token to."""

    def _list(self, monkeypatch, *, app="", sso=()):
        return TestAppUri()._providers(monkeypatch, app=app, sso=sso)["sso_return_uris"]

    def test_the_app_root_is_listed(self, monkeypatch):
        assert self._list(monkeypatch, app="https://my.agience.ai") == ["https://my.agience.ai/"]

    def test_explicit_entries_keep_their_path_and_are_normalised(self, monkeypatch):
        assert self._list(monkeypatch, app="https://my.agience.ai", sso=[
            "https://Lumen.Agience.ai:443/auth/cb", "https://my.agience.ai/",
        ]) == ["https://my.agience.ai/", "https://lumen.agience.ai/auth/cb"]

    @pytest.mark.parametrize("bad", [
        "http://lumen.agience.ai/", "https://lumen.agience.ai/?next=x", "https://lumen.agience.ai/#x",
        "https://u:p@lumen.agience.ai/", "https://localhost/", "https://origin.agience.ai/",
        "not a url",
    ])
    def test_unqualified_entries_are_left_out(self, monkeypatch, bad):
        assert self._list(monkeypatch, sso=[bad]) == []

    def test_nothing_configured_lists_nothing(self, monkeypatch):
        """Unset, silent SSO hands off to nobody: every SP gets the sign-in form."""
        assert self._list(monkeypatch) == []


# ---------------------------------------------------------------------------
# Registration refusal copy — both endpoints
# ---------------------------------------------------------------------------
def test_password_register_refusal_names_the_way_forward():
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.platform_settings.get_int", return_value=12,
    ), patch(
        "origin.routers.auth_router.hash_password", return_value="HASH",
    ), patch(
        "origin.routers.auth_router.person_service.create_user_with_password",
        side_effect=ValueError("Email already registered"),
    ):
        resp = _anon_client().post(
            "/auth/password/register",
            json={"username": "a@example.com", "email": "a@example.com", "password": "p" * 12},
        )
    assert resp.status_code == 400
    assert resp.json()["detail"] == _REFUSED


@pytest.fixture
def db_client(origin_app):
    """A client over the real app whose in-memory SQLite has tables (see
    `test_authorize_local_methods.db_client` for why `create_all` runs inside the context)."""
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _oauth_state(client) -> str:
    verifier = "v" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    page = client.get("/auth/authorize", params={
        "response_type": "code", "client_id": "agience-client",
        "redirect_uri": "http://localhost:8080/cb", "scope": "openid email profile", "state": "st",
        "code_challenge": challenge, "code_challenge_method": "S256",
    }).text
    match = re.search(r'const S = "([^"]+)"', page)
    assert match, "the chooser did not carry an oauth_state"
    return match.group(1)


def test_authorize_register_refuses_a_taken_address_with_the_same_sentence(db_client, monkeypatch):
    """The in-flow registration leg, against a real duplicate rather than a mocked refusal."""
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    with SessionLocal() as db:
        db_persons.create(db, {"email": "taken@example.com", "name": "T", "email_verified": True})
        db.commit()

    r = db_client.post("/auth/authorize/register", json={
        "oauth_state": _oauth_state(db_client),
        "email": "taken@example.com", "password": "a-long-enough-password",
    })
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == _REFUSED


# ---------------------------------------------------------------------------
# Login CSRF: a link signs in only the browser that started the verification
# ---------------------------------------------------------------------------
def _register_and_capture_link(client, email: str, nonce: str) -> str:
    """Register through the real app with verification required; return the mailed token."""
    sent = MagicMock()
    with patch(
        "origin.routers.auth_router.email_verification_required", return_value=True,
    ), patch(
        "origin.routers.auth_router.email_service.send_email_verification", sent,
    ):
        r = client.post("/auth/password/register", json={
            "username": email, "email": email, "password": "a-long-enough-password",
            "verify_nonce": nonce,
        })
    assert r.status_code == 200, r.text
    assert r.json()["verification_required"] is True
    assert sent.call_count == 1, "the verification mail was not queued"
    url = sent.call_args.args[1]
    return parse_qs(urlparse(url).query)["token"][0]


def _is_verified(email: str) -> bool:
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        return bool(db_persons.get_by_email(db, email).email_verified)


def test_a_forwarded_link_verifies_the_attacker_but_signs_the_victim_in_as_nobody(db_client):
    """The attack: register attacker@x from the attacker's browser, mail the victim the link.

    The victim's browser holds no nonce (or its own); redeeming must verify the attacker's address
    and hand the victim's browser no session at all.
    """
    token = _register_and_capture_link(db_client, "attacker@example.com", "attacker-browser-nonce")

    victim = db_client.post("/auth/email/verify-confirm", json={"token": token})
    assert victim.status_code == 200, victim.text
    assert victim.json() == {"password_required": True}, (
        "the victim's browser is told nothing about the account, and cannot confirm it without "
        "the password the attacker chose")
    assert not _is_verified("attacker@example.com")

    # Another device of the person who registered completes it with the password.
    other_device = db_client.post("/auth/email/verify-confirm",
                                  json={"token": token, "password": "a-long-enough-password"})
    assert other_device.json() == {"verified": True}, other_device.text
    assert _is_verified("attacker@example.com")


def test_a_link_presented_with_a_different_nonce_mints_nothing(db_client):
    token = _register_and_capture_link(db_client, "someone@example.com", "the-real-nonce")
    r = db_client.post("/auth/email/verify-confirm",
                       json={"token": token, "verify_nonce": "victims-own-nonce"})
    assert r.status_code == 200
    assert "access_token" not in r.json()


def test_the_starting_browser_with_its_nonce_is_signed_in(db_client):
    """The positive control: without it, "mints nothing" above would pass on a broken endpoint."""
    token = _register_and_capture_link(db_client, "owner@example.com", "owner-browser-nonce")
    r = db_client.post("/auth/email/verify-confirm",
                       json={"token": token, "verify_nonce": "owner-browser-nonce",
                             "password": "a-long-enough-password"})
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]
    assert r.json()["verified"] is True
    assert r.json()["email"] == "owner@example.com"


def test_a_link_minted_without_a_nonce_never_signs_in(db_client):
    token = _register_and_capture_link(db_client, "nononce@example.com", "")
    r = db_client.post("/auth/email/verify-confirm",
                       json={"token": token, "verify_nonce": "anything",
                             "password": "a-long-enough-password"})
    assert r.status_code == 200
    assert "access_token" not in r.json()
    assert _is_verified("nononce@example.com")


def test_the_login_refusal_binds_the_resent_link_to_the_nonce():
    """An unverified sign-in is refused with a fresh link; it carries this browser's nonce hash."""
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email",
        return_value=_person(email_verified=False),
    ), patch(
        "origin.routers.auth_router.verify_password", return_value=True,
    ), patch(
        "origin.routers.auth_router._upgrade_password_hash_if_stale",
    ), patch(
        "origin.routers.auth_router.email_verification_required", return_value=True,
    ), patch(
        "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
    ) as mint, patch(
        "origin.routers.auth_router.email_service.send_email_verification",
    ):
        resp = _anon_client().post("/auth/password/login", json={
            "identifier": "alice@example.com", "password": "ok", "verify_nonce": "n-123",
        })
    assert resp.status_code == 403
    assert mint.call_args.args[0]["vnh"] == _vnh("n-123")


def test_an_oversized_nonce_is_refused():
    resp = _anon_client().post("/auth/email/verify-confirm",
                               json={"token": "t", "verify_nonce": "x" * 129})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# A second redemption of a valid link
# ---------------------------------------------------------------------------
def _confirm(token_evf, current, nonce=""):
    with patch(
        "origin.routers.auth_router.verify_token",
        return_value={"token_type": "email_verify", "sub": "person-1", "evf": token_evf,
                      "vnh": _vnh("n")},
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_id", return_value=current,
    ), patch(
        "origin.routers.auth_router.person_service.set_email_verified",
    ) as setv, patch(
        "origin.routers.auth_router.create_jwt_token", return_value="minted.jwt",
    ) as mint:
        resp = _anon_client().post("/auth/email/verify-confirm",
                                   json={"token": "verify.jwt", "verify_nonce": nonce})
    return resp, setv, mint


def test_a_redeemed_link_says_already_verified_and_still_mints_nothing():
    minted_against = _person(email_verified=False)
    resp, setv, mint = _confirm(_email_fingerprint(minted_against), _person(email_verified=True),
                                nonce="n")
    assert resp.status_code == 400
    assert resp.json()["detail"] == _ALREADY_VERIFIED
    assert resp.json()["error"] == "already_verified"
    setv.assert_not_called()
    mint.assert_not_called()


def test_a_link_for_an_old_address_is_not_told_already_verified():
    """The address moved and the new one is verified: the link proves nothing about this mailbox,
    so it gets the generic refusal, not a statement about the account."""
    old = _person(email="alice@example.com", email_verified=False)
    now = _person(email="alice@newmail.test", email_verified=True)
    resp, setv, mint = _confirm(_email_fingerprint(old), now, nonce="n")
    assert resp.status_code == 400
    assert resp.json()["detail"] != _ALREADY_VERIFIED
    assert "error" not in resp.json()
    setv.assert_not_called()
    mint.assert_not_called()


def test_a_fingerprint_that_matches_no_state_is_not_told_already_verified():
    resp, setv, mint = _confirm("0" * 16, _person(email_verified=True), nonce="n")
    assert resp.status_code == 400
    assert resp.json()["detail"] != _ALREADY_VERIFIED
    setv.assert_not_called()


# ---------------------------------------------------------------------------
# Resend throttle
# ---------------------------------------------------------------------------
def _resend(email, user, client=("203.0.113.7", 5000)):
    app = _anon_client().app
    with patch(
        "origin.routers.auth_router.email_service.is_configured", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email", return_value=user,
    ), patch(
        "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
    ), patch(
        "origin.routers.auth_router.email_service.send_email_verification",
    ) as send:
        resp = TestClient(app, client=client).post(
            "/auth/email/verify-request", json={"email": email})
    return resp, send


def test_resends_stop_at_the_per_client_cap_with_the_same_response():
    cap = guess_budget.mail_send_cap()
    for i in range(cap):
        resp, send = _resend("pending@example.com", _person(email_verified=False))
        assert resp.status_code == 200 and resp.json() == {"sent": True}
        # A positive control: every send under the cap goes out.
        assert send.call_count == 1, f"send {i + 1} of {cap} was not sent"

    resp, send = _resend("pending@example.com", _person(email_verified=False))
    assert resp.status_code == 200
    assert resp.json() == {"sent": True}, "a throttled resend must read exactly like a sent one"
    send.assert_not_called()


def test_a_remote_caller_spending_its_budget_does_not_spend_the_owners():
    """The denial of service a per-address key allowed: an attacker keeping the victim's own
    resend budget empty. The attacker's client is throttled; the owner's is not."""
    for _ in range(guess_budget.mail_send_cap()):
        _resend("victim@example.com", None, client=("198.51.100.1", 1))
    resp, send = _resend("victim@example.com", _person(email="victim@example.com"),
                         client=("198.51.100.1", 1))
    send.assert_not_called()

    resp, send = _resend("victim@example.com", _person(email="victim@example.com"),
                         client=("192.0.2.50", 1))
    assert resp.json() == {"sent": True}
    send.assert_called_once()


def test_mail_to_one_address_is_bounded_across_clients():
    cap = guess_budget.mail_send_address_cap()
    assert cap > guess_budget.mail_send_cap()
    now = datetime.now(timezone.utc)
    for i in range(cap):
        assert not guess_budget.mail_sends_exhausted("inbox@example.com", f"c{i}", now=now)
        guess_budget.record_mail_send("inbox@example.com", f"c{i}", now=now)
    assert guess_budget.mail_sends_exhausted("inbox@example.com", "fresh-client", now=now)


def test_the_resend_budget_is_charged_for_unknown_addresses_too():
    """Counting only addresses with accounts would make the limiter an account oracle."""
    for _ in range(guess_budget.mail_send_cap()):
        _resend("Nobody@Example.com", None)
    assert guess_budget.mail_sends_exhausted("nobody@example.com", "203.0.113.7") is True


def test_the_resend_cap_is_the_otp_code_cap():
    """Two unauthenticated mail senders, one per-client rate."""
    from origin.services import otp_service

    assert guess_budget.mail_send_cap() == otp_service._window_cap()
    assert guess_budget.mail_send_window().total_seconds() == (
        otp_service._ISSUE_WINDOW_MINUTES * 60
    )


def test_one_client_cannot_reach_unbounded_inboxes():
    cap = guess_budget.mail_send_client_cap()
    for i in range(cap):
        resp, send = _resend(f"inbox{i}@example.com", _person(email=f"inbox{i}@example.com"),
                             client=("198.51.100.9", 1))
        assert send.call_count == 1, f"address {i + 1} of {cap} from one client was not sent"
    resp, send = _resend("one-more@example.com", _person(email="one-more@example.com"),
                         client=("198.51.100.9", 1))
    assert resp.json() == {"sent": True}
    send.assert_not_called()


@pytest.mark.parametrize("junk", ["", "no-at-sign", "@example.com", "a@", "a@b@c.com"])
def test_a_malformed_address_is_answered_the_same_and_charges_nothing(junk):
    resp, send = _resend(junk, None)
    assert resp.status_code == 200 and resp.json() == {"sent": True}
    send.assert_not_called()
    assert len(guess_budget._mail_sends) == 0


def test_an_address_on_a_dotless_domain_is_an_address():
    """`admin@localhost` or `user@intranet` holds accounts on a home or intranet node: it is
    charged and sent like any other address, not dropped as junk."""
    resp, send = _resend("user@intranet", _person(email="user@intranet", email_verified=False))
    assert resp.status_code == 200 and resp.json() == {"sent": True}
    assert send.call_count == 1


def test_an_oversized_address_is_refused_before_it_reaches_a_store():
    resp, send = _resend("a" * 250 + "@example.com", None)
    assert resp.status_code == 422
    send.assert_not_called()
    assert len(guess_budget._mail_sends) == 0


@pytest.mark.parametrize("path,body", [
    ("/auth/password/login", {"identifier": "a" * 255, "password": "x"}),
    ("/auth/password/register", {"username": "a" * 255, "password": "p" * 12}),
    ("/auth/password/register", {"username": "u", "email": "a" * 255, "password": "p" * 12}),
])
def test_the_password_bodies_bound_their_identifiers(path, body):
    assert _anon_client().post(path, json=body).status_code == 422


@pytest.mark.parametrize("path,body", [
    ("/auth/otp/request", {"email": "a" * 255}),
    ("/auth/otp/verify", {"email": "a" * 255, "code": "123456"}),
    ("/auth/authorize/otp/request", {"oauth_state": "s", "email": "a" * 255}),
    ("/auth/authorize/otp/verify", {"oauth_state": "s", "email": "a" * 255, "code": "1"}),
    ("/auth/authorize/register", {"oauth_state": "s", "email": "a" * 255, "password": "p" * 12}),
    ("/auth/authorize/password", {"oauth_state": "s", "identifier": "a" * 255, "password": "x"}),
    ("/auth/password/reset-request", {"email": "a" * 255}),
])
def test_the_otp_and_in_flow_bodies_bound_their_addresses(path, body):
    from origin.routers.otp_router import otp_router

    app = _anon_client().app
    app.include_router(otp_router)
    assert TestClient(app).post(path, json=body).status_code == 422


def test_dead_send_windows_make_room_before_a_live_one_is_touched(monkeypatch):
    """A full store drops keys whose window has passed before it evicts any live key, so a live
    exhausted window survives as long as dead ones remain to drop."""
    monkeypatch.setattr(guess_budget, "_MAX_TRACKED_IDENTIFIERS", 30)
    now = datetime.now(timezone.utc)
    stale = now - guess_budget.mail_send_window() - timedelta(seconds=1)
    for i in range(9):
        guess_budget.record_mail_send(f"old{i}@example.com", f"10.0.0.{i}", now=stale)
    for _ in range(guess_budget.mail_send_cap()):
        guess_budget.record_mail_send("victim@example.com", "attacker", now=now)
    assert len(guess_budget._mail_sends) == 30
    assert guess_budget.mail_sends_exhausted("victim@example.com", "attacker", now=now)

    for i in range(9):
        guess_budget.record_mail_send(f"junk{i}@example.com", f"10.1.0.{i}", now=now)

    assert guess_budget.mail_sends_exhausted("victim@example.com", "attacker", now=now), (
        "a live window was evicted while dead ones remained")
    assert len(guess_budget._mail_sends) <= 30


def test_a_filled_store_does_not_black_out_resends(monkeypatch):
    """Filling the store from many clients must not silently stop every resend in the deployment:
    an address and client with no live window of their own still get their mail."""
    monkeypatch.setattr(guess_budget, "_MAX_TRACKED_IDENTIFIERS", 30)
    now = datetime.now(timezone.utc)
    for i in range(300):
        guess_budget.record_mail_send(f"junk{i}@example.com", f"10.0.{i // 250}.{i % 250}",
                                              now=now)
    assert len(guess_budget._mail_sends) == 30
    resp, send = _resend("second@example.com", _person(email="second@example.com"))
    assert resp.json() == {"sent": True}
    send.assert_called_once()


def test_one_ipv6_64_is_one_client():
    """Every address in a /64 is one client; the next /64 is another."""
    cap = guess_budget.mail_send_client_cap()
    for i in range(cap):
        _resend(f"v6-{i}@example.com", None, client=(f"2001:db8:1:2::{i + 1:x}", 1))
    resp, send = _resend("v6-last@example.com", _person(email="v6-last@example.com"),
                         client=("2001:db8:1:2:ffff:ffff:ffff:ffff", 1))
    send.assert_not_called()

    resp, send = _resend("v6-last@example.com", _person(email="v6-last@example.com"),
                         client=("2001:db8:1:3::1", 1))
    send.assert_called_once()


def test_an_ipv4_mapped_address_is_its_ipv4_client():
    assert guess_budget._client_network("::ffff:203.0.113.7") == "203.0.113.7"
    assert guess_budget._client_network("2001:db8::1") == "2001:db8::/64"
    assert guess_budget._client_network("testclient") == "testclient"


def test_the_resend_log_names_the_address_by_hash_only(caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="origin.routers.auth_router"):
        for _ in range(guess_budget.mail_send_cap() + 1):
            _resend("private.person@example.com", _person(email="private.person@example.com"))
    assert caplog.records, "no log lines captured — this check is measuring nothing"
    assert "private.person@example.com" not in caplog.text


# ---------------------------------------------------------------------------
# Password reset mail shares the send budget
# ---------------------------------------------------------------------------
def _reset(email, user, client=("203.0.113.7", 5000)):
    app = _anon_client().app
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.email_service.is_configured", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email", return_value=user,
    ), patch(
        "origin.routers.auth_router.create_jwt_token", return_value="reset.jwt",
    ), patch(
        "origin.routers.auth_router.email_service.send_password_reset",
    ) as send:
        resp = TestClient(app, client=client).post(
            "/auth/password/reset-request", json={"email": email})
    return resp, send


def test_reset_requests_stop_at_the_per_client_cap_with_the_same_response():
    cap = guess_budget.mail_send_cap()
    for i in range(cap):
        resp, send = _reset("owner@example.com", _person(email="owner@example.com"))
        assert resp.json() == {"sent": True}
        assert send.call_count == 1, f"reset {i + 1} of {cap} was not sent"
    resp, send = _reset("owner@example.com", _person(email="owner@example.com"))
    assert resp.status_code == 200 and resp.json() == {"sent": True}
    send.assert_not_called()


def test_resends_and_resets_share_one_budget():
    """Neither endpoint is the cheaper way to fill an inbox: sends through one spend the other's."""
    for _ in range(guess_budget.mail_send_cap()):
        _resend("both@example.com", None)
    resp, send = _reset("both@example.com", _person(email="both@example.com"))
    assert resp.json() == {"sent": True}
    send.assert_not_called()


def test_reset_requests_are_charged_for_unknown_addresses_and_log_no_address(caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="origin.routers.auth_router"):
        for _ in range(guess_budget.mail_send_cap()):
            resp, _ = _reset("Nobody.Here@Example.com", None)
            assert resp.json() == {"sent": True}
    assert guess_budget.mail_sends_exhausted("nobody.here@example.com", "203.0.113.7") is True
    assert caplog.records, "no log lines captured — this check is measuring nothing"
    assert "nobody.here@example.com" not in caplog.text.lower()


@pytest.mark.parametrize("junk", ["", "no-at-sign"])
def test_a_malformed_reset_address_is_answered_the_same_and_charges_nothing(junk):
    resp, send = _reset(junk, None)
    assert resp.status_code == 200 and resp.json() == {"sent": True}
    send.assert_not_called()
    assert len(guess_budget._mail_sends) == 0


# ---------------------------------------------------------------------------
# What the pages rely on from the server
# ---------------------------------------------------------------------------
def test_the_unverified_login_refusal_carries_a_machine_readable_code():
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email",
        return_value=_person(email_verified=False),
    ), patch(
        "origin.routers.auth_router.verify_password", return_value=True,
    ), patch(
        "origin.routers.auth_router._upgrade_password_hash_if_stale",
    ), patch(
        "origin.routers.auth_router.email_verification_required", return_value=True,
    ), patch(
        "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
    ), patch(
        "origin.routers.auth_router.email_service.send_email_verification",
    ):
        resp = _anon_client().post("/auth/password/login",
                                   json={"identifier": "alice@example.com", "password": "ok"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "email_unverified"


def test_a_verification_without_the_nonce_is_still_recorded_and_names_nothing():
    """Another device, or a client that sends no nonce, verifies without signing in; the event is
    recorded all the same, and the address is not returned to a browser that did not start it."""
    minted = _person(email_verified=False, password_hash=None)
    with patch(
        "origin.routers.auth_router.verify_token",
        return_value={"token_type": "email_verify", "sub": "person-1",
                      "evf": _email_fingerprint(minted), "vnh": _vnh("n")},
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_id", return_value=minted,
    ), patch(
        "origin.routers.auth_router.person_service.set_email_verified",
    ), patch(
        "origin.routers.auth_router._compute_roles", return_value=[],
    ), patch(
        "origin.routers.auth_router.person_service.record_person_event",
    ) as record, patch(
        "origin.routers.auth_router.create_jwt_token",
    ) as mint:
        resp = _anon_client().post("/auth/email/verify-confirm", json={"token": "t"})
    assert resp.status_code == 200
    assert resp.json() == {"verified": True}
    mint.assert_not_called()
    record.assert_called_once()
    assert record.call_args.args[1] == "email_verified"


# ---------------------------------------------------------------------------
# The account page. The sign-in and verify pages' behaviour is asserted by running their scripts in
# `js/page_scripts.test.cjs`.
# ---------------------------------------------------------------------------
def test_the_account_page_leads_back_to_the_app_before_offering_a_password_change():
    html = (_WEB_DIR / "account.html").read_text(encoding="utf-8-sig")
    assert 'id="continue"' in html and "Continue to Agience" in html
    assert html.index('id="continue"') < html.index('id="changePw"')
    assert "continueHref()" in html
    assert re.search(r'<button class="link"[^>]*id="changePw"', html), (
        "Change password is a secondary action once Continue is the primary one")



# ---------------------------------------------------------------------------
# Pre-hijack: an account with a password is confirmed only with it
# ---------------------------------------------------------------------------
_PW = "a-long-enough-password"


def _redeem(client, token: str, **extra):
    return client.post("/auth/email/verify-confirm", json={"token": token, **extra})


def _signs_in(client, email: str) -> bool:
    return client.post("/auth/password/login",
                       json={"identifier": email, "password": _PW}).status_code == 200


def test_a_stranger_or_a_scanner_cannot_confirm_an_account_with_a_password(db_client):
    """The attack: register someone else's address with your own password and wait for them to
    click the link. Without that password the click confirms nothing and consumes nothing."""
    token = _register_and_capture_link(db_client, "prehijack@example.com", "registrant-nonce")

    for _ in range(3):  # a scanner, then the stranger, then the scanner again
        assert _redeem(db_client, token).json() == {"password_required": True}
    assert not _is_verified("prehijack@example.com")

    ok = _redeem(db_client, token, password=_PW)
    assert ok.json() == {"verified": True}, "the link must still work for the one who registered"


def test_a_wrong_password_confirms_nothing_and_leaves_the_link_usable(db_client):
    token = _register_and_capture_link(db_client, "wrongpw@example.com", "")

    bad = _redeem(db_client, token, password="not-the-password")
    assert bad.status_code == 401, bad.text
    assert not _is_verified("wrongpw@example.com")

    assert _redeem(db_client, token, password=_PW).json() == {"verified": True}
    assert _signs_in(db_client, "wrongpw@example.com")


def test_the_mailbox_holder_disowns_a_registration_they_did_not_make(db_client):
    """Confirmed as theirs; the registrant's password stops working; nothing is signed in, not
    even in a browser that holds the registration's nonce."""
    token = _register_and_capture_link(db_client, "disowned@example.com", "registrant-nonce")

    r = _redeem(db_client, token, disown=True, verify_nonce="registrant-nonce")

    assert r.json() == {"verified": True, "password_cleared": True}, r.text
    assert _is_verified("disowned@example.com")
    assert not _signs_in(db_client, "disowned@example.com"), "the registrant's password survived"


def test_an_account_without_a_password_confirms_from_the_link_alone(db_client, monkeypatch):
    """Positive control: federated and code-made accounts have no password to ask for."""
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    with SessionLocal() as db:
        db_persons.create(db, {"email": "nopw@example.com", "name": "N", "email_verified": False})
        db.commit()
    sent = MagicMock()
    with patch("origin.routers.auth_router.email_service.send_email_verification", sent):
        db_client.post("/auth/email/verify-request", json={"email": "nopw@example.com"})
    assert sent.call_count == 1
    token = parse_qs(urlparse(sent.call_args.args[1]).query)["token"][0]

    assert _redeem(db_client, token).json() == {"verified": True}
    assert _is_verified("nopw@example.com")


def test_a_disowned_account_sets_a_password_of_its_own_by_mail(db_client, monkeypatch):
    """A disown is not a dead end: the confirmed mailbox sets a first password through reset."""
    from origin.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    token = _register_and_capture_link(db_client, "recover@example.com", "")
    assert _redeem(db_client, token, disown=True).json()["password_cleared"] is True

    sent = MagicMock()
    with patch("origin.routers.auth_router.email_service.send_password_reset", sent):
        db_client.post("/auth/password/reset-request", json={"email": "recover@example.com"})
    assert sent.call_count == 1, "no set-password link was mailed after the disown"
    reset = parse_qs(urlparse(sent.call_args.args[1]).query)["token"][0]

    r = db_client.post("/auth/password/reset-confirm",
                       json={"token": reset, "new_password": "the-owners-own-password"})
    assert r.status_code == 200, r.text
    assert db_client.post("/auth/password/login", json={
        "identifier": "recover@example.com", "password": "the-owners-own-password"}).status_code == 200
    assert db_client.post("/auth/password/reset-confirm", json={
        "token": reset, "new_password": "a-second-use-of-the-link"}).status_code == 400, (
        "the set-password link worked twice")


def test_signing_in_as_the_address_does_not_block_its_confirmation(db_client):
    """Anyone can spend the sign-in budget for any identifier they type, the address or a string
    shaped like an internal key; none of it may refuse the registrant's confirmation."""
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services import guess_budget

    token = _register_and_capture_link(db_client, "blocked@example.com", "")
    with SessionLocal() as db:
        person_id = str(db_persons.get_by_email(db, "blocked@example.com").id)
    for typed in ("blocked@example.com", f"email-confirmation:{person_id}", person_id):
        for _ in range(guess_budget.password_window_cap() + 2):
            db_client.post("/auth/password/login", json={"identifier": typed, "password": "a-guess"})

    assert _redeem(db_client, token, password=_PW).json() == {"verified": True}
