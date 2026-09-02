"""Origin serves the account surface: `/` answers what the request actually is, not a screen
chosen in advance — a session routes to the account page, no session routes to the sign-in form.

The login form is served here rather than by another host: a credential form served elsewhere
and posting to origin would be a cross-origin flow — CORS, and a session cookie browsers
increasingly drop as third-party. Served here it is same-origin: the thing that verifies the
password is the thing that served the form and sets the session.

A signed-in user shown the sign-in page looks exactly like "not signed in yet" — nothing about
the rendering distinguishes the two — so the branch is asserted in both directions below.
"""
from __future__ import annotations

from origin.main import account_or_signin, login_page, _WEB_DIR


class _Req:
    """The one thing the decision reads."""

    def __init__(self, session):
        self.session = session


def _served(resp) -> str:
    return str(getattr(resp, "path", "")).replace("\\", "/").rsplit("/", 1)[-1]


def test_the_pages_this_surface_serves_actually_exist():
    """The positive control. Every assertion below compares filenames; if neither file were on disk
    they would still compare equal and prove nothing."""
    assert (_WEB_DIR / "index.html").is_file()
    assert (_WEB_DIR / "account.html").is_file()


def test_no_session_gets_the_SIGN_IN_page():
    assert _served(account_or_signin(_Req({}))) == "index.html"
    assert _served(account_or_signin(_Req(None))) == "index.html"


def test_a_session_gets_the_ACCOUNT_page():
    """The half that cannot be seen by looking: without this, a signed-in user is handed the login
    form forever and it reads as an ordinary logged-out visit."""
    assert _served(account_or_signin(_Req({"user_id": "u-1"}))) == "account.html"
    assert _served(account_or_signin(_Req({"sub": "u-1"}))) == "account.html"


def test_an_EMPTY_claim_is_not_a_session():
    """Fails if `{"user_id": ""}` reads as signed in — a key that exists and says nothing.
    Presence is not identity."""
    assert _served(account_or_signin(_Req({"user_id": ""}))) == "index.html"
    assert _served(account_or_signin(_Req({"sub": None}))) == "index.html"


def test_login_is_ALWAYS_the_form_whatever_the_session_says():
    """`/login` is a named address for the form. Redirecting it to the account page when a session
    exists would make signing in as someone else impossible."""
    assert _served(login_page()) == "index.html"


# ── End to end: through SessionMiddleware, with a real signed cookie ─────────────────────────────
#
# The unit assertions above call the handler directly with a plain dict, so they prove the branch
# and nothing about whether a browser's cookie ever becomes that dict. Between them sits
# `SessionMiddleware` — signing, `max_age`, the cookie name — and a signed-in user handed the
# sign-in page looks exactly like an ordinary logged-out visit, so a break there is silent.

def _signed_session(payload: dict) -> str:
    """A cookie starlette's own middleware will accept: base64(json) signed by the app's secret.

    The secret is taken from the running app, not re-derived. `_read_session_secret()` mints an
    ephemeral random key when the secret file is absent, which is the case in a checkout, so
    calling it again returns a different key — a cookie signed with that key does not verify
    against the app's own secret and looks tampered. Reading the secret off the middleware signs
    with whatever the app actually uses.
    """
    import base64
    import json

    import itsdangerous

    from origin.main import app

    secret = None
    for m in app.user_middleware:
        opts = getattr(m, "options", None) or getattr(m, "kwargs", None) or {}
        if "secret_key" in opts:
            secret = opts["secret_key"]
            break
    assert secret is not None, "no SessionMiddleware on the app - this test would prove nothing"

    data = base64.b64encode(json.dumps(payload).encode("utf-8"))
    return itsdangerous.TimestampSigner(str(secret)).sign(data).decode("utf-8")


def _client():
    from fastapi.testclient import TestClient

    from origin.main import app

    return TestClient(app)


def test_a_browser_with_NO_cookie_is_served_the_sign_in_page():
    r = _client().get("/")
    assert r.status_code == 200
    assert "<title>Sign in \u00b7 Agience</title>" in r.text


def test_a_browser_WITH_a_session_cookie_is_served_the_ACCOUNT_page():
    """The test that proves the deployment: everything between the cookie and the branch \u2014
    signing, decoding, the cookie name \u2014 is exercised here and nowhere else."""
    c = _client()
    c.cookies.set("session", _signed_session({"user_id": "u-1"}))
    r = c.get("/")
    assert r.status_code == 200
    assert "<title>Account \u00b7 Agience</title>" in r.text, "a signed-in browser got the sign-in page"


def test_a_TAMPERED_cookie_is_not_a_session():
    """Fails if an unsigned or edited cookie reads as identity. The middleware rejects it, and the
    rejection lands on the sign-in page rather than an error."""
    c = _client()
    c.cookies.set("session", _signed_session({"user_id": "u-1"})[:-4] + "AAAA")
    r = c.get("/")
    assert r.status_code == 200
    assert "<title>Sign in \u00b7 Agience</title>" in r.text


def test_login_is_the_form_even_WITH_a_session():
    c = _client()
    c.cookies.set("session", _signed_session({"user_id": "u-1"}))
    assert "<title>Sign in \u00b7 Agience</title>" in c.get("/login").text
