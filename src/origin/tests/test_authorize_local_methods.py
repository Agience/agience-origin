"""The three sign-in methods on `/auth/authorize` — password, OTP, and federated OIDC — and the
rule that resolves them to one account.

Each gate is paired with the negative control that makes it meaningful: a chooser that renders
every block regardless, or a linking rule that links regardless, would still pass a test that only
checks the happy path. Where a check could silently become a no-op, the test drives the state that
makes it fire.
"""

from __future__ import annotations

import base64
import hashlib

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def db_client(origin_app, monkeypatch):
    """A client whose in-memory SQLite actually has tables.

    `conftest.origin_app` sets `ORIGIN_SKIP_MIGRATIONS=1`, so lifespan never runs alembic and the
    schema does not exist. Creating it from the models is right for these tests — they assert
    router and service behaviour, not migration fidelity — but it must happen after lifespan has
    built the engine, or `create_all` binds a different one and every query hits an empty database
    that looks fine.
    """
    from fastapi.testclient import TestClient

    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _session():
    from origin.db.session import SessionLocal

    return SessionLocal()


def _make_person(*, email, email_verified, password=None, username=None, name="Test Person"):
    """Insert a person directly. Returns its id as a string."""
    from origin.db import persons as db_persons
    from origin.services.auth_service import hash_password

    with _session() as db:
        fields = {"email": email, "name": name, "email_verified": email_verified}
        if username:
            fields["username"] = username
        if password:
            fields["password_hash"] = hash_password(password)
        person = db_persons.create(db, fields)
        db.commit()
        return str(person.id)


def _pkce():
    verifier = "v" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


def _authorize(client, **overrides):
    """Start a flow and return the response. `FACET_URI` defaults to the allowed redirect base."""
    _, challenge = _pkce()
    params = {
        "response_type": "code",
        "client_id": "agience-client",
        "redirect_uri": "http://localhost:8080/cb",
        "scope": "openid email profile",
        "state": "st",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return client.get("/auth/authorize", params=params)


def _oauth_state(client, **overrides):
    """Start a flow and dig the server-generated handle out of the rendered page."""
    import re

    page = _authorize(client, **overrides).text
    match = re.search(r'const S = "([^"]+)"', page)
    assert match, "the chooser did not carry an oauth_state"
    return match.group(1)


@pytest.fixture
def local_only(monkeypatch):
    """A node with password + OTP and no upstream provider — the `origin.home` shape."""
    from origin.services import email_service
    from origin.services.oidc_providers import REGISTERED_PROVIDERS

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    # Restored, not just cleared: `REGISTERED_PROVIDERS` is module state shared by every test in
    # the session, so emptying it and walking away would let this fixture decide what a later
    # test sees.
    saved = dict(REGISTERED_PROVIDERS)
    REGISTERED_PROVIDERS.clear()
    yield
    REGISTERED_PROVIDERS.clear()
    REGISTERED_PROVIDERS.update(saved)


# ---------------------------------------------------------------------------
# The chooser renders what the node HAS — and omits what it does not
# ---------------------------------------------------------------------------
def test_chooser_offers_password_and_otp_when_both_are_available(db_client, local_only):
    page = _authorize(db_client).text
    assert page.startswith("<!doctype html>")
    assert 'id="pwForm"' in page, "no password form"
    assert 'id="sendForm"' in page, "no OTP form"
    assert 'id="otpToggle"' in page, "no way to reach the OTP form from the password form"


def test_the_chooser_uses_the_shared_branded_surface_and_keeps_the_animation(db_client, local_only):
    """The page is one artifact with `web/index.html`, not a second copy of it.

    It references the same stylesheet and background script `web/index.html` uses, rather than
    carrying its own copy, so it cannot drift from the account page it hands off to.
    """
    page = _authorize(db_client).text
    assert '<link rel="stylesheet" href="/web/app.css">' in page
    assert '<script src="/web/bg.js"></script>' in page, "the animated background is missing"
    assert '<div class="bg"></div>' in page, "bg.js has nothing to attach to"
    assert 'src="/web/logo_v.png"' in page

    # It must not pull in `app.js`, which carries `saveToken`/`finishLogin`: a page that cannot
    # save a token cannot leak one.
    assert "/web/app.js" not in page


def test_no_password_form_and_no_endpoint_when_password_is_disabled(db_client, local_only, monkeypatch):
    """The negative control for the password block: absent from the page, not merely hidden, and
    unreachable by URL either."""
    from origin.services.platform_settings_service import settings as platform_settings

    monkeypatch.setattr(
        platform_settings, "get_bool", lambda key, default=True: False if key == "auth.password.enabled" else default
    )
    page = _authorize(db_client).text
    assert 'id="pwForm"' not in page, "a form for a disabled method is a button that fails"
    assert 'id="sendForm"' in page, "OTP should still be offered"

    # The form being gone is not the control — the endpoint being gone is.
    state = _oauth_state(db_client)
    r = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": state, "identifier": "someone@example.com", "password": "x" * 20},
    )
    assert r.status_code == 404, "a disabled method reachable by URL is not disabled"


def test_no_otp_form_when_email_is_unconfigured_and_the_page_still_renders(db_client, monkeypatch):
    """`/authorize` 400s only when there is no sign-in method at all, not merely when email is
    unconfigured. A node with passwords and no mail server has a working sign-in and gets a page.
    """
    from origin.services import email_service
    from origin.services.oidc_providers import REGISTERED_PROVIDERS

    REGISTERED_PROVIDERS.clear()
    monkeypatch.setattr(email_service, "is_configured", lambda: False)

    r = _authorize(db_client)
    assert r.status_code == 200, "a node with passwords was told it had no way to sign anyone in"
    assert 'id="pwForm"' in r.text
    assert 'id="sendForm"' not in r.text


def test_authorize_refuses_only_when_there_is_genuinely_no_method(db_client, monkeypatch):
    from origin.services import email_service
    from origin.services.oidc_providers import REGISTERED_PROVIDERS
    from origin.services.platform_settings_service import settings as platform_settings

    REGISTERED_PROVIDERS.clear()
    monkeypatch.setattr(email_service, "is_configured", lambda: False)
    monkeypatch.setattr(
        platform_settings, "get_bool", lambda key, default=True: False if key == "auth.password.enabled" else default
    )
    r = _authorize(db_client)
    assert r.status_code == 400
    assert "no way to sign anyone in" in r.json()["detail"]


def test_no_provider_button_for_an_unregistered_provider(db_client, local_only):
    """A button for a provider that is not configured is a 400 generator wearing a login button."""
    page = _authorize(db_client).text
    assert "Continue with" not in page
    assert "/auth/authorize/federate" not in page


def test_a_registered_provider_gets_a_button_carrying_only_the_opaque_handle(db_client, monkeypatch):
    """The button carries `oauth_state` and nothing else.

    Putting client_id / redirect_uri / code_challenge back into the page to re-enter `/authorize`
    would work and would discard the property the page is built around: the browser holds a handle
    it cannot edit, and the request stays server-side.
    """
    from origin.services import email_service
    from origin.services.oidc_providers import REGISTERED_PROVIDERS

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    REGISTERED_PROVIDERS.clear()
    REGISTERED_PROVIDERS["google"] = {
        "label": "Google", "type": "oidc",
        "redirect_uri": "http://localhost:8080/auth/callback",
        "issuer": "https://accounts.google.com",
    }
    try:
        page = _authorize(db_client).text
        assert "Continue with Google" in page
        assert "/auth/authorize/federate?oauth_state=" in page
        for leaked in ("code_challenge", "redirect_uri=http", "client_id=agience-client"):
            assert leaked not in page, f"the page leaked {leaked} into the federate link"
    finally:
        REGISTERED_PROVIDERS.clear()


# ---------------------------------------------------------------------------
# `/authorize/federate`
# ---------------------------------------------------------------------------
def test_federate_refuses_an_unknown_provider(db_client, local_only):
    state = _oauth_state(db_client)
    r = db_client.get(
        "/auth/authorize/federate", params={"oauth_state": state, "provider": "nope"}
    )
    assert r.status_code == 400
    assert "Unknown or unconfigured provider" in r.json()["detail"]


def test_federate_refuses_local_as_a_provider_name(db_client, local_only):
    """`local` names Origin authenticating the person itself; it is not an upstream to redirect to."""
    state = _oauth_state(db_client)
    r = db_client.get(
        "/auth/authorize/federate", params={"oauth_state": state, "provider": "local"}
    )
    assert r.status_code == 400


def test_federate_refuses_an_unknown_state(db_client, local_only):
    r = db_client.get(
        "/auth/authorize/federate", params={"oauth_state": "not-a-real-handle", "provider": "google"}
    )
    assert r.status_code == 400
    assert "expired" in r.json()["detail"]


# ---------------------------------------------------------------------------
# The password leg
# ---------------------------------------------------------------------------
def test_password_sign_in_returns_a_redirect_carrying_a_code(db_client, local_only):
    _make_person(email="pw@example.com", email_verified=True, password="correct-horse-battery")
    state = _oauth_state(db_client)
    r = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": state, "identifier": "pw@example.com", "password": "correct-horse-battery"},
    )
    assert r.status_code == 200, r.text
    assert "code=" in r.json()["redirect"]
    assert r.json()["redirect"].startswith("http://localhost:8080/cb?")


def test_password_sign_in_works_by_username_too(db_client, local_only):
    _make_person(
        email="uname@example.com", email_verified=True, password="correct-horse-battery", username="johnny"
    )
    state = _oauth_state(db_client)
    r = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": state, "identifier": "johnny", "password": "correct-horse-battery"},
    )
    assert r.status_code == 200, r.text


def test_a_wrong_password_is_refused(db_client, local_only):
    _make_person(email="pw2@example.com", email_verified=True, password="correct-horse-battery")
    state = _oauth_state(db_client)
    r = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": state, "identifier": "pw2@example.com", "password": "wrong"},
    )
    assert r.status_code == 401


def test_an_unknown_account_is_refused_identically_to_a_wrong_password(db_client, local_only):
    """The same status and the same message — otherwise this endpoint enumerates accounts."""
    _make_person(email="pw3@example.com", email_verified=True, password="correct-horse-battery")
    known = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": _oauth_state(db_client), "identifier": "pw3@example.com", "password": "wrong"},
    )
    unknown = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": _oauth_state(db_client), "identifier": "nobody@example.com", "password": "wrong"},
    )
    assert known.status_code == unknown.status_code == 401
    assert known.json()["detail"] == unknown.json()["detail"]


def test_an_unverified_email_cannot_sign_in_with_a_password(db_client, local_only, monkeypatch):
    """The gate the linking rule leans on.

    Without it, an unproven address could hold a live session, leaving `person_service`'s
    verification check as the only thing standing between that account and a Google identity
    arriving at the same address.
    """
    import origin.routers.auth_router as ar

    monkeypatch.setattr(ar, "email_verification_required", lambda email: True)

    async def _no_mail(user):
        return None

    monkeypatch.setattr(ar, "_send_verification_email", _no_mail)

    _make_person(email="unverified@example.com", email_verified=False, password="correct-horse-battery")
    state = _oauth_state(db_client)
    r = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": state, "identifier": "unverified@example.com", "password": "correct-horse-battery"},
    )
    assert r.status_code == 403
    assert "verify your email" in r.json()["detail"].lower()


def test_the_password_leg_refuses_a_stale_handle(db_client, local_only):
    _make_person(email="pw4@example.com", email_verified=True, password="correct-horse-battery")
    r = db_client.post(
        "/auth/authorize/password",
        json={"oauth_state": "nope", "identifier": "pw4@example.com", "password": "correct-horse-battery"},
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# The linking rule — one human, one account, three doors
# ---------------------------------------------------------------------------
def _resolve(provider, subject, email, *, email_verified, name="Someone"):
    from origin.services import person_service

    with _session() as db:
        person = person_service.get_or_create_user_by_oidc_identity(
            db,
            oidc_provider=provider,
            oidc_subject=subject,
            email=email,
            name=name,
            email_verified=email_verified,
        )
        db.commit()
        return str(person.id)


def test_a_verified_google_identity_joins_the_existing_verified_account(db_client):
    """Password, OTP, and Google on one verified address resolve to the same account."""
    person_id = _make_person(
        email="linked@example.com", email_verified=True, password="correct-horse-battery"
    )
    landed = _resolve("google", "google-sub-1", "linked@example.com", email_verified=True)
    assert landed == person_id, "Google sign-in created a second account instead of linking"


def test_the_link_is_durable_and_survives_the_email_changing(db_client):
    """After linking, `(provider, subject)` is the key — the email is no longer what resolves it."""
    person_id = _make_person(email="durable@example.com", email_verified=True)
    _resolve("google", "google-sub-2", "durable@example.com", email_verified=True)
    again = _resolve("google", "google-sub-2", "renamed@example.com", email_verified=True)
    assert again == person_id


def test_an_unverified_provider_claim_is_refused_not_linked(db_client):
    """The classic "sign in with X" takeover.

    A provider that lets someone type an arbitrary address does not get the account at it: an
    unverified claim raises `IdentityLinkRefused` instead of linking.
    """
    from origin.services.person_service import IdentityLinkRefused

    _make_person(email="victim@example.com", email_verified=True, password="correct-horse-battery")
    with pytest.raises(IdentityLinkRefused):
        _resolve("google", "attacker-sub", "victim@example.com", email_verified=False)


def test_an_unverified_local_account_does_not_absorb_a_verified_identity(db_client):
    """The same attack run the other way, and the half of the rule that is easy to forget.

    An attacker registers a password account on the victim's address and never verifies it. If a
    verified Google sign-in linked into that account, the attacker would own the victim's identity
    with a password they already know.
    """
    from origin.services.person_service import IdentityLinkRefused

    _make_person(email="squatted@example.com", email_verified=False, password="attacker-password")
    with pytest.raises(IdentityLinkRefused):
        _resolve("google", "real-victim-sub", "squatted@example.com", email_verified=True)


def test_a_fresh_address_still_creates_an_account(db_client):
    """The invariant tests above must not have gone too far: a fresh, unclaimed address still
    creates an account."""
    landed = _resolve("google", "brand-new-sub", "nobody-here@example.com", email_verified=True)
    assert landed
    from origin.db import persons as db_persons

    with _session() as db:
        assert db_persons.get_by_email(db, "nobody-here@example.com") is not None


def test_a_refused_link_creates_NOTHING(db_client):
    """A blocked link leaves nothing behind: no second person at the address, and no identity row
    for the unverified claim."""
    from origin.db import person_identities as db_identities
    from origin.services.person_service import IdentityLinkRefused

    person_id = _make_person(email="untouched@example.com", email_verified=True)
    with pytest.raises(IdentityLinkRefused):
        _resolve("google", "unverified-sub", "untouched@example.com", email_verified=False)

    with _session() as db:
        from origin.db import persons as db_persons

        assert str(db_persons.get_by_email(db, "untouched@example.com").id) == person_id
        assert db_identities.get_by_identity(
            db, method="oidc", provider="google", subject="unverified-sub"
        ) is None


def test_email_verified_defaults_to_false_so_a_thoughtless_caller_cannot_link(db_client):
    """The default is the safe direction: a caller that omits `email_verified` raises
    `IdentityLinkRefused` rather than linking."""
    from origin.services import person_service
    from origin.services.person_service import IdentityLinkRefused

    _make_person(email="default@example.com", email_verified=True)
    with _session() as db:
        with pytest.raises(IdentityLinkRefused):
            person_service.get_or_create_user_by_oidc_identity(
                db, oidc_provider="google", oidc_subject="s", email="default@example.com", name="X"
            )


# ---------------------------------------------------------------------------
# The claim itself
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "claim,expected",
    [
        (True, True), ("true", True), ("True", True), ("1", True), ("yes", True),
        (False, False), ("false", False), ("no", False), (None, False), ("", False),
    ],
)
def test_email_verified_claim_is_read_without_a_naive_cast(claim, expected):
    """`bool("false")` is `True`. A provider that stringifies its claims would otherwise have
    every explicit denial read as an approval, and an absent claim is not an assertion at all."""
    from origin.routers.auth_router import _extract_email_verified

    info = {"sub": "s", "email": "a@b.c"}
    if claim is not None:
        info["email_verified"] = claim
    assert _extract_email_verified(info) is expected


def test_an_absent_claim_is_false(db_client):
    from origin.routers.auth_router import _extract_email_verified

    assert _extract_email_verified({"sub": "s", "email": "a@b.c"}) is False
