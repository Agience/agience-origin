"""Which clients `/authorize` admits, and where each may be delivered a code.

Two rules.

· ADMISSION. A `client_id` is admitted because an operator configured it (`PLATFORM_CLIENT_ID`,
  `PLATFORM_CLIENT_IDS`) or because this authority issued it (`POST /auth/register`). Nothing else
  reaches a login page.

· BINDING. `is_client_redirect_allowed` is authority-wide and client-blind — it admits this node's
  facets, the well-known tool callbacks and loopback for every caller alike — so on its own it would
  let any client name any admitted callback, including another client's. A registered client is held
  to its own `redirect_uris` as well, and the cross-client test below is what pins that.

Two properties carry as much weight as the rules.

· The refusal does not redirect. RFC 6749 §4.1.2.1 forbids redirecting an error caused by an invalid
  client or an invalid redirect URI, because the redirect target is precisely what has nothing
  standing behind it. A 302 carrying `error=invalid_client` would be the defect wearing the fix's
  clothes, so the tests assert on the status and on `Location` being absent, not on the body alone.

· Loopback keeps working on the second run. RFC 8252 §7.3 requires any port to be accepted for a
  loopback redirect, because a native client takes whatever ephemeral port the OS gives it. An
  implementation that compared the whole URI would admit an MCP client's first run and refuse every
  one after — the failure would look like a broken registration and be a working one.

Imports are function-local: `origin_app` reloads `origin.config` and the routers, so a module-level
import binds a pre-reload module and monkeypatching it changes nothing the running app reads.
"""

from __future__ import annotations

import pytest


FACET_REDIRECT = "http://localhost:8080/cb"
LOOPBACK_REDIRECT = "http://127.0.0.1:54321/callback"


@pytest.fixture
def db_client(origin_app):
    """A client whose in-memory SQLite actually has tables — `origin_app` skips migrations."""
    from fastapi.testclient import TestClient

    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


@pytest.fixture
def registration_open(monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "CLIENT_REGISTRATION_ENABLED", True)
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", "")


def _register(client, redirect_uris):
    resp = client.post("/auth/register", json={"redirect_uris": list(redirect_uris)})
    assert resp.status_code == 201, resp.text
    return resp.json()["client_id"]


def _authorize(client, *, client_id, redirect_uri=FACET_REDIRECT):
    return client.get(
        "/auth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": "st",
        },
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# The three populations
# ---------------------------------------------------------------------------
def test_the_configured_first_party_client_is_admitted(db_client):
    """The default id every node ships with. A check that locked this out would be a node nobody
    can sign in to."""
    from origin import config

    assert _authorize(db_client, client_id=config.PLATFORM_CLIENT_ID).status_code == 200


def test_an_id_enrolled_in_platform_client_ids_is_admitted(db_client, monkeypatch):
    """Mantle's browser client, working. `MANTLE_OIDC_CLIENT_ID` has no default and is set on
    Mantle; enrolling that exact value here is the operator's single edit, and it is the same edit
    that already had to happen for the browser to receive a user token rather than a scoped one."""
    from origin import config

    monkeypatch.setattr(config, "PLATFORM_CLIENT_IDS", ["mantle-browser"])
    assert _authorize(db_client, client_id="mantle-browser").status_code == 200


def test_a_first_party_id_is_admitted_without_reading_the_registry(db_client, monkeypatch):
    """A configured sign-in does not depend on `oauth_clients` existing, being migrated or being
    readable. The lookup is not merely unnecessary on this path — it is not performed, which is
    asserted by making it fail."""
    from origin import config
    from origin.db import oauth_clients as db_oauth_clients

    def _explode(*_a, **_k):
        raise AssertionError("a configured first-party client must not read oauth_clients")

    monkeypatch.setattr(db_oauth_clients, "get_by_client_id", _explode)
    assert _authorize(db_client, client_id=config.PLATFORM_CLIENT_ID).status_code == 200


def test_a_registered_client_is_admitted(db_client, registration_open):
    """The population the registry exists to create."""
    client_id = _register(db_client, [FACET_REDIRECT])
    assert _authorize(db_client, client_id=client_id).status_code == 200


def test_an_id_from_neither_population_is_refused(db_client):
    """A client id from neither population never reaches a login page."""
    resp = _authorize(db_client, client_id="a-client-nobody-named")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


def test_the_refusal_names_what_an_operator_has_to_do(db_client):
    """The operator is the only reader who can act on this, and the likeliest one to be here is a
    node whose `MANTLE_OIDC_CLIENT_ID` was never enrolled. The message has to carry the setting and
    the alternative, or it is a 400 that ends the investigation nowhere."""
    body = _authorize(db_client, client_id="mantle-browser").json()["error_description"]
    assert "PLATFORM_CLIENT_IDS" in body
    assert "MANTLE_OIDC_CLIENT_ID" in body
    assert "/auth/register" in body


def test_an_id_shaped_like_a_registration_that_is_gone_says_so(db_client):
    """A `dcr_` id with no row is a client holding what looks like a valid registration. "Unknown"
    is not actionable for it; "register again" is, and it is also what is true — the record is gone
    (a rebuilt database, a different node behind the same name), not unrecognised."""
    import origin.routers.auth_router as ar

    resp = _authorize(db_client, client_id=f"{ar._DCR_CLIENT_ID_PREFIX}vanished")
    assert resp.status_code == 400
    assert "Register again" in resp.json()["error_description"]


# ---------------------------------------------------------------------------
# RFC 6749 §4.1.2.1 — the one error that must not follow redirect_uri
# ---------------------------------------------------------------------------
def test_an_unknown_client_is_refused_without_redirecting(db_client):
    """The refusal must not go to `redirect_uri`. The redirect target is exactly what has nothing
    standing behind it when the client is unknown — reporting the error there would hand whoever
    guessed a client id a delivery to an address this authority just declined to trust. §4.1.2.1:
    "MUST NOT automatically redirect the user-agent to the invalid redirection URI."

    The redirect used here is on the authority's own allow-list, so the endpoint COULD have
    redirected and chose not to; a test against an unlisted URI would pass on the allow-list alone
    and prove nothing about this rule."""
    resp = _authorize(db_client, client_id="a-client-nobody-named", redirect_uri=FACET_REDIRECT)
    assert resp.status_code == 400
    assert resp.status_code not in (301, 302, 303, 307, 308)
    assert "location" not in {k.lower() for k in resp.headers}
    # Nor smuggled into the body as a target for a page to follow.
    assert FACET_REDIRECT not in resp.text


def test_a_redirect_binding_failure_does_not_redirect_either(db_client, registration_open):
    """The same clause covers "mismatching redirection URI", and for the same reason."""
    client_id = _register(db_client, [LOOPBACK_REDIRECT])
    resp = _authorize(db_client, client_id=client_id, redirect_uri=FACET_REDIRECT)
    assert resp.status_code == 400
    assert "location" not in {k.lower() for k in resp.headers}


def test_the_refusal_is_not_cacheable(db_client):
    """Same reason the sign-in page sets it: a shared cache holding this answer would serve one
    client's refusal to the next caller."""
    resp = _authorize(db_client, client_id="a-client-nobody-named")
    assert resp.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# Redirect binding — the finding this closes
# ---------------------------------------------------------------------------
def test_a_registered_client_cannot_use_another_clients_redirect(db_client, registration_open):
    """Two URIs on the authority-wide allow-list, and a client held to its own. Without the
    registration check, client A could name client B's callback and have B's address receive A's
    code."""
    a = _register(db_client, ["http://localhost:8080/a/callback"])
    b_uri = "http://localhost:8080/b/callback"
    _register(db_client, [b_uri])

    from origin.services.auth_service import is_client_redirect_allowed

    assert is_client_redirect_allowed(b_uri), "the point is that the allow-list admits it"

    resp = _authorize(db_client, client_id=a, redirect_uri=b_uri)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_the_refusal_does_not_disclose_what_the_client_registered(db_client, registration_open):
    """The caller either registered those URIs and has them, or is asking this authority to
    describe a client that is not theirs."""
    own = "http://localhost:8080/private/callback"
    client_id = _register(db_client, [own])
    resp = _authorize(db_client, client_id=client_id, redirect_uri="http://localhost:8080/other")
    assert own not in resp.text


def test_a_registered_client_still_answers_to_the_authority_wide_allow_list(
    db_client, registration_open, monkeypatch
):
    """Composition, not replacement. Registration validates each URI against the allow-list, so a
    registered set is a subset of it and the conjunction is the registered set — until an operator
    edits `FACET_URIS`, and then the withdrawal reaches every registered client holding it, in that
    one edit. Config stays the outer bound, which is the direction that can only narrow."""
    from origin import config

    facet = "http://facet.example:8080"
    facet_cb = f"{facet}/cb"

    monkeypatch.setattr(config, "FACET_URIS", [facet])
    client_id = _register(db_client, [facet_cb])
    assert _authorize(db_client, client_id=client_id, redirect_uri=facet_cb).status_code == 200

    # The facet is decommissioned. The row still names it; the allow-list no longer does.
    monkeypatch.setattr(config, "FACET_URIS", [])
    assert _authorize(db_client, client_id=client_id, redirect_uri=facet_cb).status_code == 403


def test_a_first_party_client_is_bound_by_the_allow_list_alone(db_client, monkeypatch):
    """There is no registration for a configured client, so the allow-list is all there is — and
    that is the answer rather than a gap: which ids are first-party and which bases are admitted are
    the same operator's configuration. This pins the deliberate half (any allowlisted base) and the
    bound that still holds (nothing else)."""
    from origin import config

    monkeypatch.setattr(config, "PLATFORM_CLIENT_IDS", ["mantle-browser"])
    assert _authorize(
        db_client, client_id="mantle-browser", redirect_uri="http://localhost:8080/anywhere"
    ).status_code == 200
    assert _authorize(
        db_client, client_id="mantle-browser", redirect_uri="https://evil.example/cb"
    ).status_code == 403


def test_a_configured_id_that_is_also_registered_is_treated_as_configured(
    db_client, registration_open, monkeypatch
):
    """The both-case, stated so it is a decision rather than an accident of ordering. Naming an id
    in `PLATFORM_CLIENT_IDS` is an operator saying "this is one of ours" — the stronger statement —
    so it keeps the allow-list, and a first-party sign-in keeps depending on no database row."""
    from origin import config

    client_id = _register(db_client, [LOOPBACK_REDIRECT])
    monkeypatch.setattr(config, "PLATFORM_CLIENT_IDS", [client_id])

    # Outside its registration, inside the allow-list: refused as a registered client, admitted as
    # a configured one.
    assert _authorize(db_client, client_id=client_id, redirect_uri=FACET_REDIRECT).status_code == 200


# ---------------------------------------------------------------------------
# RFC 8252 §7.3 — the loopback port, and an MCP client's second run
# ---------------------------------------------------------------------------
def test_a_loopback_client_works_on_a_port_it_did_not_register(db_client, registration_open):
    """The second run. "The authorization server MUST allow any port to be specified at the time of
    the request for loopback IP redirect URIs, to accommodate clients that obtain an available
    ephemeral port from the operating system at the time of the request." An MCP client registers
    once and binds a fresh port every run; matching the whole URI would make the registration a
    record of one afternoon's port."""
    client_id = _register(db_client, [LOOPBACK_REDIRECT])
    assert _authorize(db_client, client_id=client_id, redirect_uri=LOOPBACK_REDIRECT).status_code == 200
    # Same client, next run, different ephemeral port.
    assert _authorize(
        db_client, client_id=client_id, redirect_uri="http://127.0.0.1:61234/callback"
    ).status_code == 200


def test_the_loopback_relaxation_is_the_port_and_nothing_else(db_client, registration_open):
    """The relaxation is safe because a loopback port is reachable only from the machine already
    running the client. Extending it to the path would not be — `/callback` and `/evil` are two
    different programs' addresses on that machine."""
    client_id = _register(db_client, [LOOPBACK_REDIRECT])
    assert _authorize(
        db_client, client_id=client_id, redirect_uri="http://127.0.0.1:61234/evil"
    ).status_code == 400
    # Nor does a loopback registration reach off the loopback interface.
    assert _authorize(
        db_client, client_id=client_id, redirect_uri=FACET_REDIRECT
    ).status_code == 400


def test_two_loopback_clients_on_the_same_path_are_one_address(db_client, registration_open):
    """The consequence of §7.3 stated as a fact rather than met as a surprise, because it reads like
    a hole in the binding above and is not one.

    Dropping the port means two clients that both register `/callback` on loopback have registered
    the same address — no comparison can both honour "MUST allow any port" and tell them apart. It
    costs nothing already unspent: binding a loopback port requires executing on that machine, and
    a code delivered there is still unredeemable without the `code_verifier` the real client kept.
    The PATH is compared, and is where two loopback clients are told apart if that is wanted."""
    a = _register(db_client, ["http://127.0.0.1:1000/callback"])
    b_same_path = "http://127.0.0.1:2000/callback"
    _register(db_client, [b_same_path])
    assert _authorize(db_client, client_id=a, redirect_uri=b_same_path).status_code == 200

    # Distinct paths ARE distinct addresses, which is the binding doing its work on loopback.
    c_own_path = "http://127.0.0.1:2000/other-client/callback"
    _register(db_client, [c_own_path])
    assert _authorize(db_client, client_id=a, redirect_uri=c_own_path).status_code == 400


def test_a_non_loopback_registration_is_matched_with_its_port(origin_app):
    """The port relaxation is loopback-only. A facet on a named host is a fixed address, and
    dropping its port would let a registration for `:8080` name any other service on that host."""
    from origin.services.auth_service import redirect_uri_matches_registered

    registered = ["https://facet.example:8443/cb"]
    assert redirect_uri_matches_registered("https://facet.example:8443/cb", registered)
    assert not redirect_uri_matches_registered("https://facet.example:9000/cb", registered)


def test_loopback_hosts_are_not_interchangeable(origin_app):
    """`localhost` and `127.0.0.1` are both loopback and are still two different registered
    addresses — the relaxation drops the port, not the host."""
    from origin.services.auth_service import redirect_uri_matches_registered

    assert not redirect_uri_matches_registered(
        "http://localhost:5000/callback", ["http://127.0.0.1:54321/callback"]
    )


def test_userinfo_in_a_loopback_uri_does_not_match(origin_app):
    """`hostname` ignores userinfo, so comparing on it alone would make
    `http://user@127.0.0.1/cb` the same address as `http://127.0.0.1/cb`."""
    from origin.services.auth_service import redirect_uri_matches_registered

    assert not redirect_uri_matches_registered(
        "http://someone@127.0.0.1:9/callback", ["http://127.0.0.1:54321/callback"]
    )


def test_an_operator_written_string_is_not_matched_character_by_character(origin_app):
    """A hand-written row can put one string where the list belongs; iterating it would compare
    against its letters, match nothing, and hide why."""
    from origin.services.auth_service import redirect_uri_matches_registered

    assert redirect_uri_matches_registered(FACET_REDIRECT, FACET_REDIRECT)
    assert not redirect_uri_matches_registered("h", FACET_REDIRECT)


def test_an_empty_registration_matches_nothing(origin_app):
    """A row with no redirect URIs entitles its client to no address at all — never to every
    address, which is what an empty-set-is-permissive reading would give."""
    from origin.services.auth_service import redirect_uri_matches_registered

    assert not redirect_uri_matches_registered(FACET_REDIRECT, [])
    assert not redirect_uri_matches_registered(FACET_REDIRECT, None)
