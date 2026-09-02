"""RFC 7591 dynamic client registration — a client can enrol itself, and only what it was promised.

An MCP client registers itself: it reads `registration_endpoint` from the discovery document, POSTs
its redirect URIs, and starts the flow with the `client_id` it gets back. With no such endpoint it
never reaches `/authorize` at all, and the only way in is a hand-minted token in a static header.

Three claims carry this suite.

· A REGISTRATION IS WHAT ADMITS AN ID NOBODY CONFIGURED. `/authorize` refuses a `client_id` that is
  neither first-party by configuration nor present in `oauth_clients`, so the minted id must work
  there and an id from neither population must not. The rest of that rule — the first-party
  population, the redirect binding, the shape of the refusal — is pinned in
  `test_authorize_client_enforcement`, which is where enforcement lives.

· A registration is not a promise this authority will break. Every redirect URI accepted here is one
  `is_client_redirect_allowed` admits, asserted against that function directly rather than against a
  copy of its rules — the two cannot drift while this test reads the real one.

· OFF IS THE DEFAULT. Open registration lets anyone write a row; the operator turns it on, and may
  gate it with an initial access token.

Imports are function-local: the `origin_app` fixture reloads `origin.config` and the routers, so a
module-level import binds to a pre-reload module and monkeypatching it changes nothing the running
app reads. Same note as `test_server_credentials_authz`.
"""

from __future__ import annotations

import pytest


REDIRECT = "http://127.0.0.1:54321/callback"


@pytest.fixture
def db_client(origin_app):
    """A client whose in-memory SQLite actually has tables.

    Mirrors `test_mcp_client_token_scoping.db_client`: `conftest.origin_app` skips migrations, so
    the schema is built from the models after lifespan has created the engine.
    """
    from fastapi.testclient import TestClient

    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _enable(monkeypatch, *, token: str = ""):
    """Turn registration on, optionally behind an initial access token."""
    from origin import config

    monkeypatch.setattr(config, "CLIENT_REGISTRATION_ENABLED", True)
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", token)


def _register(client, body: dict | None = None, headers: dict | None = None):
    payload = {
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "An MCP Client",
    }
    if body is not None:
        payload = body
    return client.post("/auth/register", json=payload, headers=headers or {})


def _authorize(client, *, client_id, redirect_uri=REDIRECT):
    return client.get(
        "/auth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": "st",
        },
    )


# ---------------------------------------------------------------------------
# Open versus gated — and off by default
# ---------------------------------------------------------------------------
def test_registration_is_off_until_an_operator_turns_it_on(db_client):
    """The default. Open registration on a reachable node writes rows for anyone who asks, so the
    node that does nothing keeps the behaviour it has today."""
    resp = _register(db_client)
    assert resp.status_code == 403, f"registration answered {resp.status_code} with nobody enabling it"
    body = resp.json()
    assert body["error"] == "access_denied"
    # The operator is the only reader who can act on this, so it names the setting.
    assert "CLIENT_REGISTRATION_ENABLED" in body["error_description"]


def test_the_discovery_document_does_not_advertise_a_disabled_endpoint(db_client):
    """Publishing the field on a node with registration off turns a clean "this authority does not
    register clients" into a 403 on a URL the document itself promised."""
    assert "registration_endpoint" not in db_client.get("/.well-known/openid-configuration").json()


def test_the_discovery_document_advertises_the_endpoint_when_enabled(db_client, monkeypatch):
    """The whole reason a client can find it. Under the issuer, like every other endpoint — a
    document whose `issuer` is right and whose endpoints are not is only found by a client that
    follows a link."""
    _enable(monkeypatch)
    doc = db_client.get("/.well-known/openid-configuration").json()
    assert doc["registration_endpoint"] == doc["issuer"] + "/auth/register"


def test_a_gated_endpoint_refuses_a_registration_with_no_token(db_client, monkeypatch):
    _enable(monkeypatch, token="the-operators-initial-access-token")
    resp = _register(db_client)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"
    # RFC 6750 §3: a bad bearer token is answered with the challenge that says what was wanted.
    assert resp.headers["www-authenticate"].startswith("Bearer")


def test_a_gated_endpoint_refuses_the_wrong_token(db_client, monkeypatch):
    _enable(monkeypatch, token="the-operators-initial-access-token")
    resp = _register(db_client, headers={"Authorization": "Bearer not-that-one"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


def test_a_non_ascii_token_is_refused_rather_than_crashing(db_client, monkeypatch):
    """The presented side is whatever an anonymous caller put in a header. `compare_digest` on
    `str` raises TypeError unless both sides are ASCII, and a 500 on an unvalidated header is a
    worse answer than a 401.

    Sent as raw bytes, because that is the only way the value arrives: a high byte on the wire is
    decoded latin-1 by the server into a `str` no ASCII check has seen.
    """
    _enable(monkeypatch, token="the-operators-initial-access-token")
    resp = _register(
        db_client, headers={"Authorization": "Bearer héllo-wörld".encode("latin-1")}
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"] == "invalid_token"


def test_a_gated_endpoint_admits_the_configured_token(db_client, monkeypatch):
    """The positive control: without it every assertion above would pass on an endpoint that
    refused everyone."""
    _enable(monkeypatch, token="the-operators-initial-access-token")
    resp = _register(db_client, headers={"Authorization": "Bearer the-operators-initial-access-token"})
    assert resp.status_code == 201, resp.text
    assert resp.json()["client_id"]


# ---------------------------------------------------------------------------
# The registration itself
# ---------------------------------------------------------------------------
def test_an_mcp_client_registers_and_receives_a_client_id(db_client, monkeypatch):
    """RFC 7591 §3.2.1 — 201, the minted id, and the metadata that was actually registered."""
    _enable(monkeypatch)
    resp = _register(db_client)
    assert resp.status_code == 201, resp.text

    body = resp.json()
    assert body["client_id"].startswith("dcr_"), body["client_id"]
    assert body["redirect_uris"] == [REDIRECT]
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    assert body["response_types"] == ["code"]
    assert body["token_endpoint_auth_method"] == "none"
    assert body["client_name"] == "An MCP Client"
    assert isinstance(body["client_id_issued_at"], int)
    # A credential-shaped identifier is not cacheable.
    assert "no-store" in resp.headers["cache-control"]


def test_no_secret_is_issued_and_none_is_stored(db_client, monkeypatch):
    """A public PKCE client has no secret, and the token endpoint authenticates no client on the
    authorization_code path — so a stored secret would be protection that is not there."""
    from origin.models.oauth_client import OAuthClient

    _enable(monkeypatch)
    body = _register(db_client).json()
    assert "client_secret" not in body
    assert "client_secret_expires_at" not in body

    columns = set(OAuthClient.__table__.columns.keys())
    assert not [c for c in columns if "secret" in c], columns


def test_the_registration_is_stored_and_not_merely_echoed(db_client, monkeypatch):
    """A registry that answers correctly and writes nothing is a registry only in the response."""
    from origin.db import oauth_clients as db_oauth_clients
    from origin.db.session import SessionLocal

    _enable(monkeypatch)
    client_id = _register(db_client).json()["client_id"]

    with SessionLocal() as session:
        stored = db_oauth_clients.get_by_client_id(session, client_id)
    assert stored is not None, "the registration was returned but never written"
    assert stored.redirect_uris == [REDIRECT]
    assert stored.token_endpoint_auth_method == "none"
    assert stored.client_name == "An MCP Client"
    assert stored.client_id_issued_at is not None


def test_unknown_metadata_is_ignored_rather_than_refused(db_client, monkeypatch):
    """A real MCP client sends more of RFC 7591 §2 than this authority stores. Refusing on an
    unrecognised field would lock out every client that sends one; §3.2.1 makes the response the
    record of what was registered, so an ignored field is one the client can see was not kept."""
    _enable(monkeypatch)
    resp = _register(db_client, body={
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "client_name": "Claude Code",
        "client_uri": "https://claude.ai/code",
        "logo_uri": "https://claude.ai/logo.png",
        "contacts": ["someone@example.com"],
        "scope": "read write",
        "software_id": "4NRB1-0XZABZI9E6-5SM3R",
        "software_version": "1.2.3",
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    for ignored in ("client_uri", "logo_uri", "contacts", "scope", "software_id", "software_version"):
        assert ignored not in body, f"{ignored} was echoed as registered but is not stored"


def test_registration_is_not_a_client_configuration_endpoint(db_client, monkeypatch):
    """RFC 7592 is not implemented, so neither field that points at it is returned. Both are
    optional in §3.2.1; returning them without the endpoint behind them is the same lie in a
    different field."""
    _enable(monkeypatch)
    body = _register(db_client).json()
    assert "registration_access_token" not in body
    assert "registration_client_uri" not in body


# ---------------------------------------------------------------------------
# Redirect URIs — the security-relevant field
# ---------------------------------------------------------------------------
def test_a_loopback_callback_registers_because_authorize_honours_it(db_client, monkeypatch):
    """Where an MCP client's callback actually lands: a loopback listener on an ephemeral port."""
    from origin.services.auth_service import is_client_redirect_allowed

    _enable(monkeypatch)
    for uri in ("http://127.0.0.1:1/cb", "http://localhost:65535/cb"):
        assert is_client_redirect_allowed(uri), "the premise of this test moved"
        resp = _register(db_client, body={"redirect_uris": [uri]})
        assert resp.status_code == 201, f"{uri} was refused: {resp.text}"


@pytest.mark.parametrize("uri", [
    "https://evil.example/cb",
    "ftp://localhost:5173/cb",
    "https://facet.evil.example/cb",
])
def test_a_redirect_authorize_would_refuse_cannot_be_registered(db_client, monkeypatch, uri):
    """The agreement, asserted against the real gate rather than a copy of its rules: if
    `/authorize` will not deliver there, registration must not promise it."""
    from origin.services.auth_service import is_client_redirect_allowed

    _enable(monkeypatch)
    assert not is_client_redirect_allowed(uri), "the premise of this test moved"
    resp = _register(db_client, body={"redirect_uris": [uri]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


def test_nothing_registrable_is_a_redirect_authorize_would_refuse(db_client, monkeypatch):
    """The one-directional guarantee stated as a property over a spread of shapes, so a future
    loosening of either side is caught by the pair rather than by one case.

    Registration is allowed to be STRICTER than `/authorize` — a fragment-bearing URI is refused
    here and would have been honoured there — because that direction breaks no promise. The reverse
    must never happen.
    """
    from origin.services.auth_service import is_client_redirect_allowed

    _enable(monkeypatch)
    candidates = [
        "http://127.0.0.1:8765/cb",
        "http://localhost:3000/callback",
        "https://vscode.dev/redirect",
        "https://evil.example/cb",
        "http://127.0.0.1:8765/cb#frag",
        "not-a-uri",
        "http://localhost:3000/cb?next=https://evil.example",
    ]
    for uri in candidates:
        registered = _register(db_client, body={"redirect_uris": [uri]}).status_code == 201
        if registered:
            assert is_client_redirect_allowed(uri), \
                f"registration promised {uri!r}, which /authorize refuses"


def test_a_fragment_bearing_redirect_is_refused(db_client, monkeypatch):
    """RFC 6749 §3.1.2 — the redirection endpoint URI must not include a fragment."""
    _enable(monkeypatch)
    resp = _register(db_client, body={"redirect_uris": ["http://127.0.0.1:8765/cb#tokens"]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


@pytest.mark.parametrize("body", [
    {},
    {"redirect_uris": []},
    {"redirect_uris": "http://127.0.0.1:8765/cb"},
    {"redirect_uris": [""]},
    {"redirect_uris": ["/relative/cb"]},
])
def test_a_registration_with_no_usable_redirect_is_invalid_redirect_uri(db_client, monkeypatch, body):
    """§3.2.2 gives this its own error code, and an MCP client reads the code to decide what to
    tell its user — `invalid_client_metadata` here would send them looking at the wrong field."""
    _enable(monkeypatch)
    resp = _register(db_client, body=body)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri", resp.text


# ---------------------------------------------------------------------------
# The rest of the metadata
# ---------------------------------------------------------------------------
def test_a_client_asking_to_authenticate_with_a_secret_is_refused(db_client, monkeypatch):
    """This endpoint issues no secret. Registering `client_secret_basic` would record a client
    whose token requests can never succeed."""
    _enable(monkeypatch)
    resp = _register(db_client, body={
        "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


def test_an_omitted_auth_method_is_registered_as_none(db_client, monkeypatch):
    """RFC 7591 §2 defaults this field to `client_secret_basic`, which cannot apply here. §3.2.1
    lets the server return the value it registered, so the client is told `none` rather than left
    to assume a secret it never received."""
    _enable(monkeypatch)
    resp = _register(db_client, body={"redirect_uris": [REDIRECT]})
    assert resp.status_code == 201, resp.text
    assert resp.json()["token_endpoint_auth_method"] == "none"


@pytest.mark.parametrize("body,field", [
    ({"redirect_uris": [REDIRECT], "grant_types": ["client_credentials"]}, "grant_types"),
    ({"redirect_uris": [REDIRECT], "grant_types": ["password"]}, "grant_types"),
    ({"redirect_uris": [REDIRECT], "response_types": ["token"]}, "response_types"),
    ({"redirect_uris": [REDIRECT], "response_types": ["id_token"]}, "response_types"),
])
def test_a_grant_this_authority_does_not_issue_to_a_public_client_is_refused(
    db_client, monkeypatch, body, field
):
    """`client_credentials` is the pointed one: it is a grant this authority supports, and it
    authenticates with a secret this endpoint does not issue — that credential lives in
    `server_credentials` and is minted operator-only."""
    _enable(monkeypatch)
    resp = _register(db_client, body=body)
    assert resp.status_code == 400
    payload = resp.json()
    assert payload["error"] == "invalid_client_metadata"
    assert field in payload["error_description"]


def test_grant_and_response_types_must_agree(db_client, monkeypatch):
    """RFC 7591 §2 ties them: the authorization_code grant uses the code response type. Registering
    one without the other records a client that cannot complete a flow."""
    _enable(monkeypatch)
    resp = _register(db_client, body={
        "redirect_uris": [REDIRECT], "grant_types": ["refresh_token"], "response_types": ["code"],
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


def test_a_body_that_is_not_a_json_object_is_refused_with_the_rfc_code(db_client, monkeypatch):
    """Hand-parsed rather than modelled, precisely so this answers §3.2.2's shape instead of a
    validation 422 an MCP client cannot read."""
    _enable(monkeypatch)
    resp = db_client.post("/auth/register", content=b"not json",
                          headers={"Content-Type": "application/json"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"

    resp = db_client.post("/auth/register", json=["an", "array"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


def test_client_name_is_bounded_by_the_column_that_stores_it(db_client, monkeypatch):
    """The bound is the column's width, so what fits the response is exactly what fits the table —
    a longer name is refused rather than truncated into a row that no longer matches what was
    returned."""
    from origin.models.oauth_client import OAuthClient

    _enable(monkeypatch)
    limit = OAuthClient.client_name.type.length
    resp = _register(db_client, body={"redirect_uris": [REDIRECT], "client_name": "n" * (limit + 1)})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"

    assert _register(db_client, body={
        "redirect_uris": [REDIRECT], "client_name": "n" * limit,
    }).status_code == 201


# ---------------------------------------------------------------------------
# Registration is not enforcement
# ---------------------------------------------------------------------------
def test_a_registered_client_can_start_an_authorization_flow(db_client, monkeypatch):
    """The point of the whole change: the minted `client_id` is usable at `/authorize`."""
    _enable(monkeypatch)
    client_id = _register(db_client).json()["client_id"]
    assert _authorize(db_client, client_id=client_id).status_code == 200


def test_authorize_refuses_a_client_that_registered_nowhere(db_client, monkeypatch):
    """The counterpart of the test above: registration is what admits an id no operator configured,
    so an id with neither is refused. The full enforcement rule — and the first-party population it
    must not touch — is pinned in `test_authorize_client_enforcement`."""
    _enable(monkeypatch)
    resp = _authorize(db_client, client_id="never-registered-anywhere")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


def test_a_self_registered_client_is_not_thereby_first_party(db_client, monkeypatch):
    """A client vouching for itself is not the operator naming it — the scoped, PII-free
    `mcp_client` token is what it gets, as before."""
    import origin.routers.auth_router as ar

    _enable(monkeypatch)
    client_id = _register(db_client).json()["client_id"]
    assert ar._is_first_party_client(client_id) is False


# ---------------------------------------------------------------------------
# The schema this depends on
# ---------------------------------------------------------------------------
def test_the_migration_builds_the_table_the_model_declares(tmp_path):
    """Runs the real revision chain against a fresh file database and compares the result to the
    model, which is the only thing the rest of this suite builds from.

    `main._run_migrations` notes that every test here sets `ORIGIN_SKIP_MIGRATIONS=1` and builds
    from `Base.metadata`, so models-vs-migrations drift is invisible to CI. That is a general gap
    and this does not close it — it closes it for the one table this change adds, which is the table
    whose absence at boot would take the endpoint down on a real node.
    """
    from pathlib import Path

    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig

    import origin
    from origin.models.oauth_client import OAuthClient

    db_path = tmp_path / "origin.db"
    here = Path(origin.__file__).resolve().parent
    cfg = AlembicConfig(str(here / "alembic.ini"))
    cfg.set_main_option("script_location", str(here / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sa.inspect(engine)
        assert "oauth_clients" in inspector.get_table_names()
        migrated = {c["name"] for c in inspector.get_columns("oauth_clients")}
        assert migrated == set(OAuthClient.__table__.columns.keys()), \
            "the migration and the model disagree about oauth_clients"
    finally:
        engine.dispose()
