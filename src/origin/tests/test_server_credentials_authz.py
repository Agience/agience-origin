"""`/auth/clients` mints platform server credentials — only the operator may touch it.

Authentication alone is not authorization: a handler that only checks "is anyone logged in" lets
any registered user mint a `client_secret` with caller-chosen `scopes`, exchange it via
`client_credentials`, and receive an Origin-signed `principal_type: server` token with wildcard
scope. What a self-issued platform-signed credential is accepted for elsewhere is not this
router's to assume, so the gate has to hold whether or not any peer honours the type today. This
suite pins that every route on this router requires the platform operator specifically, not
merely an authenticated caller.

Imports are function-local: the `origin_app` fixture reloads `origin.config`, `key_manager` and
`auth_service`, so module-level imports bind to pre-reload modules and mint tokens the rebuilt app
cannot verify. See `test_oracle_router_auth` for the same note.
"""

OPERATOR = "operator-uuid-1234"
INTRUDER = "some-random-registered-user"
from origin.tests.test_a_key_share_is_released_only_to_mantle import custody_client  # noqa: E402,F401


def _mint(sub, **extra):
    from origin import config
    from origin.services.auth_service import create_jwt_token

    d = {"sub": sub, "email": f"{sub}@example.com", "name": "U",
         "client_id": "platform", "aud": config.AUTHORITY_ISSUER}
    d.update(extra)
    return create_jwt_token(d)


def _operator_is_set(monkeypatch):
    from origin.services.platform_settings_service import settings as platform_settings

    monkeypatch.setattr(platform_settings, "get",
                        lambda k, *a, **kw: OPERATOR if k == "platform.operator_id" else None)


def _h(sub):
    return {"Authorization": f"Bearer {_mint(sub)}"}


def test_an_ordinary_user_cannot_mint_a_server_credential(client, monkeypatch):
    """The escalation path: any registered user asking for wildcard scopes."""
    _operator_is_set(monkeypatch)
    r = client.post("/auth/clients", headers=_h(INTRUDER), json={
        "client_id": "evil", "name": "evil", "server_id": "s", "host_id": "h",
        "scopes": ["*"], "resource_filters": {"workspaces": "*"},
    })
    assert r.status_code == 403, \
        f"an ordinary user minted a platform server credential ({r.status_code})"


def test_an_ordinary_user_cannot_enumerate_or_hijack_existing_clients(client, monkeypatch):
    """`GET` lists every client unfiltered; `rotate`/`PATCH` accept any client_id — the router-level
    operator gate is the only thing standing between an ordinary caller and every credential."""
    _operator_is_set(monkeypatch)
    assert client.get("/auth/clients", headers=_h(INTRUDER)).status_code == 403
    assert client.post("/auth/clients/some-real-client/rotate",
                       headers=_h(INTRUDER)).status_code == 403
    assert client.patch("/auth/clients/some-real-client", headers=_h(INTRUDER),
                        json={"scopes": ["*"]}).status_code == 403
    assert client.delete("/auth/clients/some-real-client",
                         headers=_h(INTRUDER)).status_code == 403


def test_an_unauthenticated_caller_is_refused(client, monkeypatch):
    _operator_is_set(monkeypatch)
    assert client.get("/auth/clients").status_code in (401, 403)


def test_the_operator_s_ordinary_access_token_is_refused(client, monkeypatch):
    """A credential this router mints outlives every token, and the operator's ordinary access
    token reaches Mantle: it opens nothing here. Only the console, with a step-up, does."""
    from origin.db import server_credentials as db_server_creds

    _operator_is_set(monkeypatch)
    monkeypatch.setattr(db_server_creds, "list_all", lambda db: [])
    assert client.get("/auth/clients", headers=_h(OPERATOR)).status_code == 403
    assert client.post("/auth/clients", headers=_h(OPERATOR), json={
        "client_id": "c", "name": "c", "server_id": "s", "host_id": "h"}).status_code == 403


def test_the_operator_gets_through_on_the_console_with_a_step_up(custody_client, monkeypatch):  # noqa: F811
    """Positive control, on the console: the gate is not closed for everyone."""
    from origin.db import server_credentials as db_server_creds
    from origin.tests import authority_fixtures as af
    from origin.tests import operator_console_fixtures as oc

    af.operator(monkeypatch)
    monkeypatch.setattr(db_server_creds, "list_all", lambda db: [])
    r = oc.call(custody_client, "GET", "/auth/clients")
    assert r.status_code == 200, r.text
    _auth, token = oc.console(custody_client)
    bare = custody_client.get("/auth/clients", headers={"Authorization": f"Bearer {token}"})
    assert bare.status_code in (401, 403), "the console token alone, with no step-up"



def test_a_delegation_acting_for_the_operator_cannot_reach_the_router(client, monkeypatch):
    """A delegation carrying the operator's `sub` is not the operator's own session, and must not
    reach this router.

    `resolve_auth` normalizes a delegation to `principal_type="user"` with `actor=act.sub`, so a
    delegation carrying `sub=<operator_id>` is otherwise indistinguishable from the operator's own
    session. `_require_operator` checks both `principal_type == "user"` and `actor is None`;
    checking only the first would let a delegation through to every handler — `POST ""`, which
    mints a `client_secret` with caller-chosen `scopes`, and `POST /{id}/rotate`, which re-mints an
    existing client's secret.

    This matters more than an ordinary authorization gap: a minted client_secret outlives the
    delegation that obtained it, so revoking the delegation does not revoke the credential. Mirrors
    the reasoning `passkey_router._require_interactive_user` applies to authenticator enrolment: a
    delegated token carries no authority there either.

    `list_all` is stubbed for the same reason as the positive control above — so this exercises the
    authorization gate and not the missing test table.
    """
    from origin.db import server_credentials as db_server_creds

    _operator_is_set(monkeypatch)
    monkeypatch.setattr(db_server_creds, "list_all", lambda db: [])
    tok = _mint(OPERATOR, principal_type="delegation", act={"sub": "chorus"}, aud="seraph")
    r = client.get("/auth/clients", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code in (401, 403), \
        f"a DELEGATION acting for the operator reached /auth/clients ({r.status_code})"
