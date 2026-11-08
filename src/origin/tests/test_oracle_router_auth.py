"""The operator routes accept only Origin's operator console, with a fresh passkey for each use.

`/oracle/*` releases decrypted secrets and holds custody's background authority, seed and
bootstrap credentials, delegation revocation and ledger verification. `_require_operator` admits a
caller only when both hold:

* the bearer is a console token, minted by `/oracle/console/sign-in` after the operator's passkey
  sign-in, addressed to an audience no other token carries and no other service accepts;
* `X-Operator-Step-Up` carries a passkey assertion, with user verification, over a single-use
  challenge bound to this request's method, path and body.

The passkey is a real P-256 authenticator (`operator_console_fixtures.Authenticator`); nothing on
the verification path is replaced. `test_the_operator_console_with_a_step_up_is_accepted` is the
positive control for every refusal below.

Every import happens inside the test functions: the `origin_app` fixture reloads `origin.config`,
so a module level import would bind to a stale copy.
"""
from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


def _access(**extra):
    """An operator access token, valid in every respect for an ordinary Origin route."""
    from origin import config
    from origin.services.auth_service import create_jwt_token

    d = {"sub": af.OPERATOR, "email": "op@x.test", "name": "Op", "client_id": "platform",
         "aud": config.AUTHORITY_ISSUER}
    d.update(extra)
    return create_jwt_token(d)


def _list(c, token, step=None):
    from origin.services import operator_console

    headers = {"Authorization": f"Bearer {token}"}
    if step is not None:
        headers[operator_console.STEP_UP_HEADER] = step
    return c.get("/oracle/secrets", headers=headers)


def _ready(c, monkeypatch):
    from origin.services import key_oracle

    af.operator(monkeypatch)
    monkeypatch.setattr(key_oracle, "list_ids", lambda db: [])
    return oc.console(c)


def test_the_operator_console_with_a_step_up_is_accepted(custody_client, monkeypatch):
    auth, token = _ready(custody_client, monkeypatch)
    step = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"")
    r = _list(custody_client, token, step)
    assert r.status_code == 200, r.text


def test_an_operator_access_token_is_refused(custody_client, monkeypatch):
    """Signed in anywhere else, the operator is not the console."""
    auth, token = _ready(custody_client, monkeypatch)
    step = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"")
    assert _list(custody_client, _access(), step).status_code == 403


def test_single_purpose_and_foreign_tokens_are_refused(custody_client, monkeypatch):
    auth, token = _ready(custody_client, monkeypatch)
    for spoilt in (_access(token_type="refresh"), _access(token_type="pwd_reset"),
                   _access(aud="evil-mcp"),
                   _access(principal_type="delegation", act={"sub": "chorus"}, aud="seraph"),
                   _access(aud="origin-operator-console"),            # the audience, no type
                   _access(token_type="operator_console")):           # the type, no audience
        step = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"")
        assert _list(custody_client, spoilt, step).status_code == 403


def test_a_console_token_without_a_step_up_is_refused(custody_client, monkeypatch):
    _auth, token = _ready(custody_client, monkeypatch)
    r = _list(custody_client, token)
    assert r.status_code == 403 and "step-up" in r.json()["detail"]


def test_a_step_up_authorizes_its_own_request_once(custody_client, monkeypatch):
    auth, token = _ready(custody_client, monkeypatch)
    for_another_path = oc.step_up(custody_client, token, auth, "GET", "/oracle/job-grants",
                                  b"")
    assert _list(custody_client, token, for_another_path).status_code == 403
    for_another_body = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"{}")
    assert _list(custody_client, token, for_another_body).status_code == 403
    step = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"")
    assert _list(custody_client, token, step).status_code == 200
    assert _list(custody_client, token, step).status_code == 403              # spent


def test_a_step_up_needs_user_verification_and_the_operator_s_own_passkey(custody_client,
                                                                         monkeypatch):
    auth, token = _ready(custody_client, monkeypatch)
    presence_only = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"",
                               verified=False)
    assert _list(custody_client, token, presence_only).status_code == 403
    stranger = oc.Authenticator()                                    # never registered
    step = oc.step_up(custody_client, token, stranger, "GET", "/oracle/secrets", b"")
    assert _list(custody_client, token, step).status_code == 403


def test_a_body_is_bound_into_the_step_up(custody_client, monkeypatch):
    """A step-up for one body does not carry a different body to the same route."""
    import json as jsonlib

    from origin.services import operator_console

    auth, token = _ready(custody_client, monkeypatch)
    signed = jsonlib.dumps({"minutes": 5}).encode()
    step = oc.step_up(custody_client, token, auth, "POST", "/oracle/seed-credential", signed)
    r = custody_client.post("/oracle/seed-credential", content=jsonlib.dumps({"minutes": 9}),
                            headers={"Authorization": f"Bearer {token}",
                                     "Content-Type": "application/json",
                                     operator_console.STEP_UP_HEADER: step})
    assert r.status_code == 403 and "another request" in r.json()["detail"]


def test_only_the_operator_signs_in_to_the_console(custody_client, monkeypatch):
    """The operator is recomputed at sign-in: a passkey assertion by someone who is no longer
    `platform.operator_id` gets no console token, though the passkey itself verifies."""
    from origin.services.platform_settings_service import settings as platform_settings

    af.operator(monkeypatch)
    auth = oc.Authenticator().register(af.OPERATOR)
    opts = custody_client.post("/oracle/console/sign-in-options").json()
    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw:
                        "someone-else" if k == "platform.operator_id" else real_get(k, *a, **kw))
    r = custody_client.post("/oracle/console/sign-in", json={
        "challenge": opts["challenge"], "credential": auth.assertion(opts)})
    assert r.status_code == 401


def test_the_console_token_opens_nothing_else(custody_client, monkeypatch):
    """Origin's ordinary routes refuse it, and it is not addressed to the authority, which is the
    audience Mantle requires of a person token."""
    from origin import config
    from origin.services.auth_verifier import verify_token

    _auth, token = _ready(custody_client, monkeypatch)
    r = custody_client.get("/auth/me/preferences", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert verify_token(token, expected_audience=config.AUTHORITY_ISSUER) is None


def test_the_query_string_is_bound_into_the_step_up(custody_client, monkeypatch):
    auth, token = _ready(custody_client, monkeypatch)
    step = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets?x=1", b"")
    assert _list(custody_client, token, step).status_code == 403          # sent without it
    step = oc.step_up(custody_client, token, auth, "GET", "/oracle/secrets", b"")
    r = custody_client.get("/oracle/secrets?x=1", headers={
        "Authorization": f"Bearer {token}", "X-Operator-Step-Up": step})
    assert r.status_code == 403                                            # signed without it
