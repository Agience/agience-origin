"""The Key Oracle accepts only a genuine operator access token.

`/oracle/*` returns decrypted secrets, so it is the most sensitive router in the platform.
`_require_operator` reaches that guarantee through `resolve_auth`: the token must carry no
`token_type` (ruling out the password-reset, email-verify, and refresh tokens), its audience must
match Origin, and its principal must be the operator directly, not a delegation acting for them —
`resolve_auth` normalizes a delegation to `principal_type="user"` with a non-None `actor` before
this router ever sees it.

Two properties this file relies on:

1. Each rejection test is paired with `test_a_genuine_operator_access_token_is_accepted`, the
   positive control — without it, a suite that only asserts rejection would pass just as happily
   if every request failed for an unrelated reason.

2. Every import happens inside the test functions, not at module scope. The `origin_app` fixture
   reloads `origin.config`, `origin.key_manager`, `auth_service`, and `auth_verifier`; a
   module-level import would bind to the pre-reload module and sign tokens with a key the rebuilt
   app no longer verifies against.
"""


OP = "operator-uuid-1234"


def _mint(**extra):
    """An operator token that is valid in every respect unless `extra` spoils it."""
    from origin import config
    from origin.services.auth_service import create_jwt_token

    d = {"sub": OP, "email": "op@example.com", "name": "Op",
         "client_id": "platform", "aud": config.AUTHORITY_ISSUER}
    d.update(extra)
    return create_jwt_token(d)


def _as_operator(monkeypatch):
    from origin.services.platform_settings_service import settings as platform_settings

    monkeypatch.setattr(platform_settings, "get",
                        lambda k, *a, **kw: OP if k == "platform.operator_id" else None)


def _get(client, tok):
    return client.get("/oracle/secrets", headers={"Authorization": f"Bearer {tok}"})


def test_a_genuine_operator_access_token_is_accepted(client, monkeypatch):
    """The positive control — without it, the rejection tests below prove nothing.

    `list_ids` is stubbed so this exercises the auth gate rather than the oracle's storage (the
    test DB has no `platform_settings` table).
    """
    from origin.services import key_oracle

    _as_operator(monkeypatch)
    monkeypatch.setattr(key_oracle, "list_ids", lambda db: [])
    r = _get(client, _mint())
    assert r.status_code == 200, \
        f"the genuine operator was refused by the Key Oracle ({r.status_code})"


def test_single_purpose_tokens_cannot_open_the_vault(client, monkeypatch):
    """A password-reset link is not a vault credential, even though it carries the operator's own
    `sub` and a valid signature — the same is true of an email-verify or refresh token.
    """
    _as_operator(monkeypatch)
    for token_type in ("pwd_reset", "email_verify", "refresh"):
        r = _get(client, _mint(token_type=token_type))
        assert r.status_code in (401, 403), \
            f"a {token_type!r} token was accepted by the Key Oracle ({r.status_code})"


def test_a_token_for_another_audience_cannot_open_the_vault(client, monkeypatch):
    """A third-party client authorized on its own audience does not reach Origin's vault.

    The confused-deputy half: `_require_operator` resolves the token through `resolve_auth`, so an
    `aud` naming someone else does not open it.
    """
    _as_operator(monkeypatch)
    r = _get(client, _mint(aud="evil-mcp"))
    assert r.status_code in (401, 403), \
        f"a token minted for another audience was accepted ({r.status_code})"


def test_a_non_operator_user_is_refused(client, monkeypatch):
    """Authentication is not authorization — a valid user token is still not the operator."""
    _as_operator(monkeypatch)
    r = _get(client, _mint(sub="some-other-user"))
    assert r.status_code == 403


def test_a_delegation_acting_for_the_operator_cannot_open_the_vault(client, monkeypatch):
    """A delegation acting for the operator does not open the vault.

    `resolve_auth` normalizes a delegation to `AuthContext(principal_type="user", user_id=sub,
    actor=act.sub)` before any router sees it, so a token with `sub=<operator_id>` and any
    non-empty `aud` arrives looking exactly like the operator's own session. `actor is not None` is
    the only thing that distinguishes them, and `_require_operator` checks it.

    The audience is an ordinary one (`seraph`), not a hostile-looking one: the property under test
    is that a legitimately minted delegation for a real persona does not open the vault, not that a
    malformed token doesn't. Personas holding delegations are a first-class caller of Origin.

    `test_a_genuine_operator_access_token_is_accepted` above is the positive control that keeps
    this honest; without it this assertion would still pass if every request here failed for an
    unrelated reason.
    """
    from origin.services import key_oracle

    _as_operator(monkeypatch)
    monkeypatch.setattr(key_oracle, "list_ids", lambda db: [])
    r = _get(client, _mint(principal_type="delegation", act={"sub": "chorus"}, aud="seraph"))
    assert r.status_code in (401, 403), \
        f"a DELEGATION acting for the operator opened the Key Oracle ({r.status_code})"
