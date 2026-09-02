"""What this authority may hand to a caller who has not earned it.

Three routes, three different callers, one question each — each test fails if the
corresponding disclosure comes back.

1. `GET /internal/persons/{id}` — a service token names a *service*, so the guard has to check
   which one. `principal_id` for a service principal IS the `iss` claim (`resolve_auth`), and
   `verify_token` will only reach the platform branch for an `iss` that has a trust anchor, so the
   name is signature-bound rather than caller-asserted. Pinned here: the guard rejects a service
   whose issuer is not an enrolled platform service, and `principal_id` keeps coming from `iss`.

   The service token is still unscoped — it names a service and no subject — so the route takes a
   second credential, `X-Subject-Token`, carrying the person's own Origin token exactly as
   `/internal/delegation-token` does. Pinned in the second class below: a presented token is
   verified, refused if it is not a live user token, and required to name the person in the path,
   on every setting. `PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED` governs only whether an ABSENT token is
   refused, and is off by default because Chorus's webhook mail path has none to forward.

   What this does not pin, because the default does not do it: with the flag off, a caller that
   sends no subject token still reads any person on its service token alone. That call is logged
   at WARNING naming the caller, and the log is what the flip is scheduled off.

2. `GET /setup/status` — unauthenticated by necessity (a wizard must learn whether setup is needed
   before a credential exists), so the payload carries presence, never values.

3. `POST /auth/passkey/login-options` — unauthenticated, and must answer an address with no account
   the same way it answers one with passkeys.
"""

from __future__ import annotations

import inspect

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def db_client(origin_app):
    """A client whose in-memory SQLite actually has tables.

    Mirrors `test_mcp_client_token_scoping.db_client`: `conftest.origin_app` skips migrations, so
    the schema is built from the models after lifespan has created the engine.
    """
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


# ---------------------------------------------------------------------------
# 1. /internal/persons/{id} — the caller must be a named platform service
# ---------------------------------------------------------------------------
class TestPersonLookupNamesTheService:
    def _ctx(self, **kw):
        from origin.services.dependencies import AuthContext

        return AuthContext(**kw)

    def _call_guard(self, auth):
        from fastapi import HTTPException

        from origin.routers.auth_router import _require_platform_server

        try:
            _require_platform_server(auth)
        except HTTPException as exc:
            return exc.status_code, exc.detail
        return 200, None

    def test_an_enrolled_platform_service_passes(self):
        """Positive control — the guard is not simply refusing everything."""
        for name in ("mantle", "chorus", "crystal"):
            status, _ = self._call_guard(
                self._ctx(principal_id=name, principal_type="service")
            )
            assert status == 200, f"{name} is a platform caller and must pass"

    def test_a_service_token_from_an_unenrolled_issuer_is_refused(self):
        """The exposure: `principal_type == "service"` alone must not be the whole test.

        Without the issuer check, any holder of any token this authority accepts as a service
        reads any person's email, name and identity records.
        """
        status, detail = self._call_guard(
            self._ctx(principal_id="evilcorp", principal_type="service")
        )
        assert status == 403, (
            "a service token whose issuer is not an enrolled platform service reached the "
            "person lookup — principal_type is being treated as sufficient"
        )
        assert "platform service" in str(detail).lower()

    def test_an_empty_issuer_is_refused(self):
        """A token with no `iss` resolves to `principal_id=""`; the empty string is not a name."""
        status, _ = self._call_guard(self._ctx(principal_id="", principal_type="service"))
        assert status == 403

    @pytest.mark.parametrize("ptype", ["user", "mcp_client", "server", "delegation"])
    def test_non_service_principals_are_refused(self, ptype):
        status, _ = self._call_guard(self._ctx(principal_id="mantle", principal_type=ptype))
        assert status == 403

    def test_the_allowlist_matches_the_issuers_the_verifier_will_accept(self):
        """The guard's list and `verify_token`'s dispatch tuple are one decision in two places.

        Drift is fail-closed either way, but a name in only one of them produces a 401/403 that
        looks like a bug in the caller rather than an incomplete enrolment here.
        """
        from origin.routers.auth_router import _PLATFORM_SERVICES
        from origin.services import auth_verifier

        src = inspect.getsource(auth_verifier.verify_token)
        line = next(ln for ln in src.splitlines() if "if iss in (" in ln)
        verifier_names = set(
            n.strip().strip("\"'") for n in line.split("(", 1)[1].rstrip("):").split(",") if n.strip()
        )
        assert verifier_names == set(_PLATFORM_SERVICES), (
            f"verify_token accepts {sorted(verifier_names)} but the /internal guard allows "
            f"{sorted(_PLATFORM_SERVICES)}"
        )

    def test_the_allowlist_is_not_derived_from_the_trust_anchors(self):
        """Authentication must not stand in for authorization.

        The manifest carries an anchor for `origin` itself and the installer merges new anchors in
        additively on upgrade, so `set(trust_anchors)` as the allowlist would promote every future
        anchor — and Origin — to a reader of every person's PII.
        """
        from origin.routers.auth_router import _PLATFORM_SERVICES

        assert "origin" not in _PLATFORM_SERVICES

    def test_principal_id_for_a_service_is_the_iss_claim(self):
        """The guard's subject must stay signature-bound.

        `verify_token` routes a platform `iss` to the inline JWKS registered for that exact
        service, so `iss` cannot be set by the caller without the matching private key. If
        `principal_id` were ever populated from a soft claim (`sub`, `client_id`) instead, the
        check above would become caller-asserted and this fails.
        """
        from origin.services import dependencies as _deps

        src = inspect.getsource(_deps.resolve_auth)
        head, _, tail = src.partition('if jwt_principal_type == "service":')
        assert tail, "the service branch of resolve_auth has moved"
        service_branch = tail.split("if jwt_principal_type ==")[0]
        assert 'principal_id=str(payload.get("iss", ""))' in service_branch, (
            "a service principal's id no longer comes from the signature-bound `iss` claim"
        )


# ---------------------------------------------------------------------------
# 1b. /internal/persons/{id} — the caller must also say on whose behalf
# ---------------------------------------------------------------------------
class TestPersonLookupNamesTheSubject:
    """The second credential: `X-Subject-Token`, and what the flag does and does not govern.

    The service token above answers "which service is asking". It cannot answer "may this caller
    read person X", because it carries no subject at all. So the route takes the person's own
    Origin token in a header — the same credential `/internal/delegation-token` takes in its body,
    verified the same way, refused the same way.

    Every case here runs through the real route over HTTP with a real person row; only the two
    token verifications are stubbed (`verify_token`), matching `test_delegation_token`.
    """

    _CALLER = "mantle"

    @pytest.fixture
    def person_id(self, db_client) -> str:
        from origin.db import persons as db_persons
        from origin.db.session import SessionLocal

        with SessionLocal() as db:
            person = db_persons.create(
                db, {"email": "subject@example.invalid", "name": "Subject", "username": "subject"}
            )
            pid = str(person.id)
            db.commit()
        return pid

    @pytest.fixture
    def as_platform(self, origin_app):
        """Authenticate every request in the test as the `mantle` platform service."""
        from origin.services.dependencies import AuthContext, get_auth

        origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
            principal_id=self._CALLER, principal_type="service", user_id=None,
        )
        yield
        origin_app.dependency_overrides.pop(get_auth, None)

    @staticmethod
    def _set_flag(monkeypatch, value: bool):
        from origin.routers import auth_router

        monkeypatch.setattr(
            auth_router.config, "PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED", value, raising=False
        )

    @staticmethod
    def _subject_claims(claims):
        """Stub the subject-token verification with the claims a real token would carry."""
        from unittest.mock import patch

        from origin.routers import auth_router

        return patch.object(auth_router, "verify_token", return_value=claims)

    # -- the default: today's behaviour, plus a record of it ------------------
    def test_off_and_absent_is_the_behaviour_a_node_already_has(
        self, db_client, person_id, as_platform, monkeypatch, caplog
    ):
        """A node that upgrades and changes nothing keeps working — this is Chorus's call."""
        self._set_flag(monkeypatch, False)
        with caplog.at_level("WARNING"):
            resp = db_client.get(f"/internal/persons/{person_id}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["email"] == "subject@example.invalid"

    def test_off_and_absent_logs_the_caller_that_still_needs_updating(
        self, db_client, person_id, as_platform, monkeypatch, caplog
    ):
        """The audit line the flip is scheduled off.

        An operator greps `unscoped person lookup` and reads `caller=`; when nothing new appears,
        turning the flag on refuses nobody. The caller has to be IN the line — a warning that says
        only "someone did this" cannot be acted on.
        """
        self._set_flag(monkeypatch, False)
        with caplog.at_level("WARNING"):
            db_client.get(f"/internal/persons/{person_id}")
        line = next(
            (r.getMessage() for r in caplog.records if "unscoped person lookup" in r.getMessage()),
            None,
        )
        assert line is not None, "a subject-less read left no trace for an operator to grep"
        assert f"caller={self._CALLER}" in line
        assert person_id in line

    def test_off_and_present_is_honoured_without_waiting_for_the_flip(
        self, db_client, person_id, as_platform, monkeypatch, caplog
    ):
        """Mantle ships the header before the flag moves, and gets the tighter rule immediately."""
        self._set_flag(monkeypatch, False)
        with self._subject_claims({"sub": person_id}), caplog.at_level("WARNING"):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "user.jwt"}
            )
        assert resp.status_code == 200, resp.text
        assert not [r for r in caplog.records if "unscoped person lookup" in r.getMessage()], (
            "a caller that presented a subject token was still logged as a straggler"
        )

    # -- the case that matters: A's token, B's record ------------------------
    def test_off_and_a_token_for_another_person_is_refused(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        """Holding user A's token is not authority over user B.

        Chorus is a gateway and holds user tokens routinely. Without this check, presenting one and
        naming someone else in the path is the unscoped read with an extra step, not a closed gap —
        so the mismatch is refused on BOTH settings of the flag.
        """
        self._set_flag(monkeypatch, False)
        with self._subject_claims({"sub": "00000000-0000-4000-8000-00000000000b"}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "other.jwt"}
            )
        assert resp.status_code == 403, resp.text
        assert "does not name the requested person" in resp.json()["detail"]

    def test_a_mismatch_is_refused_before_the_person_is_looked_up(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        """The refusal must not double as an existence oracle.

        A 404 here for an absent id and a 403 for a present one would let a caller holding any one
        user's token enumerate which person ids exist.
        """
        self._set_flag(monkeypatch, False)
        absent = "00000000-0000-4000-8000-0000000000ff"
        with self._subject_claims({"sub": person_id}):
            present = db_client.get(
                f"/internal/persons/{'00000000-0000-4000-8000-00000000000b'}",
                headers={"X-Subject-Token": "user.jwt"},
            )
            missing = db_client.get(
                f"/internal/persons/{absent}", headers={"X-Subject-Token": "user.jwt"}
            )
        assert present.status_code == missing.status_code == 403, (
            f"existent and non-existent ids answered differently: "
            f"{present.status_code} vs {missing.status_code}"
        )

    def test_the_same_id_in_the_other_case_is_the_same_person(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        """`get_by_id` resolves through `uuid.UUID`, so the match has to as well.

        A raw string comparison would 403 a correct caller whose token spells the UUID in upper
        case — a refusal indistinguishable, in a log, from the attack above.
        """
        self._set_flag(monkeypatch, False)
        with self._subject_claims({"sub": person_id.upper()}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "user.jwt"}
            )
        assert resp.status_code == 200, resp.text

    # -- the refusals are /internal/delegation-token's, unconditionally ------
    def test_an_invalid_subject_token_is_refused_even_with_the_flag_off(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        self._set_flag(monkeypatch, False)
        with self._subject_claims(None):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "garbage"}
            )
        assert resp.status_code == 401, resp.text

    def test_a_service_token_is_not_a_subject(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        """Otherwise a caller re-asserts its own unscoped identity as authority over the path."""
        self._set_flag(monkeypatch, False)
        with self._subject_claims({"sub": "chorus", "principal_type": "service"}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "svc.jwt"}
            )
        assert resp.status_code == 403, resp.text

    @pytest.mark.parametrize("ptype", ["service", "server", "delegation"])
    def test_no_non_user_principal_is_a_subject(
        self, db_client, person_id, as_platform, monkeypatch, ptype
    ):
        self._set_flag(monkeypatch, False)
        with self._subject_claims({"sub": person_id, "principal_type": ptype}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "x.jwt"}
            )
        assert resp.status_code == 403, resp.text

    def test_a_subject_token_with_no_subject_is_refused(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        self._set_flag(monkeypatch, False)
        with self._subject_claims({"aud": "origin"}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "nosub.jwt"}
            )
        assert resp.status_code == 400, resp.text

    def test_the_two_routes_share_one_non_user_principal_list(self):
        """One credential, one definition of "not a person".

        `/internal/delegation-token` and the person lookup both refuse a non-user subject token. If
        they ever refused different sets, a token rejected by one would be accepted by the other.
        """
        from origin.routers import auth_router

        src = inspect.getsource(auth_router)
        assert src.count("_NON_USER_PRINCIPALS = {") == 1, (
            "the non-user principal list has been forked; the two routes can now disagree"
        )
        assert auth_router._NON_USER_PRINCIPALS == {"service", "server", "delegation"}

    # -- the flag on ---------------------------------------------------------
    def test_on_and_absent_is_refused(self, db_client, person_id, as_platform, monkeypatch):
        self._set_flag(monkeypatch, True)
        resp = db_client.get(f"/internal/persons/{person_id}")
        assert resp.status_code == 403, resp.text
        assert "X-Subject-Token" in resp.json()["detail"], (
            "the refusal must name the header the caller is missing"
        )

    def test_on_and_present_still_works(self, db_client, person_id, as_platform, monkeypatch):
        self._set_flag(monkeypatch, True)
        with self._subject_claims({"sub": person_id}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "user.jwt"}
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == person_id

    def test_on_and_a_token_for_another_person_is_still_refused(
        self, db_client, person_id, as_platform, monkeypatch
    ):
        self._set_flag(monkeypatch, True)
        with self._subject_claims({"sub": "00000000-0000-4000-8000-00000000000b"}):
            resp = db_client.get(
                f"/internal/persons/{person_id}", headers={"X-Subject-Token": "other.jwt"}
            )
        assert resp.status_code == 403, resp.text

    def test_the_service_check_is_not_weakened_by_either_setting(
        self, db_client, person_id, origin_app, monkeypatch
    ):
        """A subject token is an ADDITIONAL constraint, never a substitute for being a platform
        service — a third party holding a user's own token must still be refused."""
        from origin.services.dependencies import AuthContext, get_auth

        origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
            principal_id="evilcorp", principal_type="service", user_id=None,
        )
        try:
            for flag in (False, True):
                self._set_flag(monkeypatch, flag)
                with self._subject_claims({"sub": person_id}):
                    resp = db_client.get(
                        f"/internal/persons/{person_id}",
                        headers={"X-Subject-Token": "user.jwt"},
                    )
                assert resp.status_code == 403, f"flag={flag}: {resp.text}"
        finally:
            origin_app.dependency_overrides.pop(get_auth, None)

    # -- the setting itself --------------------------------------------------
    @staticmethod
    def _flag_from_env(monkeypatch, raw) -> bool:
        """Reload `origin.config` under one env value and hand back what it resolved to.

        Restores the module afterwards: `origin.config` is a shared module object and a reload
        mutates it in place, so leaving it holding this test's environment would set the default
        for whatever ran next.
        """
        import importlib

        import origin.config as cfg

        if raw is None:
            monkeypatch.delenv("PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED", raising=False)
        else:
            monkeypatch.setenv("PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED", raw)
        try:
            return importlib.reload(cfg).PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED
        finally:
            monkeypatch.delenv("PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED", raising=False)
            importlib.reload(cfg)

    def test_the_default_is_todays_behaviour(self, monkeypatch):
        """A node that upgrades and sets nothing must not start refusing calls."""
        assert self._flag_from_env(monkeypatch, None) is False

    @pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on"])
    def test_the_environment_turns_it_on(self, monkeypatch, raw):
        """Configuration, read the way every other boolean in `config` is read."""
        assert self._flag_from_env(monkeypatch, raw) is True

    def test_the_env_example_documents_the_flag_and_its_audit_line(self):
        """The flip is an operator action, and it is only safe if the log to check is written down."""
        from pathlib import Path

        import origin

        text = (Path(origin.__file__).resolve().parents[2] / ".env.example").read_text(
            encoding="utf-8"
        )
        assert "PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED" in text
        assert "unscoped person lookup" in text, (
            ".env.example names the flag but not the log an operator greps before flipping it"
        )


# ---------------------------------------------------------------------------
# 2. /setup/status — presence, never values
# ---------------------------------------------------------------------------
#: Env vars whose VALUES this unauthenticated route must never echo. Each is set to a marker below
#: and the whole response is searched for it, so a new key that happens to carry one of these fails
#: without anyone remembering to extend a field list.
_MUST_NOT_APPEAR = {
    "SMTP_USERNAME": "postmaster@leaked.invalid",
    "SMTP_FROM": "no-reply@leaked.invalid",
    "SMTP_HOST": "mail.leaked.invalid",
    "SMTP_PASSWORD": "leaked-smtp-password",
    "RESEND_API_KEY": "re_leaked_key",
    "SENDGRID_API_KEY": "SG.leaked_key",
    "GMAIL_OAUTH_CLIENT_ID": "leaked-client-id.apps.googleusercontent.com",
    "GMAIL_OAUTH_REFRESH_TOKEN": "1//leaked-refresh-token",
    "PLATFORM_EMAIL_ADDRESS": "platform@leaked.invalid",
}


class TestSetupStatusPublishesNoValues:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        for k, v in _MUST_NOT_APPEAR.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("EMAIL_PROVIDER", "smtp")

    def test_no_configured_value_appears_in_the_body(self, client: TestClient):
        resp = client.get("/setup/status")
        assert resp.status_code == 200
        body = resp.text
        for var, marker in _MUST_NOT_APPEAR.items():
            assert marker not in body, (
                f"GET /setup/status published the value of {var} to an unauthenticated caller"
            )

    def test_every_env_default_is_a_bool_except_the_provider_name(self, client: TestClient):
        """The shape that makes the above hold for keys nobody has added yet.

        `email_provider` is the one string, and it names a provider rather than an account.
        """
        env_defaults = client.get("/setup/status").json()["env_defaults"]
        for key, value in env_defaults.items():
            if key == "email_provider":
                assert value in ("", "smtp", "resend", "sendgrid", "gmail")
                continue
            assert isinstance(value, bool), (
                f"env_defaults[{key!r}] is {type(value).__name__}, not bool — this route is "
                "unauthenticated, so a non-bool is a published value"
            )

    def test_it_still_reports_whether_mail_is_configured(self, client: TestClient):
        """Positive control: the wizard's actual question is still answered."""
        env_defaults = client.get("/setup/status").json()["env_defaults"]
        assert env_defaults["email_provider"] == "smtp"
        assert env_defaults["smtp_has_host"] is True
        assert env_defaults["smtp_has_username"] is True
        assert env_defaults["smtp_has_password"] is True

    def test_setup_complete_supplies_what_status_stopped_publishing(
        self, db_client: TestClient, monkeypatch
    ):
        """The other half of the change: values travel in-process instead of through the browser.

        Chorus's wizard read `smtp_host`/`smtp_port`/`smtp_username` from `/setup/status` and
        submitted them back. With the route publishing presence only, a wizard submits nothing for
        them — so `/setup/complete` must fill them from the environment, or setup completes with no
        SMTP host and mail silently stops working. Pinned here because the wizard lives in another
        repo and cannot fail this suite.
        """
        from origin.routers import setup_router as sr

        captured: dict[str, str] = {}

        def _capture(db, items, updated_by=None):
            captured.update({i["key"]: i["value"] for i in items})

        monkeypatch.setattr(sr, "get_setup_token", lambda: "tok")
        monkeypatch.setattr(sr.platform_settings, "needs_setup", lambda: True)
        monkeypatch.setattr(sr.platform_settings, "set_many", _capture)

        resp = db_client.post(
            "/setup/complete",
            headers={"X-Setup-Token": "tok"},
            # Exactly what a wizard sends once it can no longer read the values back.
            json={"settings": [{"key": "email.provider", "value": "smtp", "category": "email"}]},
        )
        assert resp.status_code == 200, resp.text
        assert captured.get("email.smtp.host") == _MUST_NOT_APPEAR["SMTP_HOST"]
        assert captured.get("email.smtp.username") == _MUST_NOT_APPEAR["SMTP_USERNAME"]
        assert captured.get("email.smtp.password") == _MUST_NOT_APPEAR["SMTP_PASSWORD"]

    def test_an_operator_typed_value_still_wins_over_env(
        self, db_client: TestClient, monkeypatch
    ):
        """Env fills blanks; it never overrides what the operator actually entered."""
        from origin.routers import setup_router as sr

        captured: dict[str, str] = {}
        monkeypatch.setattr(sr, "get_setup_token", lambda: "tok")
        monkeypatch.setattr(sr.platform_settings, "needs_setup", lambda: True)
        monkeypatch.setattr(
            sr.platform_settings,
            "set_many",
            lambda db, items, updated_by=None: captured.update(
                {i["key"]: i["value"] for i in items}
            ),
        )

        resp = db_client.post(
            "/setup/complete",
            headers={"X-Setup-Token": "tok"},
            json={
                "settings": [
                    {"key": "email.provider", "value": "smtp", "category": "email"},
                    {"key": "email.smtp.host", "value": "typed.example.com", "category": "email"},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        assert captured.get("email.smtp.host") == "typed.example.com"

    def test_absent_mail_config_reports_false(self, client: TestClient, monkeypatch):
        for k in _MUST_NOT_APPEAR:
            monkeypatch.delenv(k, raising=False)
        monkeypatch.delenv("EMAIL_PROVIDER", raising=False)
        env_defaults = client.get("/setup/status").json()["env_defaults"]
        assert env_defaults["smtp_has_host"] is False
        assert env_defaults["smtp_has_username"] is False
        assert env_defaults["smtp_has_password"] is False


# ---------------------------------------------------------------------------
# 3. /auth/passkey/login-options — no account-existence oracle
# ---------------------------------------------------------------------------
class TestPasskeyLoginOptionsIsNotAnOracle:
    """The response for an address with no account must be indistinguishable from one with keys.

    `otp_router.request_otp` and `/auth/email/verify-request` already answer unknown addresses
    identically; these pin that this route agrees with them.
    """

    _UNKNOWN = "nobody-here@example.invalid"
    _ALSO_UNKNOWN = "someone-else@example.invalid"

    def test_an_unknown_address_still_gets_a_challenge(self, db_client: TestClient):
        resp = db_client.post("/auth/passkey/login-options", json={"email": self._UNKNOWN})
        assert resp.status_code == 200
        body = resp.json()
        assert body["has_passkeys"] is True, (
            "has_passkeys=False for an unknown address is a yes/no membership test against the "
            "user table, runnable by anyone"
        )
        assert body["options"] is not None
        assert body["options"]["allowCredentials"], (
            "an empty allowCredentials for an unknown address is the same oracle in a new shape"
        )

    def test_the_response_shape_matches_the_real_one(self, db_client: TestClient):
        body = db_client.post(
            "/auth/passkey/login-options", json={"email": self._UNKNOWN}
        ).json()["options"]
        assert set(body) == {
            "challenge",
            "rpId",
            "timeout",
            "allowCredentials",
            "userVerification",
        }
        for cred in body["allowCredentials"]:
            assert set(cred) == {"id", "type", "transports"}
            assert cred["type"] == "public-key"

    def test_a_decoy_is_field_for_field_indistinguishable_from_a_real_response(
        self, db_client: TestClient
    ):
        """Compare a decoy against a genuine response from a seeded account.

        The first version of this decoy failed exactly here: it minted its own 32-byte challenge
        while `generate_authentication_options` mints 64, so every non-account was identifiable by
        response length without looking at anything else. Both paths now go through one builder and
        one serializer; this is what keeps them there.
        """
        import base64
        import uuid

        from origin.db import passkey_credentials as db_passkeys
        from origin.db import persons as db_persons
        from origin.db.session import SessionLocal

        email = "real-account@example.invalid"
        with SessionLocal() as db:
            person = db_persons.create(
                db, {"email": email, "name": "Real", "username": "real"}
            )
            db_passkeys.create(
                db,
                {
                    # 32 raw bytes, the width a platform authenticator returns.
                    "id": base64.urlsafe_b64encode(uuid.uuid4().bytes * 2)
                    .rstrip(b"=")
                    .decode(),
                    "person_id": str(person.id),
                    "public_key": b"\x00" * 32,
                    "sign_count": 0,
                    "transports": ["internal", "hybrid"],
                    "device_name": "Seeded",
                },
            )
            db.commit()

        real = db_client.post("/auth/passkey/login-options", json={"email": email}).json()
        decoy = db_client.post(
            "/auth/passkey/login-options", json={"email": self._UNKNOWN}
        ).json()

        assert real["has_passkeys"] == decoy["has_passkeys"] is True
        assert set(real["options"]) == set(decoy["options"])
        assert len(real["options"]["challenge"]) == len(decoy["options"]["challenge"]), (
            "challenge length differs between a real account and a non-account — the response "
            "size alone is an enumeration oracle"
        )
        assert real["options"]["rpId"] == decoy["options"]["rpId"]
        assert real["options"]["timeout"] == decoy["options"]["timeout"]
        assert real["options"]["userVerification"] == decoy["options"]["userVerification"]
        # Credential ids must be the same width; a short or long decoy id is a tell.
        assert {len(c["id"]) for c in real["options"]["allowCredentials"]} == {
            len(c["id"]) for c in decoy["options"]["allowCredentials"]
        }

    def test_decoy_credentials_are_stable_across_calls(self, db_client: TestClient):
        """A real account's credential ids do not change between calls, so decoys must not.

        Randomly regenerated ids would out a non-account to anyone who asked twice, which is the
        oracle again with an extra request.
        """
        first, second = (
            db_client.post("/auth/passkey/login-options", json={"email": self._UNKNOWN}).json()[
                "options"
            ]["allowCredentials"]
            for _ in range(2)
        )
        assert [c["id"] for c in first] == [c["id"] for c in second]

    def test_the_challenge_is_fresh_every_call(self, db_client: TestClient):
        """The one field a real response varies, so the decoy must vary it too."""
        challenges = {
            db_client.post("/auth/passkey/login-options", json={"email": self._UNKNOWN}).json()[
                "options"
            ]["challenge"]
            for _ in range(3)
        }
        assert len(challenges) == 3

    def test_different_addresses_get_different_decoys(self, db_client: TestClient):
        a, b = (
            db_client.post("/auth/passkey/login-options", json={"email": e}).json()["options"][
                "allowCredentials"
            ]
            for e in (self._UNKNOWN, self._ALSO_UNKNOWN)
        )
        assert [c["id"] for c in a] != [c["id"] for c in b]

    def test_case_variants_of_one_address_agree(self, db_client: TestClient):
        """`db_persons.get_by_email` resolves these to one row, so the decoys must too."""
        a, b = (
            db_client.post("/auth/passkey/login-options", json={"email": e}).json()["options"][
                "allowCredentials"
            ]
            for e in (self._UNKNOWN, self._UNKNOWN.upper())
        )
        assert [c["id"] for c in a] == [c["id"] for c in b]

    def test_decoys_are_unpredictable_without_the_server_key(self, monkeypatch):
        """Derived under a server-held key, not from the address alone.

        Decoys computable from public input would let a prober recompute the expected list and
        compare — restoring the oracle for anyone who read this file.
        """
        from origin.services import passkey_service

        monkeypatch.setattr(passkey_service, "_decoy_secret", lambda: b"key-one")
        one = passkey_service.get_decoy_authentication_options(self._UNKNOWN)
        monkeypatch.setattr(passkey_service, "_decoy_secret", lambda: b"key-two")
        two = passkey_service.get_decoy_authentication_options(self._UNKNOWN)
        assert [c["id"] for c in one["allowCredentials"]] != [
            c["id"] for c in two["allowCredentials"]
        ]

    def test_no_secret_refuses_rather_than_falling_back(self, monkeypatch):
        """With no key there is no unpredictable decoy, so the service declines to invent one."""
        from origin.services import passkey_service

        monkeypatch.setattr(passkey_service, "_decoy_secret", lambda: b"")
        assert passkey_service.get_decoy_authentication_options(self._UNKNOWN) is None

    def test_the_decoy_key_is_one_the_node_actually_loads(self):
        """The branch above must stay unreachable on a serving node.

        `_decoy_secret` derives from `key_manager.get_nonce_secret()`, which `main.lifespan` loads
        from disk and which raises on a missing file — so it is present wherever Origin serves at
        all. Deriving from anything Origin populates lazily would send every passkey login, real
        and decoy, to the 503.
        """
        from origin.services import passkey_service

        assert passkey_service._decoy_secret(), (
            "_decoy_secret() is empty on a booted node — passkey login is 503ing"
        )
