"""Origin /setup router — the first-boot wizard.

It covers the operator account and the platform settings Origin owns, and nothing else:

- No passkey registration during setup; the operator registers one after signing in.
- Connection validation covers email providers only. No model provider is validated here.

Anything a peer service needs seeded at first boot travels through the `manifest.yml` mechanism
instead, which each service applies to its own section at startup.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from origin import config
from origin.key_manager import delete_setup_token, get_setup_token
from origin.db import persons as db_persons
from origin.db.session import get_db
from origin.services.auth_service import create_jwt_token, hash_password
from origin.services.platform_settings_service import (
    is_secret_key,
    settings as platform_settings,
)

logger = logging.getLogger(__name__)
setup_router = APIRouter(prefix="/setup", tags=["Setup"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class SetupStatusResponse(BaseModel):
    """`GET /setup/status` — deliberately unauthenticated, therefore deliberately value-free.

    The route cannot be authenticated: a setup wizard has to learn whether setup is needed before
    any credential exists to present. So the constraint lands on the payload instead — every
    `env_defaults` entry answers *whether* a thing is configured, never *what* it is configured to.

    Mail settings in particular travel inside the process rather than through the browser:
    `/setup/complete` fills `email.smtp.host`, `.port` and `.username` from the environment when the
    wizard's payload omits them, as it does for `SMTP_PASSWORD` and the gmail client id. A wizard
    that never sees those values submits nothing for them and setup lands the same settings; an
    operator who types a value still overrides. `smtp_from` needs no injection —
    `email_service._from_address` falls back to `PLATFORM_EMAIL_ADDRESS` at read time.

    `bool | str` is in the type because `email_provider` is a provider *name*, not an account, and the
    wizard needs it to preselect the right form. Every other key is a bool.
    """

    needs_setup: bool
    ready: bool
    version: str
    env_defaults: dict[str, bool | str] = {}


class ValidateTokenRequest(BaseModel):
    token: str


class ValidateTokenResponse(BaseModel):
    valid: bool


class OperatorAccount(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    name: Optional[str] = None


class SettingInput(BaseModel):
    key: str
    value: str
    category: str
    is_secret: bool = False


class SetupCompleteRequest(BaseModel):
    operator: Optional[OperatorAccount] = None
    settings: list[SettingInput] = []


class SetupCompleteResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class ValidateConnectionRequest(BaseModel):
    service: str
    config: dict


class ValidateConnectionResponse(BaseModel):
    success: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _verify_setup_token(token: str) -> None:
    """Authorize a setup-wizard call: setup must be incomplete and the token must match.

    The token alone is not sufficient authorization — it can outlive setup. `delete_setup_token()`
    cannot unlink the token file when `KEYS_DIR` is read-only, which a managed deployment may
    make it: it logs a warning, clears the in-memory copy, and relies on DB state being
    authoritative on restart. That only holds for routes that consult the DB — on the next restart
    `init_setup_token()` reads the surviving file and the token is live again.

    Checking `needs_setup()` here, rather than trusting the token alone, is what keeps every route
    that calls this closed once setup completes — including `/validate-connection`, which posts to
    a caller-supplied `uri` and returns the body or `str(exc)`: reachable on a token alone, it would
    be a full-response SSRF and a credential-testing oracle for any API key a caller wants to check.
    """
    if not platform_settings.needs_setup():
        raise HTTPException(status_code=410, detail="Setup already completed")
    expected = get_setup_token()
    if not expected:
        raise HTTPException(status_code=410, detail="Setup already completed")
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="Invalid setup token")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@setup_router.get("/status", response_model=SetupStatusResponse)
async def get_setup_status():
    email_provider_env = os.getenv("EMAIL_PROVIDER", "")
    if not email_provider_env:
        if os.getenv("SMTP_HOST"):
            email_provider_env = "smtp"
        elif os.getenv("RESEND_API_KEY"):
            email_provider_env = "resend"
        elif os.getenv("SENDGRID_API_KEY"):
            email_provider_env = "sendgrid"
        elif os.getenv("GMAIL_OAUTH_REFRESH_TOKEN"):
            email_provider_env = "gmail"
    return SetupStatusResponse(
        needs_setup=platform_settings.needs_setup(),
        ready=not platform_settings.needs_setup(),
        version="origin",
        env_defaults={
            # `email_provider` names a provider, not an account — see SetupStatusResponse.
            "email_provider": email_provider_env,
            # Presence, not value. `smtp_port` is gone rather than reduced: a port carries no
            # presence signal worth reporting once the host it belongs to is not published.
            "smtp_has_host": bool(os.getenv("SMTP_HOST")),
            "smtp_has_username": bool(os.getenv("SMTP_USERNAME")),
            "smtp_has_from": bool(os.getenv("SMTP_FROM") or os.getenv("PLATFORM_EMAIL_ADDRESS")),
            "smtp_has_password": bool(os.getenv("SMTP_PASSWORD")),
            "resend_has_api_key": bool(os.getenv("RESEND_API_KEY")),
            "sendgrid_has_api_key": bool(os.getenv("SENDGRID_API_KEY")),
            "gmail_has_client": bool(os.getenv("GMAIL_OAUTH_CLIENT_ID")),
            "gmail_has_refresh_token": bool(os.getenv("GMAIL_OAUTH_REFRESH_TOKEN")),
        },
    )


@setup_router.post("/validate-token", response_model=ValidateTokenResponse)
async def validate_setup_token(body: ValidateTokenRequest):
    # Same reasoning as `_verify_setup_token`: a surviving token file on a
    # read-only mount would otherwise keep this confirming a live setup token
    # long after setup finished.
    if not platform_settings.needs_setup():
        raise HTTPException(status_code=410, detail="Setup already completed")
    expected = get_setup_token()
    if not expected:
        raise HTTPException(status_code=410, detail="Setup already completed")
    return ValidateTokenResponse(valid=secrets.compare_digest(body.token, expected))


@setup_router.post("/validate-connection", response_model=ValidateConnectionResponse)
async def validate_connection(
    body: ValidateConnectionRequest,
    x_setup_token: str = Header(..., alias="X-Setup-Token"),
):
    """Validate email provider configs.

    Origin validates email providers only. Anthropic / OpenAI / OpenRouter key validation is not
    implemented here, under the no-models rule: a remote model API is trained weights, whether
    reached directly or through a BYOK validator.
    """
    _verify_setup_token(x_setup_token)
    service = body.service.lower()
    cfg = body.config
    try:
        # Embeddings validation is not implemented here either, under the same no-models rule as
        # the provider branches above: a remote embedding model is trained weights (see
        # by any service in the platform).
        if service in ("smtp", "ses", "sendgrid", "resend", "gmail"):
            from origin.services.email_service import test_connection

            success, error = await test_connection({"provider": service, **cfg})
            return ValidateConnectionResponse(success=success, error=error)
        return ValidateConnectionResponse(
            success=False,
            error=(
                f"Service '{service}' not validated by Origin "
                "(use smtp / ses / sendgrid / resend / gmail)."
            ),
        )
    except Exception as exc:
        return ValidateConnectionResponse(success=False, error=str(exc))


@setup_router.post("/complete", response_model=SetupCompleteResponse)
async def complete_setup(
    body: SetupCompleteRequest,
    x_setup_token: str = Header(..., alias="X-Setup-Token"),
    db: Session = Depends(get_db),
):
    _verify_setup_token(x_setup_token)
    if not platform_settings.needs_setup():
        raise HTTPException(status_code=410, detail="Setup already completed")

    operator_id: Optional[str] = None
    access_token = ""
    refresh_token_str = ""
    op_email = ""
    person_name = ""

    if body.operator:
        if body.operator.password and len(body.operator.password) < 12:
            raise HTTPException(status_code=422, detail="Password must be at least 12 characters")
        password_hash = (
            hash_password(body.operator.password) if body.operator.password else None
        )
        op_email = (body.operator.email or "").lower() if body.operator.email else ""
        person_name = body.operator.name or (op_email.split("@")[0] if op_email else "operator")

        person = db_persons.create(
            db,
            {
                "email": op_email or None,
                "name": person_name,
                "username": person_name,
                "password_hash": password_hash,
            },
        )
        operator_id = str(person.id)

    # Write all settings
    settings_dicts: list[dict] = []
    for s in body.settings:
        # Classification is the server's, from the key. `s.is_secret` is only a hint from the
        # wizard; it cannot downgrade a sensitive key to plaintext — `set_many` re-derives the
        # classification either way.
        if is_secret_key(s.key) and not s.value:
            continue
        settings_dicts.append(
            {"key": s.key, "value": s.value, "category": s.category}
        )
    # Inject env-sourced email settings when not provided in the wizard payload.
    #
    # This is the server-side half of `/setup/status` publishing presence instead of values. Origin
    # already holds the platform's mail host and mailbox account, so it fills them in here and an
    # unauthenticated caller never has to be handed them to send them back.
    #
    # `email.from_address` is deliberately absent: `email_service._from_address` already falls back
    # to `PLATFORM_EMAIL_ADDRESS` at read time, so injecting it would write a setting whose only
    # effect is to shadow a fallback that already works.
    #
    # Same precedence as the secrets below and the gmail block further down — an explicit wizard
    # value always wins, and env fills only what the operator left blank.
    _email_provider_val = next((s.value for s in body.settings if s.key == "email.provider"), "")
    if _email_provider_val == "smtp":
        for _skey, _senv in (
            ("email.smtp.host", "SMTP_HOST"),
            ("email.smtp.port", "SMTP_PORT"),
            ("email.smtp.username", "SMTP_USERNAME"),
        ):
            if not any(s.key == _skey for s in body.settings):
                _sval = os.getenv(_senv, "")
                if _sval:
                    settings_dicts.append(
                        {"key": _skey, "value": _sval, "category": "email", "is_secret": False}
                    )
    if _email_provider_val == "smtp" and not any(s.key == "email.smtp.password" for s in body.settings):
        _smtp_password = os.getenv("SMTP_PASSWORD", "")
        if _smtp_password:
            settings_dicts.append({"key": "email.smtp.password", "value": _smtp_password, "category": "email", "is_secret": True})
    elif _email_provider_val == "resend" and not any(s.key == "email.resend.api_key" for s in body.settings):
        _resend_key = os.getenv("RESEND_API_KEY", "")
        if _resend_key:
            settings_dicts.append({"key": "email.resend.api_key", "value": _resend_key, "category": "email", "is_secret": True})
    elif _email_provider_val == "sendgrid" and not any(s.key == "email.sendgrid.api_key" for s in body.settings):
        _sendgrid_key = os.getenv("SENDGRID_API_KEY", "")
        if _sendgrid_key:
            settings_dicts.append({"key": "email.sendgrid.api_key", "value": _sendgrid_key, "category": "email", "is_secret": True})
    elif _email_provider_val == "gmail":
        # Gmail's dedicated OAuth client — pull any creds not supplied in the wizard
        # from GMAIL_OAUTH_* env so unattended / static-file setup works.
        for _gkey, _genv, _gsecret in (
            ("email.gmail.client_id", "GMAIL_OAUTH_CLIENT_ID", False),
            ("email.gmail.client_secret", "GMAIL_OAUTH_CLIENT_SECRET", True),
            ("email.gmail.refresh_token", "GMAIL_OAUTH_REFRESH_TOKEN", True),
        ):
            if not any(s.key == _gkey for s in body.settings):
                _gval = os.getenv(_genv, "")
                if _gval:
                    settings_dicts.append({"key": _gkey, "value": _gval, "category": "email", "is_secret": _gsecret})
    settings_dicts.append(
        {"key": "platform.setup_complete", "value": "true", "category": "platform", "is_secret": False}
    )
    if operator_id:
        settings_dicts.append(
            {"key": "platform.operator_id", "value": operator_id, "category": "platform", "is_secret": False}
        )
    platform_settings.set_many(db, settings_dicts, updated_by=operator_id)

    if not operator_id:
        # Carry the setup token forward for first-Google-sign-in promotion.
        raw_setup_token = get_setup_token()
        if raw_setup_token:
            platform_settings.set_value(
                db,
                "platform.setup_operator_token",
                raw_setup_token,
                is_secret=True,
                category="platform",
            )
    delete_setup_token()
    db.commit()

    if operator_id and body.operator:
        user_data = {
            "sub": operator_id,
            "email": op_email,
            "name": person_name,
            "picture": "",
            "roles": ["platform:admin"],
            "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
            "aud": config.AUTHORITY_ISSUER,
        }
        access_token = create_jwt_token(user_data)
        refresh_token_str = create_jwt_token(
            {**user_data, "token_type": "refresh"}, expires_hours=24 * 30
        )
        logger.info("Setup completed. Operator: %s (%s)", person_name, operator_id)
    else:
        logger.info("Setup completed. Operator captured on first OAuth sign-in.")

    return SetupCompleteResponse(access_token=access_token, refresh_token=refresh_token_str)
