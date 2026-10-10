"""Origin OTP router — email one-time-password login.

Backed by `origin.services.otp_service`.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from origin import config
from origin.db import persons as db_persons
from origin.db.session import get_db
from origin.services import email_service, otp_service
from origin.services.auth_service import create_jwt_token, person_token_claims
from origin.services.dependencies import kdf_admission
from origin.services.guess_budget import Identifier

logger = logging.getLogger(__name__)
otp_router = APIRouter(prefix="/auth/otp", tags=["Authentication"])


class OTPRequestBody(BaseModel):
    email: Identifier


class OTPRequestResponse(BaseModel):
    sent: bool
    expires_in: int = 600


class OTPVerifyBody(BaseModel):
    email: Identifier
    code: str


class OTPVerifyResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


@otp_router.post("/request", response_model=OTPRequestResponse,
                 dependencies=[Depends(kdf_admission, scope="function")])
async def request_otp(
    request: Request,
    body: OTPRequestBody,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Always `{"sent": true}`, for an unknown address, a known one, and one whose limits refuse
    another code; each spends one code hash, and the mail goes out after the response. Anything
    that differed between them — a status, a delay, a mail server's latency — would tell anyone,
    unauthenticated, whether an address holds an account here."""
    if not email_service.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Email service not configured. Use password login instead.",
        )

    from origin.routers.auth_router import _mail_sign_in_code

    await _mail_sign_in_code(request, background_tasks, db, otp_service.normalize_email(body.email))
    return OTPRequestResponse(sent=True)


@otp_router.post("/verify", response_model=OTPVerifyResponse,
                 dependencies=[Depends(kdf_admission, scope="function")])
async def verify_otp(
    body: OTPVerifyBody,
    db: Session = Depends(get_db),
):
    email = otp_service.normalize_email(body.email)
    person_id = await otp_service.verify_otp(db, email, body.code)
    if not person_id:
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    person = db_persons.get_by_id(db, person_id)
    if person is None:
        raise HTTPException(status_code=401, detail="User not found")

    # An OTP delivered to this address proves ownership — mark the email verified
    # so an account whose address is unverified is not left blocked.
    if not person.email_verified:
        person.email_verified = True

    user_data = person_token_claims(
        person, client_id=getattr(config, "PLATFORM_CLIENT_ID", "platform"),
    )
    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token({**user_data, "token_type": "refresh"}, expires_hours=24 * 30)
    db.commit()
    return OTPVerifyResponse(access_token=access_token, refresh_token=refresh_token)
