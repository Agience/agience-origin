"""Feedback from the Help panel's "Send feedback" (John, 2026-11-14): text, from anyone, filed as
an item in the platform's own "Feedback" collection, which Agience's team reads from Backlog ·
Incoming.

It is filed by the feedback account: its own identity, never a person's (FR-028), which owns the
Feedback collection and holds nothing anywhere else. Origin is that account's identity provider
and mints its Mantle token here; the account has no password anyone holds. `FEEDBACK_BOT_ID` and
`FEEDBACK_COLLECTION_ID` name them; without both, feedback is refused as unavailable, and the app
offers mail instead.

The request passes `feedback_intake.admit` (the sign-up form's FR-027 tests, a length cap, and
hourly ceilings) or nothing is filed; either way the answer is the same thank-you. The sender's
account id is filed with the text when the request carries their token.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from origin import config
from origin.db.session import get_db
from origin.services import feedback_intake, signup_guard

logger = logging.getLogger(__name__)

feedback_router = APIRouter(tags=["Feedback"])

THANKS = {"thanks": "Thank you. Your feedback was received."}


class FeedbackIn(BaseModel):
    text: str = ""
    #: The form's hidden field: a person never fills it in.
    website: str = ""
    form_token: str = ""


def _sender(request: Request) -> Optional[str]:
    """The signed-in sender's account id, from their bearer token, or None."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    from origin.services.auth_verifier import verify_token
    claims = verify_token(auth[7:].strip())
    return str(claims["sub"]) if claims and claims.get("sub") else None


def configured() -> tuple:
    return (os.getenv("FEEDBACK_BOT_ID", "").strip(), os.getenv("FEEDBACK_COLLECTION_ID", "").strip())


async def file_feedback(db: Session, text: str, sender: Optional[str]) -> bool:
    """File `text` in the Feedback collection as the feedback account. True when Mantle took it."""
    bot_id, collection = configured()
    mantle = (getattr(config, "MANTLE_URI", "") or "").rstrip("/")
    if not (bot_id and collection and mantle):
        return False
    from origin.db import persons as db_persons
    from origin.services import auth_service
    bot = db_persons.get_by_id(db, bot_id)
    if bot is None:
        logger.error("feedback: FEEDBACK_BOT_ID names no account; nothing filed")
        return False
    token = auth_service.issue_mantle_token(
        bot, client_id=getattr(config, "PLATFORM_CLIENT_ID", "") or "agience-client")
    at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = {
        "container_id": collection,
        "name": f"Feedback {at}",
        "description": text.splitlines()[0][:120],
        # Plain text: nothing a sender types becomes a link anywhere it is shown.
        "content_type": "text/plain",
        "content": text,
        "context": json.dumps({"type": "feedback", "received_at": at,
                               "from": sender or "signed out"}),
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(f"{mantle}/artifacts", json=body,
                                  headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as exc:
        logger.error("feedback: Mantle unreachable (%s); nothing filed", type(exc).__name__)
        return False
    if r.status_code not in (200, 201):
        logger.error("feedback: Mantle answered %s; nothing filed", r.status_code)
        return False
    logger.info("feedback filed (%d characters, %s)", len(text), "signed in" if sender else "signed out")
    return True


@feedback_router.get("/feedback/form")
async def feedback_form():
    """The token the feedback form fetches when it opens (FR-027). Unavailable while no feedback
    account is configured, so the app offers mail from the start."""
    if not all(configured()):
        return JSONResponse({"available": False}, status_code=503, headers={"Cache-Control": "no-store"})
    return JSONResponse({"available": True, "form_token": signup_guard.form_token()},
                        headers={"Cache-Control": "no-store"})


#: The most of a request's body read. Well above the longest feedback filed
#: (`feedback_intake.MAX_CHARS`, at most four bytes a character, plus the form's other fields), so a
#: real request always fits, and a body past it is not read further.
MAX_BODY_BYTES = 32 * 1024


async def _capped_body(request: Request) -> Optional[bytes]:
    """The request's body, or None when it declares or turns out larger than `MAX_BODY_BYTES`."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_BYTES:
                return None
        except ValueError:
            return None
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY_BYTES:
            return None
    return bytes(buf)


@feedback_router.post("/feedback")
async def feedback(request: Request, db: Session = Depends(get_db)):
    """File the feedback if the request is real; the same thank-you either way. 503 only when no
    feedback account is configured or Mantle did not take it, so the app can offer mail. The body
    is read only up to `MAX_BODY_BYTES`; one past it, or one that is not the form's, files
    nothing."""
    if not all(configured()):
        return JSONResponse({"available": False}, status_code=503)
    raw = await _capped_body(request)
    if raw is None:
        return THANKS
    try:
        body = FeedbackIn.model_validate_json(raw)
    except ValueError:
        return THANKS
    address = (request.client.host if request.client else "") or "-"
    text = feedback_intake.admit(body.text, body.website, body.form_token, address)
    if text is None:
        return THANKS
    if not await file_feedback(db, text, _sender(request)):
        return JSONResponse({"available": False}, status_code=503)
    return THANKS
