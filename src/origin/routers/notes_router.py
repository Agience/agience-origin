"""Approval requests: an account files a request against a workspace or collection, an admin of it
decides on Origin's page, and the agent spends the note it gets.

- `POST /notes/requests` and `GET /notes/requests/{id}`: any signed-in account (a person's or an
  agent's own, FR-028) files a request with a bearer access token against a resource it can read,
  and reads back any request it can see.
- `/notes/page/*`: the approvals page at `/approvals`. These routes take no bearer token: only an
  Origin session, sent from Origin's own page, with a per-form token bound to that session. Whoever
  holds admin on the request's resource decides it; anyone who can read the resource sees it.
- `POST /notes/spend`: whoever holds a note spends it once per action. The note is the only
  credential the route reads.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from origin import config
from origin.db.session import get_db
from origin.services import chair_notes as notes
from origin.services import origin_session
from origin.services.dependencies import AuthContext, get_auth

notes_router = APIRouter(prefix="/notes", tags=["Approvals"])

def _refused(e: notes.NoteRefused) -> JSONResponse:
    return JSONResponse({"detail": e.detail}, status_code=e.status,
                        headers={"Cache-Control": "no-store"})


def _account(auth: AuthContext) -> str:
    if not auth.user_id or auth.principal_type != "user":
        raise HTTPException(status_code=401, detail="sign in to file a request")
    return str(auth.user_id)


# --- filing ---------------------------------------------------------------------------------------

@notes_router.post("/requests", status_code=201)
async def file_request(request: Request, auth: AuthContext = Depends(get_auth),
                       db: Session = Depends(get_db)):
    account = _account(auth)
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="the request is JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="the request is a JSON object")
    from origin.services import person_service
    person = person_service.get_user_by_id(db, account)
    name = (getattr(person, "name", None) or getattr(person, "email", None) or account) \
        if person is not None else account
    try:
        req = notes.file_request(db, filer_id=account, filer_name=str(name), body=body)
    except notes.NoteRefused as e:
        return _refused(e)
    return JSONResponse({"id": req.id, "digest": req.digest, "level": req.level,
                         "resource": req.resource_id,
                         "expires": notes.request_view(db, req)["expires"],
                         "page": f"/approvals?req={req.id}"}, status_code=201)


@notes_router.get("/requests/{req_id}")
def read_request(req_id: str, auth: AuthContext = Depends(get_auth),
                 db: Session = Depends(get_db)):
    account = _account(auth)
    req = notes.get_request(db, req_id)
    if req is None or not notes.can_see(db, account, req):
        raise HTTPException(status_code=404, detail="no such request")
    return JSONResponse(notes.request_view(db, req), headers={"Cache-Control": "no-store"})


# --- the approvals page -------------------------------------------------------------------------------

def _form_token(session_digest: str, subject: str) -> str:
    from origin.key_manager import get_nonce_secret
    secret = get_nonce_secret()
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, f"chair-form|{session_digest}|{subject}".encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _session(request: Request, db: Session):
    """The viewer's live Origin session on Origin's own page, or a refusal."""
    from origin.routers.auth_router import on_origin_s_own_page
    if not on_origin_s_own_page(request):
        raise HTTPException(status_code=403, detail="approvals are made on Origin's own page")
    row = origin_session.session_of(request, db)
    if row is None:
        raise HTTPException(status_code=401, detail="sign in at Origin")
    return row


def _check_form(request: Request, row, subject: str, token: Optional[str]) -> None:
    want = _form_token(row.id_sha256, subject)
    if not token or not hmac.compare_digest(want, str(token)):
        raise HTTPException(status_code=403, detail="this form has expired; reload the page")


def _page_view(db: Session, row, req) -> dict:
    """A request as the page shows it: whether the viewer can decide it, its form, and a revoke form
    for an unspent note."""
    v = notes.request_view(db, req)
    v["can_decide"] = notes.can_approve(db, row.person_id, req)
    v["form"] = _form_token(row.id_sha256, req.id)
    if v["can_decide"] and v.get("note_jti") and not v.get("revoked") and not v.get("spent"):
        v["revoke_form"] = _form_token(row.id_sha256, "revoke:" + v["note_jti"])
    return v


@notes_router.get("/page/state")
def page_state(request: Request, db: Session = Depends(get_db)):
    row = _session(request, db)
    views = [_page_view(db, row, req) for req in notes.pending_for(db, row.person_id)]
    live = [{"jti": n.jti, "req": n.req, "level": n.level,
             "expires": notes._aware(n.expires_time).isoformat(),
             "form": _form_token(row.id_sha256, "revoke:" + n.jti)}
            for n in notes.live_notes(db, row.person_id)]
    return JSONResponse({"pending": views, "notes": live, "app_uri": config.APP_URI or "/",
                         "revoke_all_form": _form_token(row.id_sha256, "revoke-all"),
                         "sign_out_form": _form_token(row.id_sha256, "sign-out-everywhere")},
                        headers={"Cache-Control": "no-store"})


@notes_router.get("/page/requests/{req_id}")
def page_request(req_id: str, request: Request, db: Session = Depends(get_db)):
    row = _session(request, db)
    req = notes.get_request(db, req_id)
    if req is None:
        raise HTTPException(status_code=404, detail="no such request")
    if not notes.can_see(db, row.person_id, req):
        # The refusal names nothing of the request: its details are for viewers who can see it.
        return JSONResponse({"detail": notes.CANNOT_APPROVE, "app_uri": config.APP_URI or "/"},
                            status_code=403, headers={"Cache-Control": "no-store"})
    return JSONResponse(_page_view(db, row, req), headers={"Cache-Control": "no-store"})


class Decision(BaseModel):
    req: str
    decision: str
    digest: str
    form: str
    reason: Optional[str] = None
    option: Optional[str] = None


@notes_router.post("/page/decide")
def decide(body: Decision, request: Request, db: Session = Depends(get_db)):
    row = _session(request, db)
    _check_form(request, row, body.req, body.form)
    req = notes.get_request(db, body.req)
    try:
        if body.decision == "approve":
            req = notes.approve(db, req, person_id=row.person_id, digest=body.digest,
                                auth_time=row.auth_time or row.created_time,
                                amr=list(row.amr or []), option=body.option)
        elif body.decision == "decline":
            req = notes.decline(db, req, person_id=row.person_id, digest=body.digest,
                                reason=body.reason or "")
        else:
            raise HTTPException(status_code=422, detail="approve or decline")
    except notes.NoteRefused as e:
        return _refused(e)
    return JSONResponse(_page_view(db, row, req), headers={"Cache-Control": "no-store"})


class Revoke(BaseModel):
    form: str
    jti: Optional[str] = None


@notes_router.post("/page/revoke")
def revoke(body: Revoke, request: Request, db: Session = Depends(get_db)):
    row = _session(request, db)
    if not body.jti:
        raise HTTPException(status_code=422, detail="name the note")
    _check_form(request, row, "revoke:" + body.jti, body.form)
    if not notes.revoke(db, body.jti, person_id=row.person_id):
        raise HTTPException(status_code=404, detail="no such note")
    return {"revoked": body.jti}


@notes_router.post("/page/revoke-all")
def revoke_all(body: Revoke, request: Request, db: Session = Depends(get_db)):
    row = _session(request, db)
    _check_form(request, row, "revoke-all", body.form)
    return {"revoked": notes.revoke_all(db, person_id=row.person_id)}


@notes_router.post("/page/sign-out-everywhere")
def sign_out_everywhere(body: Revoke, request: Request, db: Session = Depends(get_db)):
    """Every sign-in of the viewer's ends: refresh tokens, Origin sessions, job grants. Notes already
    minted stay until revoked; "Revoke all unspent" is its own button."""
    from origin.services import authority_ledger as _ledger
    from origin.services import not_before
    from origin.services import refresh_tokens as _refresh_tokens
    row = _session(request, db)
    _check_form(request, row, "sign-out-everywhere", body.form)
    who = row.person_id
    n = _refresh_tokens.revoke_person(db, who)
    origin_session.revoke_person(db, who)
    not_before.end_all(db, who)
    db.commit()
    jobs = _ledger.revoke_person_job_grants(db, who)
    return {"signed_out": True, "revoked": n, "job_grants_revoked": jobs}


# --- spending -------------------------------------------------------------------------------------

class Spend(BaseModel):
    note: str
    action: str


@notes_router.post("/spend")
def spend(body: Spend, db: Session = Depends(get_db)):
    try:
        return JSONResponse(notes.spend(db, body.note, body.action),
                            headers={"Cache-Control": "no-store"})
    except notes.NoteRefused as e:
        return _refused(e)
