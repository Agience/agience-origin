"""Approval notes: requests filed against a workspace or collection, the notes approvals mint,
and their spends.

An account files a request against a resource (a workspace or collection it can read) with the
exact fields of what it will do, a level label and an expiry. Origin computes their digest
(`action_digest`). Whoever holds `update` on that resource, through the ordinary grants, approves
on Origin's own page; the approval mints one signed note (`decision-note+jwt`) bound to that digest,
valid until the request's expiry and never longer than `MAX_NOTE_LIFE`. The agent that acts
spends the note once per action.

The kinds, levels and expiries are the filer's data. Origin names no approver and holds no
process of its own.

A note is never a bearer token: it carries `token_type: "decision_note"`, which every bearer check
refuses.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from origin import config
from origin.models.decision_note import DecisionNote, DecisionRequest, DecisionSpend

NOTE_TYP = "decision-note+jwt"
TOKEN_TYPE = "decision_note"

#: The longest a request stays open and a note stays valid.
MAX_NOTE_LIFE = timedelta(days=7)

#: What an approver holds on the request's resource; what a viewer holds to see the request.
APPROVE_ACTION = "update"
SEE_ACTION = "read"


class NoteRefused(Exception):
    """A request, decision or spend Origin refuses; `status` is the HTTP answer."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


# --- digest ---------------------------------------------------------------------------------------

def _canon(body: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _kind(kind: Any) -> str:
    if not isinstance(kind, str) or not kind or len(kind) > 32:
        raise NoteRefused(422, "kind names the action, in at most 32 characters")
    return kind


def action_digest(kind: str, fields: dict) -> str:
    """`sha256:<hex>` of the canonical JSON of `{"kind": kind, **fields}`."""
    kind = _kind(kind)
    if not isinstance(fields, dict) or "kind" in fields:
        raise NoteRefused(422, f"a {kind} action carries its fields as an object without `kind`")
    return _canon({"kind": kind, **fields})


def steps_digest(kind: str, fields: dict, step_digests: list[str]) -> str:
    """`sha256:<hex>` of `{"kind": kind, **fields, "actions": [each step's digest]}`."""
    kind = _kind(kind)
    if not isinstance(fields, dict) or "kind" in fields or "actions" in fields:
        raise NoteRefused(422, "a request with steps carries its fields as an object without "
                               "`kind` or `actions`")
    return _canon({"kind": kind, **fields, "actions": list(step_digests)})


def _level(raw: Any) -> str:
    """The filer's label for the request, shown on the page."""
    if raw is None:
        return ""
    if not isinstance(raw, str) or len(raw) > 16:
        raise NoteRefused(422, "level is a label of at most 16 characters")
    return raw


def _expires(raw: Any, now: datetime) -> datetime:
    """The filer's expiry: an ISO time after now and within `MAX_NOTE_LIFE`."""
    if not isinstance(raw, str):
        raise NoteRefused(422, "expires is the ISO time the request closes")
    try:
        at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise NoteRefused(422, "expires is the ISO time the request closes")
    if at.tzinfo is None:
        raise NoteRefused(422, "expires carries its UTC offset")
    at = at.astimezone(timezone.utc)
    if at <= now or at > now + MAX_NOTE_LIFE:
        raise NoteRefused(422, "expires is after now and within 7 days")
    return at


# --- who sees and who decides ---------------------------------------------------------------------

def _reaches(db: Session, person_id: str, resource_id: Optional[str], action: str) -> bool:
    if not person_id or not resource_id:
        return False
    from origin.services import authority_ledger
    return authority_ledger.reach(db).reaches(str(person_id), str(resource_id), action)


APPROVER_LOST_UPDATE = "the approver no longer holds update on the request's resource"


def can_approve(db: Session, person_id: str, req: DecisionRequest) -> bool:
    """Does `person_id` hold `update` on the request's resource? Nothing else decides it."""
    return _reaches(db, person_id, req.resource_id, APPROVE_ACTION)


def can_see(db: Session, person_id: str, req: DecisionRequest) -> bool:
    """The filer, and anyone who can read the request's resource, sees the request."""
    return person_id == req.filed_by_account         or _reaches(db, person_id, req.resource_id, SEE_ACTION)


# --- requests -------------------------------------------------------------------------------------

def file_request(db: Session, *, filer_id: str, filer_name: str, body: dict) -> DecisionRequest:
    """File a request. `body` holds `resource` (a workspace or collection the filer can read),
    `kind`, `fields` (with `steps` when the request covers several actions), `expires`, and
    optionally `level`, `summary`, `evidence`, `aud`, `options`, `default`."""
    now = _now()
    resource = body.get("resource")
    if not isinstance(resource, str) or not resource or len(resource) > 64 \
            or not _reaches(db, filer_id, resource, SEE_ACTION):
        raise NoteRefused(422, "resource names a workspace or collection you can read")
    kind = _kind(body.get("kind"))
    aud = body.get("aud") or []
    if not isinstance(aud, list) or not aud or not all(isinstance(a, str) and a for a in aud):
        raise NoteRefused(422, "aud names the agents the note is for")
    summary = str(body.get("summary") or "")[:2000]
    level = _level(body.get("level"))
    expires = _expires(body.get("expires"), now)
    steps_out = None
    options = None
    if kind == "question":
        options = _options(body.get("options"))
        fields = {"question": summary}
        # The question's digest covers its options, each action's digest among them.
        digest = _canon({"kind": "question", "options": options})
    elif body.get("steps") is not None:
        steps = body.get("steps")
        fields = body.get("fields")
        if not isinstance(steps, list) or not steps:
            raise NoteRefused(422, "steps lists the actions the request covers")
        steps_out = []
        for st in steps:
            if not isinstance(st, dict):
                raise NoteRefused(422, "each step is {kind, fields}")
            steps_out.append({"kind": st.get("kind"), "fields": st.get("fields"),
                              "digest": action_digest(st.get("kind"), st.get("fields"))})
        digest = steps_digest(kind, fields, [st["digest"] for st in steps_out])
    else:
        fields = body.get("fields")
        digest = action_digest(kind, fields)
    default = body.get("default")
    if default is not None:
        if kind != "question":
            raise NoteRefused(422, "only a question has a default")
        chosen = [o for o in options if o["label"] == default]
        if not chosen:
            raise NoteRefused(422, "the default is one of the options")
        if chosen[0].get("action"):
            raise NoteRefused(422, "the default is an option that needs no note")
    claimed = body.get("digest")
    if claimed is not None and not isinstance(claimed, str):
        raise NoteRefused(422, "digest is the filer's own sha256:<hex>, for comparison")
    req = DecisionRequest(
        id=str(uuid.uuid4()), kind=kind, level=level, fields=fields, digest=digest,
        steps=steps_out, summary=summary, aud=aud, options=options, default_option=default,
        filed_by=filer_name[:200], filed_by_account=filer_id, created_time=now,
        expires_time=expires, state="pending", resource_id=resource,
    )
    # Origin never takes the filer's digest; it keeps it beside its own so the page can say
    # whether both computed the same.
    req.evidence = {"items": _evidence(body.get("evidence"))}
    if claimed is not None:
        req.evidence["filer_digest"] = claimed[:80]
    db.add(req)
    db.commit()
    return req


def _options(raw: Any) -> list[dict]:
    if not isinstance(raw, list) or len(raw) < 2:
        raise NoteRefused(422, "a question offers at least two options")
    out, seen = [], set()
    for o in raw:
        if isinstance(o, str):
            o = {"label": o}
        if not isinstance(o, dict) or not isinstance(o.get("label"), str) or not o["label"]:
            raise NoteRefused(422, "each option has a label")
        label = o["label"][:200]
        if label in seen:
            raise NoteRefused(422, "each option's label is its own")
        seen.add(label)
        item: dict[str, Any] = {"label": label}
        act = o.get("action")
        if act is not None:
            if not isinstance(act, dict):
                raise NoteRefused(422, "an option's action is {kind, fields}")
            item["action"] = {"kind": act.get("kind"), "fields": act.get("fields"),
                              "digest": action_digest(act.get("kind"), act.get("fields"))}
        out.append(item)
    return out


def _evidence(raw: Any) -> list[dict]:
    """Each piece of evidence: a `label` ("CI green"), and optionally `at` (an ISO time), `url`, and
    `heads` (repo to sha), against which the page marks each head of the request."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise NoteRefused(422, "evidence is a list")
    out = []
    for e in raw[:20]:
        if isinstance(e, str):
            e = {"url": e, "label": e}
        if not isinstance(e, dict):
            raise NoteRefused(422, "each piece of evidence is {label, at, url, heads}")
        item: dict[str, Any] = {k: str(e[k])[:500] for k in ("label", "at", "url") if e.get(k)}
        if isinstance(e.get("heads"), dict):
            item["heads"] = {str(k)[:200]: str(v)[:64] for k, v in e["heads"].items()}
        out.append(item)
    return out


def get_request(db: Session, req_id: str) -> Optional[DecisionRequest]:
    req = db.get(DecisionRequest, req_id)
    return settle(db, req) if req is not None else None


def is_open(req: DecisionRequest, now: Optional[datetime] = None) -> bool:
    return req.state == "pending" and _aware(req.expires_time) > (now or _now())


def settle(db: Session, req: DecisionRequest) -> DecisionRequest:
    """A question past its expiry takes its default, when it has one."""
    if req.kind == "question" and req.state == "pending" and req.default_option \
            and not is_open(req):
        req.state, req.answer = "answered", req.default_option
        req.decided_time, req.decided_by = req.expires_time, None
        db.commit()
    return req


def request_view(db: Session, req: DecisionRequest) -> dict:
    out: dict[str, Any] = {
        "id": req.id, "kind": req.kind, "level": req.level, "fields": req.fields,
        "resource": req.resource_id,
        "digest": req.digest, "steps": req.steps, "summary": req.summary,
        "evidence": (req.evidence or {}).get("items", []),
        "filer_digest": (req.evidence or {}).get("filer_digest"), "aud": req.aud, "options": req.options,
        "default": req.default_option, "filed_by": req.filed_by,
        "created": _aware(req.created_time).isoformat(),
        "expires": _aware(req.expires_time).isoformat(),
        "state": "expired" if req.state == "pending" and not is_open(req) else req.state,
    }
    if req.state == "declined":
        out["reason"] = req.decline_reason
    if req.state == "answered":
        out["answer"] = req.answer
    if req.note_jti:
        note = db.get(DecisionNote, req.note_jti)
        if note is not None:
            out["note"] = note.token
            out["revoked"] = note.revoked_time is not None
            out["note_jti"] = note.jti
            out["spent"] = db.query(DecisionSpend).filter(DecisionSpend.jti == note.jti).first() is not None
    return out


# --- decisions ------------------------------------------------------------------------------------

CANNOT_APPROVE = "You can't approve this request. Approving needs Editor access to it."


def _decidable(db: Session, req: Optional[DecisionRequest], person_id: str,
               digest: Optional[str]) -> DecisionRequest:
    if req is None:
        raise NoteRefused(404, "no such request")
    if not can_approve(db, person_id, req):
        raise NoteRefused(403, CANNOT_APPROVE)
    if not is_open(req):
        raise NoteRefused(409, "this request is no longer open")
    if digest is not None and digest != req.digest:
        raise NoteRefused(412, "This request changed after you opened it. Here is the new version.")
    return req


def approve(db: Session, req: Optional[DecisionRequest], *, person_id: str, digest: str,
            auth_time: datetime, amr: list[str], option: Optional[str] = None) -> DecisionRequest:
    """Approve: mint the note. For a question, record the option (no note is minted)."""
    req = _decidable(db, req, person_id, digest)
    now = _now()
    action = req.digest
    if req.kind == "question":
        chosen = [o for o in (req.options or []) if o["label"] == option]
        if not chosen:
            raise NoteRefused(422, "choose one of the options")
        req.answer = option
        if not chosen[0].get("action"):
            req.state = "answered"
            req.decided_time, req.decided_by = now, person_id
            db.commit()
            return req
        action = chosen[0]["action"]["digest"]
    from origin.key_manager import get_key_id, get_private_key_pem
    exp = min(_aware(req.expires_time), now + MAX_NOTE_LIFE)
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "iss": config.AUTHORITY_ISSUER, "sub": person_id, "aud": list(req.aud),
        "iat": int(now.timestamp()), "nbf": int(now.timestamp()), "exp": int(exp.timestamp()),
        "jti": jti, "level": req.level, "decision": "approve",
        "auth_time": int(_aware(auth_time).timestamp()), "amr": list(amr), "req": req.id,
        "resource": req.resource_id, "parent": None, "token_type": TOKEN_TYPE,
    }
    if req.steps:
        payload["scope"] = {**(req.fields or {}), "actions": [st["digest"] for st in req.steps]}
    else:
        payload["action"] = action
    token = jwt.encode(payload, get_private_key_pem(), algorithm="RS256",
                       headers={"kid": get_key_id(), "typ": NOTE_TYP})
    db.add(DecisionNote(jti=jti, req=req.id, person_id=person_id, level=req.level, token=token,
                     issued_time=now, expires_time=exp))
    req.state = "answered" if req.kind == "question" else "approved"
    req.note_jti = jti
    req.decided_time, req.decided_by = now, person_id
    db.commit()
    return req


def withdraw(db: Session, req: Optional[DecisionRequest], *, person_id: str) -> DecisionRequest:
    """The filer takes back a request nobody has decided yet."""
    if req is None:
        raise NoteRefused(404, "no such request")
    if person_id != req.filed_by_account:
        raise NoteRefused(403, "only the one who filed a request withdraws it")
    if not is_open(req):
        raise NoteRefused(409, "this request is no longer open")
    req.state = "withdrawn"
    req.decided_time, req.decided_by = _now(), person_id
    db.commit()
    return req


def decline(db: Session, req: Optional[DecisionRequest], *, person_id: str, digest: str,
            reason: str = "") -> DecisionRequest:
    req = _decidable(db, req, person_id, digest)
    req.state, req.decline_reason = "declined", (reason or "")[:2000]
    req.decided_time, req.decided_by = _now(), person_id
    db.commit()
    return req


# --- spending -------------------------------------------------------------------------------------

def _verify(token: str) -> dict:
    """The note's claims, verified against every key Origin still publishes."""
    from origin.services.signing_keys import published_jwks
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise NoteRefused(400, "not a decision note")
    if header.get("typ") != NOTE_TYP:
        raise NoteRefused(400, "not a decision note")
    try:
        claims = jwt.decode(token, {"keys": published_jwks()}, algorithms=["RS256"],
                            issuer=config.AUTHORITY_ISSUER,
                            options={"verify_aud": False, "verify_exp": False})
    except (JWTError, TypeError, ValueError):
        raise NoteRefused(400, "not a decision note")
    if claims.get("token_type") != TOKEN_TYPE or not claims.get("jti"):
        raise NoteRefused(400, "not a decision note")
    return claims


def covers(claims: dict, action: str) -> bool:
    if "action" in claims:
        return claims["action"] == action
    scope = claims.get("scope") or {}
    return action in (scope.get("actions") or [])


def spend(db: Session, token: str, action: str) -> dict:
    """Spend the note on `action` once. Answers the receipt, or raises with 400/403/409/410/422.

    The approver must still hold update on the request's resource when the note is spent."""
    claims = _verify(token)
    note = db.get(DecisionNote, claims["jti"])
    if note is None:
        raise NoteRefused(400, "not a decision note")
    now = _now()
    if note.revoked_time is not None or _aware(note.expires_time) <= now \
            or claims.get("exp", 0) <= now.timestamp():
        raise NoteRefused(410, "revoked" if note.revoked_time is not None else "expired")
    req = db.get(DecisionRequest, note.req)
    if req is None or not can_approve(db, note.person_id, req):
        raise NoteRefused(403, APPROVER_LOST_UPDATE)
    if not isinstance(action, str) or not covers(claims, action):
        raise NoteRefused(422, "action not covered by the note")
    row = DecisionSpend(jti=note.jti, action=action, id=str(uuid.uuid4()), req=note.req,
                     spent_time=now)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise NoteRefused(409, "already spent")
    return {"receipt": {"id": row.id, "jti": note.jti, "action": action, "req": note.req,
                        "spent_at": int(now.timestamp())}}


# --- revoking -------------------------------------------------------------------------------------

def revoke(db: Session, jti: str, *, person_id: str) -> bool:
    """Revoke a note: the one who approved it, or an approver on its request's resource."""
    note = db.get(DecisionNote, jti)
    if note is None:
        return False
    if note.person_id != person_id:
        req = db.get(DecisionRequest, note.req)
        if req is None or not can_approve(db, person_id, req):
            return False
    if note.revoked_time is None:
        note.revoked_time = _now()
        db.commit()
    return True


def revoke_all(db: Session, *, person_id: str) -> int:
    """Revoke every unspent, unexpired note `person_id` approved."""
    now = _now()
    n = 0
    for note in db.query(DecisionNote).filter(DecisionNote.person_id == person_id,
                                           DecisionNote.revoked_time.is_(None)):
        if _aware(note.expires_time) > now:
            note.revoked_time = now
            n += 1
    db.commit()
    return n


def pending_for(db: Session, person_id: str) -> list[DecisionRequest]:
    """The open requests `person_id` can approve, oldest first."""
    now = _now()
    rows = db.query(DecisionRequest).filter(DecisionRequest.state == "pending",
                                         DecisionRequest.resource_id.isnot(None)) \
        .order_by(DecisionRequest.created_time).all()
    return [r for r in rows if _aware(r.expires_time) > now and can_approve(db, person_id, r)]


def live_notes(db: Session, person_id: str) -> list[DecisionNote]:
    now = _now()
    rows = db.query(DecisionNote).filter(DecisionNote.person_id == person_id,
                                      DecisionNote.revoked_time.is_(None)).all()
    return [n for n in rows if _aware(n.expires_time) > now]
