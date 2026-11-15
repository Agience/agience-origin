"""Chair notes: requests for the chair's approval, the notes approvals mint, and their spends.

An agent's account files a request with the exact fields of what it will do. Origin computes their
digest (`action_digest`) and raises the level to the kind's floor. The chair approves on Origin's
own page; the approval mints one signed note (`chair-note+jwt`) bound to that digest, valid until
the next 21:00 in Toronto. The agent that acts spends the note once per action.

A note is never a bearer token: it carries `token_type: "chair_note"`, which every bearer check
refuses.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from origin import config
from origin.models.chair_note import ChairNote, ChairRequest, ChairSpend

NOTE_TYP = "chair-note+jwt"
TOKEN_TYPE = "chair_note"

#: The exact fields each action kind carries: no more, no fewer.
DIGEST_FIELDS: dict[str, tuple[str, ...]] = {
    "release": ("release", "heads"),
    "github-publish": ("repo", "tree", "tag", "branch"),
    "prod-script": ("host", "command", "kit_sha256sums"),
    "release-step": ("release", "step", "heads"),
}

LEVELS = ("Routine", "Costed", "Outward")
#: A request may be filed at Governance; it is shown, and only declined: no note carries it.
REQUEST_LEVELS = LEVELS + ("Governance",)
_OUTWARD_KINDS = {"release", "github-publish", "release-step", "train"}

MAX_NOTE_LIFE = timedelta(days=7)


class NoteRefused(Exception):
    """A request, decision or spend Origin refuses; `status` is the HTTP answer."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def chair_email() -> Optional[str]:
    """`CHAIR_EMAIL`: the chair's address. The chair is the account holding it, verified."""
    return (os.getenv("CHAIR_EMAIL") or "").strip().lower() or None


def chair_person_id(db: Session) -> Optional[str]:
    """The account that holds `CHAIR_EMAIL`, verified; None when unset or no such account."""
    email = chair_email()
    if email is None:
        return None
    from origin.services import person_service
    person = person_service.get_user_by_email(db, email)
    if person is None or not getattr(person, "email_verified", False):
        return None
    return str(person.id)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


# --- digest ---------------------------------------------------------------------------------------

def action_digest(kind: str, fields: dict) -> str:
    """`sha256:<hex>` of the canonical JSON of `{"kind": kind, **fields}`."""
    want = DIGEST_FIELDS.get(kind)
    if want is None:
        raise NoteRefused(422, f"unknown action kind {kind!r}")
    if not isinstance(fields, dict) or set(fields) != set(want):
        raise NoteRefused(422, f"a {kind} action carries exactly {', '.join(want)}")
    body = json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def level_floor(kind: str, fields: dict) -> str:
    if kind in _OUTWARD_KINDS:
        return "Outward"
    if kind == "prod-script" and str(fields.get("host", "")).lower().startswith("prod"):
        return "Outward"
    return "Routine"


def raised_level(asked: Optional[str], kind: str, fields: dict) -> str:
    """The asked level raised to the kind's floor, never lowered."""
    if asked is not None and asked not in REQUEST_LEVELS:
        raise NoteRefused(422, "level is Routine, Costed, Outward or Governance")
    floor = level_floor(kind, fields)
    return REQUEST_LEVELS[max(REQUEST_LEVELS.index(asked or "Routine"),
                              REQUEST_LEVELS.index(floor))]


# --- the next cut ---------------------------------------------------------------------------------

def _nth_sunday(year: int, month: int, n: int) -> datetime:
    first = datetime(year, month, 1)
    return first + timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))


def toronto_offset(at: datetime) -> timedelta:
    """Toronto's UTC offset at `at`: daylight time from the second Sunday of March at 02:00 local
    to the first Sunday of November at 02:00 local, standard time otherwise. Computed here so no
    host needs a time-zone database."""
    at = _aware(at).astimezone(timezone.utc)
    y = at.year
    start = _nth_sunday(y, 3, 2).replace(hour=2, tzinfo=timezone.utc) + timedelta(hours=5)
    end = _nth_sunday(y, 11, 1).replace(hour=2, tzinfo=timezone.utc) + timedelta(hours=4)
    return timedelta(hours=-4) if start <= at < end else timedelta(hours=-5)


def next_cut(now: Optional[datetime] = None) -> datetime:
    """The next 21:00 in Toronto after `now`, in UTC."""
    now = _aware(now or _now()).astimezone(timezone.utc)
    for days in range(0, 3):
        local_day = (now + toronto_offset(now)).date() + timedelta(days=days)
        guess = datetime(local_day.year, local_day.month, local_day.day, 21, tzinfo=timezone.utc)
        cut = guess - toronto_offset(guess - timedelta(hours=5))
        if cut > now:
            return cut
    raise AssertionError("unreachable")


# --- requests -------------------------------------------------------------------------------------

def file_request(db: Session, *, filer_id: str, filer_name: str, body: dict) -> ChairRequest:
    """File a request. `body` holds `kind`, `fields` (or `steps` for a train), and optionally
    `level`, `summary`, `evidence`, `aud`, `options`, `default`."""
    kind = body.get("kind")
    aud = body.get("aud") or []
    if not isinstance(aud, list) or not aud or not all(isinstance(a, str) and a for a in aud):
        raise NoteRefused(422, "aud names the agents the note is for")
    summary = str(body.get("summary") or "")[:2000]
    steps_out = None
    if kind == "train":
        train = body.get("train")
        steps = body.get("steps")
        if not isinstance(train, str) or not train or not isinstance(steps, list) or not steps:
            raise NoteRefused(422, "a train names itself and lists its steps")
        steps_out = []
        for s in steps:
            if not isinstance(s, dict):
                raise NoteRefused(422, "each step is {kind, fields}")
            steps_out.append({"kind": s.get("kind"), "fields": s.get("fields"),
                              "digest": action_digest(s.get("kind"), s.get("fields"))})
        fields = {"train": train}
        digest = action_digest_of_train(train, [s["digest"] for s in steps_out])
        level = raised_level(body.get("level"), "train", fields)
    elif kind == "question":
        options = _options(body.get("options"))
        fields = {"question": summary}
        # The question's digest covers its options, each action's digest among them.
        digest = "sha256:" + hashlib.sha256(json.dumps(
            {"kind": "question", "options": options}, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        level = body.get("level")
        for o in options:
            if o.get("action"):
                level = raised_level(level, o["action"]["kind"], o["action"]["fields"])
        level = raised_level(level, "question", fields)
    else:
        fields = body.get("fields")
        digest = action_digest(kind, fields)
        level = raised_level(body.get("level"), kind, fields)
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
    now = _now()
    req = ChairRequest(
        id=str(uuid.uuid4()), kind=kind, level=level, fields=fields, digest=digest,
        steps=steps_out, summary=summary, aud=aud,
        options=options if kind == "question" else None, default_option=default,
        filed_by=filer_name[:200], filed_by_account=filer_id, created_time=now,
        expires_time=next_cut(now), state="pending",
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


def action_digest_of_train(train: str, step_digests: list[str]) -> str:
    body = json.dumps({"kind": "train", "train": train, "actions": step_digests},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def get_request(db: Session, req_id: str) -> Optional[ChairRequest]:
    req = db.get(ChairRequest, req_id)
    return settle(db, req) if req is not None else None


def is_open(req: ChairRequest, now: Optional[datetime] = None) -> bool:
    return req.state == "pending" and _aware(req.expires_time) > (now or _now())


def settle(db: Session, req: ChairRequest) -> ChairRequest:
    """A question past its expiry takes its default, when it has one."""
    if req.kind == "question" and req.state == "pending" and req.default_option \
            and not is_open(req):
        req.state, req.answer = "answered", req.default_option
        req.decided_time, req.decided_by = req.expires_time, None
        db.commit()
    return req


def request_view(db: Session, req: ChairRequest) -> dict:
    out: dict[str, Any] = {
        "id": req.id, "kind": req.kind, "level": req.level, "fields": req.fields,
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
        note = db.get(ChairNote, req.note_jti)
        if note is not None:
            out["note"] = note.token
            out["revoked"] = note.revoked_time is not None
            out["note_jti"] = note.jti
            out["spent"] = db.query(ChairSpend).filter(ChairSpend.jti == note.jti).first() is not None
    return out


# --- decisions ------------------------------------------------------------------------------------

def _decidable(req: Optional[ChairRequest], chair_id: str, digest: Optional[str]) -> ChairRequest:
    if req is None:
        raise NoteRefused(404, "no such request")
    if not is_open(req):
        raise NoteRefused(409, "this request is no longer open")
    if digest is not None and digest != req.digest:
        raise NoteRefused(412, "This request changed after you opened it. Here is the new version.")
    return req


def approve(db: Session, req: Optional[ChairRequest], *, chair_id: str, digest: str,
            auth_time: datetime, amr: list[str], option: Optional[str] = None) -> ChairRequest:
    """Approve: mint the note. For a question, record the option (no note is minted)."""
    req = _decidable(req, chair_id, digest)
    if req.level not in LEVELS:
        raise NoteRefused(422, "Decide at your desk. Phone approval for Governance comes later.")
    now = _now()
    action = req.digest
    if req.kind == "question":
        chosen = [o for o in (req.options or []) if o["label"] == option]
        if not chosen:
            raise NoteRefused(422, "choose one of the options")
        req.answer = option
        if not chosen[0].get("action"):
            req.state = "answered"
            req.decided_time, req.decided_by = now, chair_id
            db.commit()
            return req
        action = chosen[0]["action"]["digest"]
    from origin.key_manager import get_key_id, get_private_key_pem
    exp = min(next_cut(now), now + MAX_NOTE_LIFE)
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "iss": config.AUTHORITY_ISSUER, "sub": chair_id, "aud": list(req.aud),
        "iat": int(now.timestamp()), "nbf": int(now.timestamp()), "exp": int(exp.timestamp()),
        "jti": jti, "level": req.level, "decision": "approve",
        "auth_time": int(_aware(auth_time).timestamp()), "amr": list(amr), "req": req.id,
        "parent": None, "token_type": TOKEN_TYPE,
    }
    if req.kind == "train":
        payload["scope"] = {"train": req.fields["train"],
                            "actions": [s["digest"] for s in req.steps or []]}
    else:
        payload["action"] = action
    token = jwt.encode(payload, get_private_key_pem(), algorithm="RS256",
                       headers={"kid": get_key_id(), "typ": NOTE_TYP})
    db.add(ChairNote(jti=jti, req=req.id, person_id=chair_id, level=req.level, token=token,
                     issued_time=now, expires_time=exp))
    req.state = "answered" if req.kind == "question" else "approved"
    req.note_jti = jti
    req.decided_time, req.decided_by = now, chair_id
    db.commit()
    return req


def decline(db: Session, req: Optional[ChairRequest], *, chair_id: str, digest: str,
            reason: str = "") -> ChairRequest:
    req = _decidable(req, chair_id, digest)
    req.state, req.decline_reason = "declined", (reason or "")[:2000]
    req.decided_time, req.decided_by = _now(), chair_id
    db.commit()
    return req


# --- spending -------------------------------------------------------------------------------------

def _verify(token: str) -> dict:
    """The note's claims, verified against every key Origin still publishes."""
    from origin.services.signing_keys import published_jwks
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise NoteRefused(400, "not a chair note")
    if header.get("typ") != NOTE_TYP:
        raise NoteRefused(400, "not a chair note")
    try:
        claims = jwt.decode(token, {"keys": published_jwks()}, algorithms=["RS256"],
                            issuer=config.AUTHORITY_ISSUER,
                            options={"verify_aud": False, "verify_exp": False})
    except (JWTError, TypeError, ValueError):
        raise NoteRefused(400, "not a chair note")
    if claims.get("token_type") != TOKEN_TYPE or not claims.get("jti"):
        raise NoteRefused(400, "not a chair note")
    return claims


def covers(claims: dict, action: str) -> bool:
    if "action" in claims:
        return claims["action"] == action
    scope = claims.get("scope") or {}
    return action in (scope.get("actions") or [])


def spend(db: Session, token: str, action: str) -> dict:
    """Spend the note on `action` once. Answers the receipt, or raises with 400/409/410/422."""
    claims = _verify(token)
    note = db.get(ChairNote, claims["jti"])
    if note is None:
        raise NoteRefused(400, "not a chair note")
    now = _now()
    if note.revoked_time is not None or _aware(note.expires_time) <= now \
            or claims.get("exp", 0) <= now.timestamp():
        raise NoteRefused(410, "revoked" if note.revoked_time is not None else "expired")
    if not isinstance(action, str) or not covers(claims, action):
        raise NoteRefused(422, "action not covered by the note")
    row = ChairSpend(jti=note.jti, action=action, id=str(uuid.uuid4()), req=note.req,
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

def revoke(db: Session, jti: str, *, chair_id: str) -> bool:
    note = db.get(ChairNote, jti)
    if note is None or note.person_id != chair_id:
        return False
    if note.revoked_time is None:
        note.revoked_time = _now()
        db.commit()
    return True


def revoke_all(db: Session, *, chair_id: str) -> int:
    now = _now()
    n = 0
    for note in db.query(ChairNote).filter(ChairNote.person_id == chair_id,
                                           ChairNote.revoked_time.is_(None)):
        if _aware(note.expires_time) > now:
            note.revoked_time = now
            n += 1
    db.commit()
    return n


def pending(db: Session) -> list[ChairRequest]:
    now = _now()
    rows = db.query(ChairRequest).filter(ChairRequest.state == "pending") \
        .order_by(ChairRequest.created_time).all()
    return [r for r in rows if _aware(r.expires_time) > now]


def live_notes(db: Session, chair_id: str) -> list[ChairNote]:
    now = _now()
    rows = db.query(ChairNote).filter(ChairNote.person_id == chair_id,
                                      ChairNote.revoked_time.is_(None)).all()
    return [n for n in rows if _aware(n.expires_time) > now]
