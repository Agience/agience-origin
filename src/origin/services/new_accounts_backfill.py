"""Giving existing accounts what "New accounts receive" lists: an invoke on that collection.

The dry run lists, for every account, the grants the collection gives that the account does not
hold yet, and files that list as one approval request against the collection, one step per grant.
Whoever holds `update` on the collection decides it on Origin's approvals page. The run then
spends the note once per step and appends each grant as the operator's own entry, which the
ledger accepts only while the collection still lists it.

Both are taken from a person who reaches `invoke` on the collection; the run, only from one the
note is addressed to. A step already held is passed over, so a run repeated after an interruption
grants each one once.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from origin.services import authority_ledger as L
from origin.services import chair_notes as notes

KIND = "new-accounts-backfill"
STEP = "new-account-grant"
INVOKE = "invoke"
#: How long the request stays open when the filer names no expiry.
DEFAULT_OPEN = timedelta(days=6)


class BackfillRefused(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _collection(db: Session, person_id: str) -> tuple:
    """(operator, collection), for a person who reaches invoke on the collection."""
    operator = L._operator()
    if not operator:
        raise BackfillRefused(409, "this platform has no operator")
    nar = L.new_accounts_receive_id(operator)
    if not L.reach(db).reaches(str(person_id), nar, INVOKE):
        raise BackfillRefused(403, 'running this needs invoke on "New accounts receive"')
    return operator, nar


def plan(db: Session, operator: str) -> list:
    """Every grant an existing account receives and does not hold yet, in a stable order."""
    from origin.models.person import Person
    rc = L.reach(db)
    out = []
    for (pid,) in db.query(Person.id).filter(Person.deactivated_at.is_(None)).order_by(Person.id):
        out.extend(L.new_account_grant_bodies(db, str(pid), operator, rc))
    return out


def _step(body: dict) -> dict:
    return {"kind": STEP, "fields": {k: v for k, v in body.items() if k != "kind"}}


def file(db: Session, person_id: str, filer_name: str, expires: Optional[str] = None) -> dict:
    """The dry run: list the grants and file them as one request on the collection. Answers the
    list, and the request when there is anything to grant."""
    operator, nar = _collection(db, person_id)
    bodies = plan(db, operator)
    grants = [{"person": b["grantee_id"], "resource": b["resource_id"], "actions": b["actions"]}
              for b in bodies]
    if not bodies:
        return {"collection": nar, "grants": [], "request": None}
    accounts = len({b["grantee_id"] for b in bodies})
    req = notes.file_request(db, filer_id=str(person_id), filer_name=filer_name, body={
        "resource": nar, "kind": KIND, "level": "Governance",
        "fields": {"collection": nar, "operator": operator},
        "steps": [_step(b) for b in bodies],
        "aud": [str(person_id)],
        "expires": expires or (datetime.now(timezone.utc) + DEFAULT_OPEN).isoformat(),
        "summary": f'Give {accounts} existing accounts what "New accounts receive" lists: '
                   f"{len(bodies)} grants, each read or read and invoke on one member.",
    })
    return {"collection": nar, "grants": grants, "request": req.id,
            "page": f"/approvals?req={req.id}"}


def run(db: Session, person_id: str, req_id: str) -> dict:
    """Spend the approved note once per step and append each grant as the operator's entry."""
    operator, nar = _collection(db, person_id)
    req = notes.get_request(db, req_id)
    if req is None or req.kind != KIND or req.resource_id != nar:
        raise BackfillRefused(404, "no such request")
    if str(person_id) not in (req.aud or []):
        raise BackfillRefused(403, "the note is not addressed to you")
    if req.state != "approved" or not req.note_jti:
        raise BackfillRefused(409, f"the request is {req.state}, not approved")
    from origin.models.chair_note import ChairNote
    token = db.get(ChairNote, req.note_jti).token
    granted, held, refused = 0, 0, []
    for st in req.steps or []:
        fields = st.get("fields") or {}
        if st.get("kind") != STEP or notes.action_digest(STEP, fields) != st.get("digest"):
            raise BackfillRefused(409, "a step does not match its digest")
        body = {"kind": "grant", **fields}
        prior = L.reach(db).r.grant(body["grant_id"])
        if prior is not None and prior.state == "active":
            held += 1
            continue
        try:
            notes.spend(db, token, st["digest"])
        except notes.NoteRefused as e:
            # Spent already: a run interrupted between the spend and the grant. The step was
            # approved, and the grant id is stable, so it is granted once.
            if e.status != 409:
                raise BackfillRefused(e.status, e.detail)
        try:
            L.append(db, body, actor=L.Actor(operator, "operator", f"backfill:{req.id}"),
                     submitted_jti=f"backfill:{req.id}")
            granted += 1
        except L.EntryRefused as e:
            refused.append({"person": body["grantee_id"], "resource": body["resource_id"],
                            "reason": str(e)})
    return {"request": req.id, "granted": granted, "held": held, "refused": refused}
