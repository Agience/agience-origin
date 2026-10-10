"""SQLite CRUD for `persons`.

Returns the SQLAlchemy `Person` model directly. Callers convert to whatever
entity or Pydantic shape they need at the service layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import func, select, update as sa_update
from sqlalchemy.orm import Session

from origin.models.person import Person


def get_by_id(db: Session, person_id: str) -> Optional[Person]:
    return db.get(Person, _to_uuid(person_id))


def get_by_email(db: Session, email: str) -> Optional[Person]:
    return db.execute(
        select(Person).where(Person.email == email.strip()).limit(1)
    ).scalar_one_or_none()


def get_by_username(db: Session, username: str) -> Optional[Person]:
    return db.execute(
        select(Person).where(Person.username == username.strip()).limit(1)
    ).scalar_one_or_none()




def create(db: Session, fields: Mapping[str, Any]) -> Person:
    """Insert a new Person. `id` may be supplied; otherwise generated."""
    payload = dict(fields)
    if "id" in payload and payload["id"]:
        payload["id"] = _to_uuid(payload["id"])
    else:
        payload["id"] = uuid.uuid4()
    payload.setdefault("preferences", {})
    person = Person(**payload)
    db.add(person)
    db.flush()
    return person


def update(db: Session, person_id: str, fields: Mapping[str, Any]) -> Person:
    person = db.get(Person, _to_uuid(person_id))
    if person is None:
        raise LookupError(f"Person {person_id} not found")
    for key, value in fields.items():
        setattr(person, key, value)
    person.modified_time = datetime.now(timezone.utc)
    db.flush()
    return person


def replace_password_hash(db: Session, person_id: str, expected: str, new: str) -> bool:
    """Set the password hash to `new` only if it is still `expected`; True when it was replaced.

    One conditional UPDATE, so a hash written by someone else since `expected` was read — a
    password reset, a change — is never overwritten by a writer still holding the old one.
    """
    result = db.execute(
        sa_update(Person)
        .where(Person.id == _to_uuid(person_id), Person.password_hash == expected)
        .values(password_hash=new, modified_time=datetime.now(timezone.utc))
        .execution_options(synchronize_session=False)
    )
    return (result.rowcount or 0) == 1


def update_preferences(db: Session, person_id: str, preferences: dict) -> Person:
    return update(db, person_id, {"preferences": preferences or {}})


def count(db: Session) -> int:
    return db.execute(select(func.count()).select_from(Person)).scalar_one()


def _to_uuid(value: str | uuid.UUID) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))
