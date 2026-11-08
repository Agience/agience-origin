"""Service accounts (review 11, M5): an Origin account that is a service's own.

Ember's own credential is an Origin account. Marked here for an audience, every person token Origin
would issue for it is issued instead as a delegation narrowed to that audience
(`auth_service.create_jwt_token`), five minutes long, never `platform:admin`: Origin enforces the
narrowing, not Ember. Its refresh tokens still rotate (`services.refresh_tokens`), so the service
keeps its sign-in. Marked by the operator on Origin's host:

    python -m origin.scripts.service_account --person <id> --audience ember
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from origin.models.service_account import ServiceAccount


class ServiceAccountsUnavailable(RuntimeError):
    """Origin cannot tell a service's own account from a person's: it issues no token."""


def mark(db: Session, person_id: str, audience: str) -> None:
    """Mark `person_id` as the service account for `audience`. The caller commits."""
    from origin.services.auth_service import narrow_audiences
    if audience not in narrow_audiences():
        raise ValueError(f"{audience!r} is not a narrow audience")
    row = db.get(ServiceAccount, str(person_id))
    if row is None:
        db.add(ServiceAccount(person_id=str(person_id), audience=audience))
    else:
        row.audience = audience
    db.flush()


def unmark(db: Session, person_id: str) -> bool:
    row = db.get(ServiceAccount, str(person_id))
    if row is None:
        return False
    db.delete(row)
    db.flush()
    return True


def audience_of(person_id: Optional[str]) -> Optional[str]:
    """The audience `person_id`'s tokens are narrowed to, or None for a person."""
    if not person_id:
        return None
    from origin.db.session import SessionLocal
    try:
        with SessionLocal() as db:
            row = db.get(ServiceAccount, str(person_id))
            return row.audience if row is not None else None
    except RuntimeError:                  # no engine initialised (a unit test): no accounts
        return None
    except OperationalError as exc:
        # Origin's person store exists but not this table: migration 0019 has not run. Fail closed
        # (review 12): which accounts are a service's own is unknown, so no person token is issued
        # for anyone, rather than a full one for what may be a service account. A database with no
        # person store at all holds no account that could be one.
        if not _has_person_store():
            return None
        logging.getLogger(__name__).error("service_accounts is missing: run migration 0019")
        raise ServiceAccountsUnavailable(
            "service_accounts is missing (run migration 0019): no token is issued") from exc


def _has_person_store() -> bool:
    try:
        from sqlalchemy import inspect

        from origin.db.session import get_engine
        return inspect(get_engine()).has_table("persons")
    except Exception:  # noqa: BLE001 — cannot tell: treat it as present, and fail closed
        return True
