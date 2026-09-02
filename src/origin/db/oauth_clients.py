"""SQLite CRUD for `oauth_clients` — RFC 7591 dynamically registered public clients."""

from __future__ import annotations

from typing import Any, Mapping, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from origin.models.oauth_client import OAuthClient


def get_by_client_id(db: Session, client_id: str) -> Optional[OAuthClient]:
    """The lookup a registry exists for, and the read that admits a client to `/authorize`.

    Two answers come out of the one row. Its EXISTENCE admits a `client_id` that no operator
    configured — without it, an id that is not first-party is refused. Its `redirect_uris` then bind
    that client to its own callbacks, which is the part the authority-wide allow-list cannot do.

    Not on the authorization-code exchange path: `_grant_authorization_code` compares the exchanging
    client against the request that started the flow, and that request was already checked here. One
    lookup per flow, at the door.
    """
    return db.execute(
        select(OAuthClient).where(OAuthClient.client_id == client_id).limit(1)
    ).scalar_one_or_none()


def create(db: Session, fields: Mapping[str, Any]) -> OAuthClient:
    """Insert one registration. `client_id` is minted by the caller and is the primary key."""
    client = OAuthClient(**dict(fields))
    db.add(client)
    db.flush()
    return client
