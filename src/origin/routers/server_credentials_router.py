"""Origin /auth/clients router — OAuth client CRUD (RFC 6749 standard naming).

First-party services sign their own JWTs with their own service key and do not register here.
This router creates `server_credentials` rows, which `/auth/token`'s `client_credentials` grant
exchanges for a `principal_type: "server"` JWT.

No Origin route accepts that token: every authenticated route here requires `user` or `service`.
The router is operator-gated regardless, because what a platform-signed credential is accepted
for elsewhere is not this router's to assume.
"""

from __future__ import annotations

import secrets as _secrets
from typing import List

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from origin import config
from origin.api.server_credential import (
    ServerCredentialCreate,
    ServerCredentialCreateResponse,
    ServerCredentialResponse,
    ServerCredentialRotateResponse,
    ServerCredentialUpdate,
)
from origin.db import server_credentials as db_server_creds
from origin.db.session import get_db
from origin.models.server_credential import ServerCredential
from origin.services import operator_console
from origin.services.dependencies import AuthContext

async def _require_operator(request: Request, db: Session = Depends(get_db),
                            who: str = Depends(operator_console.get_console_auth)) -> AuthContext:
    """Only the platform operator, on the operator console with a fresh passkey step-up for this
    very request (`oracle_router._require_operator`), may manage server credentials.

    A credential minted here outlives every token, and the operator's ordinary access token
    reaches Mantle, so that token opens nothing here. Applied as a router-level dependency, so a
    route added later is gated by default. Resolved at call time, so the console's own guard is
    the one that runs."""
    from origin.routers import oracle_router

    return await oracle_router._require_operator(request, db, who)


router = APIRouter(prefix="/auth/clients", tags=["OAuth Clients"],
                   dependencies=[Depends(_require_operator)])

_SECRET_PREFIX = "scs_"
_SECRET_BYTES = 32


def _generate_secret() -> str:
    return _SECRET_PREFIX + _secrets.token_urlsafe(_SECRET_BYTES)


def _hash_secret(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()


def _entity_to_response(entity: ServerCredential) -> ServerCredentialResponse:
    return ServerCredentialResponse(
        id=str(entity.id),
        client_id=entity.client_id,
        name=entity.name,
        server_id=str(entity.server_id),
        host_id=str(entity.host_id),
        authority=entity.authority,
        scopes=list(entity.scopes or []),
        resource_filters=dict(entity.resource_filters or {}),
        is_active=bool(entity.is_active),
        created_time=entity.created_time.isoformat() if entity.created_time else "",
        last_used_at=entity.last_used_at.isoformat() if entity.last_used_at else None,
        last_rotated_at=entity.last_rotated_at.isoformat() if entity.last_rotated_at else None,
    )


@router.post("", response_model=ServerCredentialCreateResponse, status_code=status.HTTP_201_CREATED)
def register_server_credential(
    payload: ServerCredentialCreate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(_require_operator),
):
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    if db_server_creds.get_by_client_id(db, payload.client_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"client_id '{payload.client_id}' is already registered",
        )

    raw_secret = _generate_secret()
    cred = db_server_creds.create(
        db,
        {
            "client_id": payload.client_id,
            "name": payload.name,
            "secret_hash": _hash_secret(raw_secret),
            "authority": getattr(config, "AUTHORITY_DOMAIN", "localhost"),
            "host_id": payload.host_id,
            "server_id": payload.server_id,
            "user_id": auth.user_id,
            "scopes": list(payload.scopes),
            "resource_filters": dict(payload.resource_filters),
            "is_active": True,
        },
    )
    db.commit()
    return ServerCredentialCreateResponse(
        client_id=cred.client_id,
        client_secret=raw_secret,
        name=cred.name,
        server_id=str(cred.server_id),
        host_id=str(cred.host_id),
        authority=cred.authority,
        scopes=list(cred.scopes or []),
        resource_filters=dict(cred.resource_filters or {}),
        created_time=cred.created_time.isoformat() if cred.created_time else "",
    )


@router.get("", response_model=List[ServerCredentialResponse])
def list_server_credentials(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(_require_operator),
):
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return [_entity_to_response(c) for c in db_server_creds.list_all(db)]


@router.get("/{client_id}", response_model=ServerCredentialResponse)
def get_server_credential(
    client_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(_require_operator),
):
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    cred = db_server_creds.get_by_client_id(db, client_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Server credential not found")
    return _entity_to_response(cred)


@router.patch("/{client_id}", response_model=ServerCredentialResponse)
def update_server_credential(
    client_id: str,
    payload: ServerCredentialUpdate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(_require_operator),
):
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    cred = db_server_creds.get_by_client_id(db, client_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Server credential not found")
    fields = payload.model_dump(exclude_unset=True)
    updated = db_server_creds.update(db, str(cred.id), fields)
    db.commit()
    return _entity_to_response(updated)  # type: ignore[arg-type]


@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server_credential_endpoint(
    client_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(_require_operator),
):
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    cred = db_server_creds.get_by_client_id(db, client_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Server credential not found")
    db_server_creds.delete(db, str(cred.id))
    db.commit()


@router.post("/{client_id}/rotate", response_model=ServerCredentialRotateResponse)
def rotate_server_credential(
    client_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(_require_operator),
):
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    cred = db_server_creds.get_by_client_id(db, client_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Server credential not found")
    raw_secret = _generate_secret()
    rotated = db_server_creds.rotate_secret(db, str(cred.id), _hash_secret(raw_secret))
    db.commit()
    return ServerCredentialRotateResponse(
        client_id=rotated.client_id,  # type: ignore[union-attr]
        client_secret=raw_secret,
        last_rotated_at=rotated.last_rotated_at.isoformat()  # type: ignore[union-attr]
        if rotated and rotated.last_rotated_at
        else "",
    )
