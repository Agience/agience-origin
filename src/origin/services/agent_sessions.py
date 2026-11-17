"""An agent session's way to a Mantle token (FR-032): a window's standing grant, a session's signed
ask, the approval token Origin signs for it, and its exchange (RFC 8693, RFC 7523).

The window. At sign-in the bridge makes a key pair (ES256) and, in the person's own Origin
session, a job grant `agent.window.<jkt>` (`authority_ledger.AGENT_WINDOW_PREFIX`), `jkt` being
the key's RFC 7638 thumbprint. The grant's `reach` is the collections its sessions may work in and
its `actions` the most they may do there; it ends within seven days.

The ask. Each session makes its own key and has the window key sign an ask: a JWT (`typ`
`agent-ask+jwt`, the window's public key in its `jwk` header) naming the grant, the agent, its
role, the actions and collections it asks for, its home collection and the session key's
thumbprint (`cnf.jkt`). Origin checks the ask against the grant, files the agent artifact (when the
ask names none) and an approval artifact in Mantle as the person, records the approval
(`agent_approvals`) and returns the approval token: Origin-signed, `sub` the person, `aud` the
agent, `cnf.jkt` the session's key, the agent, role, actions, collections, grant and `jti`, ending
with the grant and within seven days. It carries `token_type`, so no route takes it as a bearer.

The exchange. At `/auth/token` the subject is the approval token and the actor a JWT the session
key signs (`iss` = `sub` = the agent, addressed to this endpoint, minutes long, bound to the
subject by `subject_digest`, used once). The result is a delegation addressed to Mantle: `sub` the
person, `act.sub` the agent, scope `mantle:agent`, `job_reach` the approval's collections and
`reach_actions` its actions, five minutes long. The window key is never the actor (its thumbprint
is not the approval's `cnf.jkt`), and the window key alone yields no Mantle token.

The key. An agent may instead carry its Key artifact's token (`agk_<key id>.<secret>`), issued
once when the person creates the Key in Mantle under the agent. At `/auth/token` it is the actor
(`actor_token_type` `agent-key`); Origin asks Mantle what it is (`GET /credentials/self`, the key
as the bearer) and signs the same five-minute delegation: `sub` the person, `act.sub` the agent,
`job_reach` and `reach_actions` as the Key says, never past the Key's end. Mantle answers only for
a live Key whose collection is live, so archiving either ends it.

Revocation. An approval is checked by `jti` at every exchange. Revoking the grant (the window's
key signs it, or the person on Origin's page, or signing out everywhere) revokes every approval
made under it; a session's key revokes its own.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Awaitable, Optional

from sqlalchemy.orm import Session

from origin import config
from origin.models.agent_approval import AgentApproval
from origin.services import authority_ledger

logger = logging.getLogger(__name__)

ASK_TOKEN_TYPE = "urn:agience:params:oauth:token-type:agent-ask"
APPROVAL_TOKEN_TYPE = "urn:agience:params:oauth:token-type:agent-approval"
#: An agent's Key artifact token, the actor at the exchange (`exchange_key`).
KEY_TOKEN_TYPE = "urn:agience:params:oauth:token-type:agent-key"
REVOKE_TYPE = "agent-revoke+jwt"
ASK_TYP = "agent-ask+jwt"
APPROVAL_TYP = "agent-approval+jwt"
#: The scope of the delegation an approval exchanges for: Mantle's agent routes.
AGENT_SCOPE = "mantle:agent"
#: The longest a signed ask, a revoke, or the session's actor assertion may live.
SIGNED_MAX_TTL = 300
SKEW = 30
APPROVAL_MAX_DAYS = authority_ledger.AGENT_WINDOW_MAX_DAYS
AGENT_TYPE = "application/vnd.agience.agent+json"
APPROVAL_TYPE = "application/vnd.agience.approval+json"
_MAX_ID = 128


class Refused(Exception):
    def __init__(self, detail: str, status_code: int = 401):
        super().__init__(detail)
        self.detail, self.status_code = detail, status_code


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jkt(jwk: dict) -> str:
    """The RFC 7638 thumbprint of an EC P-256 public key."""
    if (not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256"
            or not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str)
            or "d" in jwk):
        raise Refused("the key is an EC P-256 public key")
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"),
                       sort_keys=True)
    return _b64url(hashlib.sha256(canon.encode("ascii")).digest())


def endpoints() -> set:
    return {f"{(config.ORIGIN_URI or '').rstrip('/')}/auth/token",
            f"{(config.AUTHORITY_ISSUER or '').rstrip('/')}/auth/token"}


def _self_signed(token: str, typ: str) -> tuple:
    """(claims, jkt) of a JWT signed by the key in its own `jwk` header, with header `typ`, addressed
    to this token endpoint, issued now and minutes long."""
    from jose import jwt as _jwt

    try:
        header = _jwt.get_unverified_header(token)
    except Exception:  # noqa: BLE001
        raise Refused("the signed request is not a JWT")
    if header.get("typ") != typ or header.get("alg") != "ES256":
        raise Refused(f"the signed request is an ES256 {typ}")
    jwk = header.get("jwk")
    thumb = jkt(jwk)
    try:
        claims = _jwt.decode(token, jwk, algorithms=["ES256"],
                             options={"verify_aud": False, "verify_exp": False})
    except Exception:  # noqa: BLE001
        raise Refused("the signed request does not verify")
    now = datetime.now(timezone.utc).timestamp()
    iat, exp = claims.get("iat"), claims.get("exp")
    if (claims.get("aud") not in endpoints()
            or not isinstance(iat, (int, float)) or not isinstance(exp, (int, float))
            or exp <= now or exp - iat > SIGNED_MAX_TTL
            or iat > now + SKEW or exp > now + SIGNED_MAX_TTL):
        raise Refused("the signed request is for this endpoint and minutes long")
    if not isinstance(claims.get("jti"), str) or not claims["jti"]:
        raise Refused("the signed request has no jti")
    return claims, thumb


def _spend(db: Session, key: str, exp: float) -> None:
    from origin.services import key_shares as _key_shares
    if not _key_shares.spend_token(db, key, datetime.fromtimestamp(exp, timezone.utc)):
        raise Refused("the signed request was already used")


def _live_window_grant(db: Session, grant_id: str, person: Optional[str] = None):
    from origin.models.authority_ledger import AuthorityJobGrant
    row = db.get(AuthorityJobGrant, str(grant_id or ""))
    if (row is None or row.state != "active" or not authority_ledger.is_agent_window_job(row.job)
            or (person is not None and row.principal != person)):
        raise Refused("no live agent window grant", 403)
    ends = authority_ledger.parse_time(row.expires_at)
    if ends is None or ends <= datetime.now(timezone.utc):
        raise Refused("the agent window grant has ended", 403)
    return row, ends


def _window_grant_of(db: Session, window_jkt: str):
    """The live grant the person made for this window's key, found by its job when the ask names
    none: a CLI opens the job-grant page for `agent.window.<jkt>` and then asks with the key."""
    from origin.models.authority_ledger import AuthorityJobGrant
    rows = (db.query(AuthorityJobGrant)
            .filter(AuthorityJobGrant.job == authority_ledger.AGENT_WINDOW_PREFIX + window_jkt,
                    AuthorityJobGrant.state == "active").all())
    live = []
    for row in rows:
        ends = authority_ledger.parse_time(row.expires_at)
        if ends is not None and ends > datetime.now(timezone.utc):
            live.append((ends, row))
    if not live:
        raise Refused("no live agent window grant", 403)
    ends, row = max(live, key=lambda e: e[0])
    return row, ends


def _ids(value: Any, what: str) -> list:
    if (not isinstance(value, list) or not value
            or not all(isinstance(v, str) and v and len(v) <= _MAX_ID for v in value)):
        raise Refused(f"{what} is a non-empty list of ids", 400)
    return sorted(set(value))


def _person(db: Session, person_id: str):
    from origin.db import persons as db_persons
    from origin.services.auth_service import refuse_if_deactivated
    try:
        person = db_persons.get_by_id(db, person_id)
    except ValueError:
        person = None
    if person is None:
        raise Refused("no such person")
    refuse_if_deactivated(person)
    return person


@dataclass
class Ask:
    person: str
    grant_id: str
    agent_id: Optional[str]
    agent_name: str
    role: str
    actions: list
    collections: list
    home: str
    session_jkt: str
    ends: datetime


def read_ask(db: Session, token: str) -> Ask:
    """A session's ask, checked against the window grant it names; spends its jti."""
    claims, window_jkt = _self_signed(token, ASK_TYP)
    if claims.get("grant"):
        row, ends = _live_window_grant(db, str(claims["grant"]), str(claims.get("sub") or ""))
    else:
        row, ends = _window_grant_of(db, window_jkt)
    if row.job != authority_ledger.AGENT_WINDOW_PREFIX + window_jkt:
        raise Refused("the ask is not signed by the window's key", 403)
    agent = claims.get("agent")
    if not isinstance(agent, dict) or not isinstance(agent.get("name"), str) or not agent["name"]:
        raise Refused("the ask names its agent", 400)
    role = agent.get("role")
    if not isinstance(role, str) or not role or len(role) > 64:
        raise Refused("the ask names the agent's role", 400)
    actions = _ids(claims.get("actions"), "actions")
    collections = _ids(claims.get("collections"), "collections")
    ceiling = set(json.loads(row.actions or "[]"))
    reach = set(json.loads(row.reach or "[]"))
    if not set(actions) <= ceiling:
        raise Refused("the ask's actions are outside the window grant's", 403)
    if not set(collections) <= reach:
        raise Refused("the ask's collections are outside the window grant's", 403)
    home = claims.get("home")
    if home not in collections:
        raise Refused("the ask's home is one of its collections", 400)
    cnf = claims.get("cnf")
    session_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if not isinstance(session_jkt, str) or len(session_jkt) != 43:
        raise Refused("the ask binds the session's key (cnf.jkt)", 400)
    if session_jkt == window_jkt:
        raise Refused("a session's key is its own, never the window's", 400)
    agent_id = agent.get("id")
    if agent_id is not None and (not isinstance(agent_id, str) or not agent_id
                                 or len(agent_id) > _MAX_ID):
        raise Refused("the agent's id is an artifact id", 400)
    _person(db, row.principal)
    _spend(db, f"ask:{row.grant_id}:{claims['jti']}", claims["exp"])
    return Ask(person=row.principal, grant_id=row.grant_id, agent_id=agent_id,
               agent_name=agent["name"][:200], role=role, actions=actions,
               collections=collections, home=home, session_jkt=session_jkt,
               ends=min(ends, datetime.now(timezone.utc) + timedelta(days=APPROVAL_MAX_DAYS)))


#: Files the agent artifact (when the ask names none) and the approval in Mantle as the person;
#: returns the agent's id. Tests replace it.
Filer = Callable[[Session, Ask, str], Awaitable[str]]


async def file_in_mantle(db: Session, ask: Ask, jti: str) -> str:
    import httpx

    from origin.services import auth_service
    mantle = (getattr(config, "MANTLE_URI", "") or "").rstrip("/")
    if not mantle:
        raise Refused("Mantle is not configured", 503)
    token = auth_service.issue_mantle_token(
        _person(db, ask.person),
        client_id=getattr(config, "PLATFORM_CLIENT_ID", "") or "agience-client")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            agent_id = ask.agent_id
            if agent_id is None:
                r = await client.post(f"{mantle}/artifacts", headers=headers, json={
                    "container_id": ask.home, "name": ask.agent_name,
                    "content_type": AGENT_TYPE,
                    "context": json.dumps({"title": ask.agent_name, "role": ask.role}),
                    "content": ""})
                if r.status_code not in (200, 201):
                    raise Refused(f"Mantle did not file the agent ({r.status_code})", 502)
                agent_id = str(r.json().get("id") or "")
            else:
                r = await client.get(f"{mantle}/artifacts/{agent_id}", headers=headers)
                if r.status_code != 200 or r.json().get("content_type") != AGENT_TYPE:
                    raise Refused("the ask's agent is not an agent the person holds", 403)
            r = await client.post(f"{mantle}/artifacts", headers=headers, json={
                "container_id": agent_id, "name": f"Approval {jti[:8]}",
                "content_type": APPROVAL_TYPE,
                "context": json.dumps({
                    "title": f"{ask.agent_name} as {ask.role}", "state": "approved",
                    "reason": f"asked under the window grant {ask.grant_id}"}),
                "content": json.dumps({
                    "jti": jti, "role": ask.role, "actions": ask.actions,
                    "collections": ask.collections, "session_jkt": ask.session_jkt,
                    "expires_at": ask.ends.isoformat()})})
            if r.status_code not in (200, 201):
                raise Refused(f"Mantle did not file the approval ({r.status_code})", 502)
    except httpx.HTTPError as exc:
        raise Refused(f"Mantle is unreachable ({type(exc).__name__})", 502)
    if not agent_id:
        raise Refused("Mantle gave the agent no id", 502)
    return agent_id


async def approve(db: Session, ask_token: str, filer: Optional[Filer] = None) -> dict:
    """The approval token for a session's signed ask."""
    from jose import jwt as _jwt

    from origin.services.auth_service import JWT_ALGORITHM, get_key_id, get_private_key_pem
    ask = read_ask(db, ask_token)
    jti = secrets.token_hex(16)
    agent_id = await (filer or file_in_mantle)(db, ask, jti)
    now = datetime.now(timezone.utc)
    claims = {"iss": config.AUTHORITY_ISSUER, "sub": ask.person, "aud": [agent_id],
              "token_type": "agent-approval", "cnf": {"jkt": ask.session_jkt},
              "agent": agent_id, "role": ask.role, "actions": ask.actions,
              "collections": ask.collections, "job_grant": ask.grant_id, "jti": jti,
              "iat": int(now.timestamp()), "exp": int(ask.ends.timestamp())}
    token = _jwt.encode(claims, get_private_key_pem(), algorithm=JWT_ALGORITHM,
                        headers={"kid": get_key_id(), "typ": APPROVAL_TYP})
    db.add(AgentApproval(jti=jti, grant_id=ask.grant_id, person=ask.person, agent=agent_id,
                         session_jkt=ask.session_jkt, expires_at=ask.ends))
    db.commit()
    logger.info("agent approval %s for agent %s under %s", jti[:8], agent_id, ask.grant_id)
    return {"access_token": token, "issued_token_type": APPROVAL_TOKEN_TYPE,
            "token_type": "N_A", "expires_in": int(ask.ends.timestamp() - now.timestamp()),
            "agent": agent_id}


def _approval_claims(token: str) -> dict:
    """The verified claims of an Origin-signed approval token."""
    from jose import jwt as _jwt

    from origin.services.auth_verifier import verify_token
    try:
        header = _jwt.get_unverified_header(token)
    except Exception:  # noqa: BLE001
        raise Refused("the approval is not a JWT")
    if header.get("typ") != APPROVAL_TYP:
        raise Refused("the subject is not an approval")
    claims = verify_token(token)
    if (not claims or claims.get("iss") != config.AUTHORITY_ISSUER
            or claims.get("token_type") != "agent-approval"):
        raise Refused("the approval does not verify")
    return claims


def exchange(db: Session, approval: str, actor_token: Optional[str]) -> dict:
    """A five-minute delegation to Mantle for an approval and the session key's actor JWT."""
    from jose import jwt as _jwt

    from origin.models.narrow_hop import NarrowHop
    from origin.services import auth_service
    from origin.services import not_before as _not_before
    claims = _approval_claims(approval)
    row = db.get(AgentApproval, str(claims.get("jti") or ""))
    if row is None or row.revoked_at is not None:
        raise Refused("the approval is revoked")
    _live_window_grant(db, row.grant_id, row.person)
    if str(claims.get("sub")) != row.person or claims.get("agent") != row.agent:
        raise Refused("the approval does not match its record")
    if _not_before.ended(db, claims):
        raise Refused("this sign-in has ended; ask again")
    person = _person(db, row.person)
    if not actor_token:
        raise Refused("the exchange needs the session key's actor token")
    actor, thumb = _self_signed(actor_token, "JWT")
    if thumb != row.session_jkt or (claims.get("cnf") or {}).get("jkt") != thumb:
        raise Refused("the actor is not the session key the approval binds", 403)
    if actor.get("iss") != row.agent or actor.get("sub") != row.agent:
        raise Refused("the actor token is the agent's own (iss = sub = the agent)")
    if actor.get("subject_digest") != hashlib.sha256(approval.encode()).hexdigest():
        raise Refused("the actor token is not bound to this approval")
    _spend(db, f"agent:{row.agent}:{actor['jti']}", actor["exp"])
    ends = datetime.fromtimestamp(float(claims["exp"]), timezone.utc)
    token = auth_service.issue_narrow_delegation(
        str(person.id), auth_service.MANTLE_AUDIENCE, [AGENT_SCOPE], expires_at=ends,
        actor=row.agent, job_reach=list(claims.get("collections") or []),
        job_grant=row.grant_id, reach_actions=list(claims.get("actions") or []))
    issued = _jwt.get_unverified_claims(token)
    db.add(NarrowHop(jti=str(issued["jti"]), sub=str(person.id), subject_jti=row.jti,
                     from_aud=f"agent:{row.agent}", to_aud=auth_service.MANTLE_AUDIENCE))
    db.commit()
    return {"access_token": token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "bearer",
            "expires_in": max(0, int(issued["exp"] - datetime.now(timezone.utc).timestamp())),
            "scope": AGENT_SCOPE}


#: The shape of a Key artifact's token: its type's prefix, the Key's id, a dot, the secret.
_KEY_SHAPE = re.compile(r"^agk_[A-Za-z0-9-]{1,128}\.[A-Za-z0-9_-]{20,}$")

#: Reads what a Key token is from Mantle: ``async (key) -> dict``.
KeyReader = Callable[[str], Awaitable[dict]]


async def read_key_in_mantle(key: str) -> dict:
    """What Mantle says the Key token ``key`` is (``GET /credentials/self``, the key as the
    bearer): the person, the agent, the reach, the actions, the end."""
    import httpx
    mantle = (getattr(config, "MANTLE_URI", "") or "").rstrip("/")
    if not mantle:
        raise Refused("Mantle is not configured", 503)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{mantle}/credentials/self",
                                 headers={"Authorization": f"Bearer {key}"})
    except httpx.HTTPError as exc:
        raise Refused(f"Mantle is unreachable ({type(exc).__name__})", 502)
    if r.status_code in (401, 403, 404):
        raise Refused("the key is not live")
    if r.status_code != 200:
        raise Refused(f"Mantle did not read the key ({r.status_code})", 502)
    return r.json()


async def exchange_key(db: Session, key: str, reader: Optional[KeyReader] = None) -> dict:
    """A five-minute delegation to Mantle for an agent's Key artifact token."""
    from jose import jwt as _jwt

    from origin.models.narrow_hop import NarrowHop
    from origin.services import auth_service
    if not isinstance(key, str) or not _KEY_SHAPE.match(key):
        raise Refused("the actor is not an agent's key")
    seen = await (reader or read_key_in_mantle)(key)
    actor, artifact = str(seen.get("actor") or ""), str(seen.get("artifact") or "")
    reach, actions = seen.get("reach"), seen.get("actions")
    if not actor:
        raise Refused("the key names no agent: a person's own key is used at Mantle as it is")
    if (seen.get("scope") != AGENT_SCOPE or not artifact
            or not key.startswith(f"agk_{artifact}.")
            or not isinstance(reach, list) or not reach
            or not isinstance(actions, list) or not actions):
        raise Refused("the key does not say whom it acts for and what it reaches")
    person = _person(db, str(seen.get("person") or ""))
    ends = None
    if seen.get("ends"):
        ends = authority_ledger.parse_time(str(seen["ends"]))
        if ends is None or ends <= datetime.now(timezone.utc):
            raise Refused("the key has ended")
    token = auth_service.issue_narrow_delegation(
        str(person.id), auth_service.MANTLE_AUDIENCE, [AGENT_SCOPE], expires_at=ends,
        actor=actor, job_reach=[str(i) for i in reach],
        reach_actions=[str(a) for a in actions])
    issued = _jwt.get_unverified_claims(token)
    db.add(NarrowHop(jti=str(issued["jti"]), sub=str(person.id), subject_jti=artifact[:64],
                     from_aud=f"key:{actor}"[:128], to_aud=auth_service.MANTLE_AUDIENCE))
    db.commit()
    return {"access_token": token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "bearer",
            "expires_in": max(0, int(issued["exp"] - datetime.now(timezone.utc).timestamp())),
            "scope": AGENT_SCOPE}


def revoke_approvals(db: Session, *, grant_id: Optional[str] = None,
                     person: Optional[str] = None, jti: Optional[str] = None) -> int:
    """Mark the approvals under a grant, of a person, or one by jti revoked; returns how many."""
    q = db.query(AgentApproval).filter(AgentApproval.revoked_at.is_(None))
    if grant_id is not None:
        q = q.filter(AgentApproval.grant_id == grant_id)
    if person is not None:
        q = q.filter(AgentApproval.person == person)
    if jti is not None:
        q = q.filter(AgentApproval.jti == jti)
    now = datetime.now(timezone.utc)
    n = 0
    for row in q.all():
        row.revoked_at = now
        n += 1
    return n


def revoke(db: Session, token: str) -> dict:
    """A signed revoke (`typ` `agent-revoke+jwt`): by the window's key, its grant and every approval
    under it; by a session's key, that session's approval (`approval` names its jti). A window's
    revoke that names no grant ends the live grant made for its key."""
    claims, thumb = _self_signed(token, REVOKE_TYPE)
    if claims.get("grant"):
        row, _ = _live_window_grant(db, str(claims["grant"]), str(claims.get("sub") or ""))
    else:
        row, _ = _window_grant_of(db, thumb)
    grant_id = row.grant_id
    if row.job == authority_ledger.AGENT_WINDOW_PREFIX + thumb:
        _spend(db, f"revoke:{grant_id}:{claims['jti']}", claims["exp"])
        authority_ledger.page_revoke_job_grant(db, row.principal, grant_id=grant_id)
        n = revoke_approvals(db, grant_id=grant_id)
        db.commit()
        return {"revoked": "window", "approvals": n}
    approval = db.get(AgentApproval, str(claims.get("approval") or ""))
    if approval is None or approval.grant_id != grant_id or approval.session_jkt != thumb:
        raise Refused("the revoke is signed by neither the window's key nor the session's", 403)
    _spend(db, f"revoke:{grant_id}:{claims['jti']}", claims["exp"])
    n = revoke_approvals(db, jti=approval.jti)
    db.commit()
    return {"revoked": "session", "approvals": n}
