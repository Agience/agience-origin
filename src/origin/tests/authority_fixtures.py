"""Shared helpers for the authority-ledger tests: people, submissions and releases over HTTP.

Every entry here goes through `POST /internal/authority/entries` on a really signed Mantle service
token and a really signed acting credential, so the replica a test sets up is one Origin built
itself from co-signed entries.
"""
from __future__ import annotations

import hashlib
import uuid

from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

OPERATOR = "00000000-0000-0000-0000-0000000000aa"


def person(name: str = "", *, email: str = "", verified: bool = True) -> tuple:
    """A live person: `(id, access token)`."""
    from origin import config
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import create_jwt_token

    with SessionLocal() as db:
        p = db_persons.create(db, {"email": email or f"{uuid.uuid4().hex}@x.test",
                                   "name": name or "P", "username": uuid.uuid4().hex[:12],
                                   "email_verified": verified})
        pid = str(p.id)
        db.commit()
    return pid, create_jwt_token({"sub": pid, "email": "p@x.test", "name": "P",
                                  "client_id": "platform", "aud": config.AUTHORITY_ISSUER})


def operator(monkeypatch) -> str:
    """Make `OPERATOR` the platform operator, and return their access token."""
    from origin import config
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.services.auth_service import create_jwt_token
    from origin.services.platform_settings_service import settings as platform_settings

    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw:
                        OPERATOR if k == "platform.operator_id" else real_get(k, *a, **kw))
    from origin.models.person import Person
    with SessionLocal() as db:
        if db.get(Person, uuid.UUID(OPERATOR)) is None:
            db_persons.create(db, {"id": OPERATOR, "email": "op@x.test", "name": "Op",
                                   "username": "op"})
            db.commit()
    return create_jwt_token({"sub": OPERATOR, "email": "op@x.test", "name": "Op",
                             "client_id": "platform", "aud": config.AUTHORITY_ISSUER})


def open_bootstrap(c, operator_token=None, minutes=60, ids=None) -> str:
    """The operator obtains a bootstrap credential, through the operator console; returns it.
    `ids` names the unseen ids a window opened after cutover may state."""
    from origin.tests import operator_console_fixtures as oc

    body = {"minutes": minutes}
    if ids is not None:
        body["ids"] = list(ids)
    r = oc.call(c, "POST", "/oracle/authority-ledger/bootstrap", json=body)
    assert r.status_code == 200, r.text
    return r.json()["token"]


#: What Origin answers when an authority change comes on a token Mantle holds (review 12).
SESSION_ONLY = "made in the person's Origin session"


class _Answer:
    """What a session route would have answered, for a change made through the ledger call the
    session routes themselves make."""

    def __init__(self, status_code: int, body: dict):
        self.status_code, self._body = status_code, body
        self.text = __import__("json").dumps(body)

    def json(self):
        return self._body


def session_submit(c, person_id: str, entry: dict, proof: dict = None):
    """The person makes `entry` in their own Origin session, as the web app does (review 12).
    An edge change goes through `POST /auth/me/authority/entries` with the custom header and the
    web app's `Origin`. A grant, deny or invite (whose session routes build the entry themselves,
    review 13) goes through the ledger call those routes make, as the person's session entry, so
    a test can state the grant it sets up."""
    from origin import config
    from origin.tests import operator_console_fixtures as oc

    if entry.get("kind") == "grant":
        from origin.db.session import SessionLocal
        from origin.services import authority_ledger
        with SessionLocal() as db:
            try:
                return _Answer(200, authority_ledger.session_entry(db, person_id, entry, proof))
            except authority_ledger.EntryRefused as exc:
                return _Answer(exc.status, {"detail": str(exc)})
    oc.origin_page_session(c, person_id)
    body = {"entry": entry, **({"proof": proof} if proof else {})}
    return c.post("/auth/me/authority/entries", json=body,
                  headers={"X-Origin-Session": "1",
                           "Origin": config.APP_URI or config.ORIGIN_URI})


def submit(c, credential, entry: dict, *, bootstrap: bool = False, digest: str = "",
           proof: dict = None, compensates: int = None, batch="test", via_session=True):
    """`batch`: the submission batch (one operation), named here and issued by Origin. The first
    submission under a name on a credential carries none and Origin issues one; later ones under
    that name and credential carry it. By default every submission of a test on one credential
    shares one; pass `batch=None` for a batch of its own, or a name.

    An authority change Origin takes only in the person's Origin session (review 12) is made
    there instead when the credential is a person's own access token, so a test that sets up a
    grant reads as before; `via_session=False` keeps to the credential path."""
    from origin.services.authority_ledger import body_digest, proof_digest

    if entry.get("kind") == "root" and not bootstrap and proof is None:
        proof = creation(credential)
    extra = {"htu": "/internal/authority/entries",
             "body_sha256": digest or body_digest(entry)}
    if bootstrap:
        extra["bootstrap"] = True
    if proof:
        extra["proof_sha256"] = proof_digest(proof)
    if compensates is not None:
        extra["compensates"] = compensates
    issued = c.__dict__.setdefault("_issued_batches", {})
    name = (batch, hashlib.sha256(credential.encode()).hexdigest()) if batch is not None else None
    batch = issued.get(name) if name else None
    if batch is not None:
        extra["batch"] = batch
    tok = _shares._token("POST", "-", **extra)
    body = {"entry": entry, "bootstrap": bootstrap}
    if proof:
        body["proof"] = proof
    if compensates is not None:
        body["compensates"] = compensates
    if batch is not None:
        body["batch"] = batch
    r = c.post("/internal/authority/entries", json=body,
               headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})
    if name and r.status_code == 200 and r.json().get("batch"):
        issued.setdefault(name, r.json()["batch"])
    if (via_session and r.status_code == 403 and SESSION_ONLY in r.text and not bootstrap
            and compensates is None):
        from jose import jwt as jose_jwt
        claims = jose_jwt.get_unverified_claims(credential)
        if claims.get("principal_type", "user") == "user" and claims.get("sub"):
            return session_submit(c, str(claims["sub"]), entry, proof)
    return r


def creation(credential, *, minutes_ago=0) -> dict:
    """The creation the store recorded for a new key principal: made by the credential's subject,
    `minutes_ago` minutes ago."""
    from datetime import datetime, timedelta, timezone

    from jose import jwt as jose_jwt

    sub = jose_jwt.get_unverified_claims(credential)["sub"]
    when = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return {"created_by": str(sub), "created_at": when.isoformat()}


def grant(gid, grantee, resource, actions=("read",), *, effect="allow", state="active",
          grantee_type="user", expires_at=None, target=None, max_claims=None) -> dict:
    return {"kind": "grant", "grant_id": gid, "grantee_id": grantee,
            "grantee_type": grantee_type, "resource_id": resource, "actions": list(actions),
            "effect": effect, "state": state, "expires_at": expires_at, "target": target,
            "max_claims": max_claims}


def invite(gid, token, resource, actions=("read",), *, target=None, max_claims=None,
           expires_at=None, state="active") -> dict:
    """An invite whose grantee is the claim token's hash; `target` is `(kind, value)`."""
    from origin.services.authority_ledger import target_digest

    t = {"kind": target[0], "digest": target_digest(*target)} if target else None
    return grant(gid, hashlib.sha256(token.encode()).hexdigest(), resource, actions,
                 grantee_type="invite", expires_at=expires_at, target=t, max_claims=max_claims,
                 state=state)


def edge(src, dst, *, origin=True, propagate=None) -> dict:
    return {"kind": "edge.add", "src": src, "dst": dst, "origin": origin, "propagate": propagate}


def unedge(src, dst) -> dict:
    return {"kind": "edge.remove", "src": src, "dst": dst}


def root(principal, root_id=None) -> dict:
    return {"kind": "root", "principal_id": principal, "root_id": root_id or principal}


def ok(r):
    assert r.status_code == 200, r.text
    return r.json()


def release(c, principal, credential, *, collection=None, artifact=None):
    params, extra = {}, {}
    if collection:
        params["collection_id"] = extra["collection_id"] = collection
    if artifact:
        params["artifact_id"] = extra["artifact_id"] = artifact
    tok = _shares._token("GET", principal, **extra)
    return c.get(f"/internal/key-shares/{principal}", params=params,
                 headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def store_share(c, principal, credential="own", **body):
    """Store a share, on the key principal's own credential unless `credential` is given (a
    first share needs its principal's or its creator's); `None` sends none."""
    tok = _shares._token("PUT", principal)
    headers = {"Authorization": f"Bearer {tok}"}
    if credential == "own":
        try:
            credential = _shares.own_credential(principal)
        except Exception:  # noqa: BLE001 — a key Origin cannot mint for: stored without one
            credential = None
    if credential:
        headers["X-Acting-Credential"] = credential
    r = c.put(f"/internal/key-shares/{principal}",
              json={"x": 2, "y": _shares.SHARE_Y, "kcv": _shares.KCV_A, **body}, headers=headers)
    return r


#: Job grants a test states as held without a grantor: read by the ledger's test-only seam
#: (`authority_ledger._held_for_tests`), never in production.
HELD_FOR_TESTS: set = set()


def background(principal: str, *, job: str = "test.job", collections=()) -> str:
    """A background delegation for `principal`: a live job grant written straight to the replica
    (as a co-signed `job_grant` would leave it), then minted under it."""
    import json
    from datetime import datetime, timedelta, timezone

    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant
    from origin.services import share_credentials

    with SessionLocal() as db:
        gid = f"jg-test-{job}-{principal}"
        HELD_FOR_TESTS.add(gid)                        # stated with no grantor to check
        if db.get(AuthorityJobGrant, gid) is None:
            db.add(AuthorityJobGrant(
                grant_id=gid, job=job, principal=principal, collections=json.dumps(list(collections)),
                expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                state="active", created_by="", seq=0))
            db.commit()
        return share_credentials.mint_background_delegation(db, principal, job)["token"]


class _Answer:
    def __init__(self, status_code: int, body: dict):
        self.status_code, self._body = status_code, body
        self.text = __import__("json").dumps(body)

    def json(self):
        return self._body


def page(person_id: str, entry: dict) -> "_Answer":
    """A ledger entry Origin appends for a person at its own page (their Origin session and a
    step-up, which `/auth/me/job-grants` checks): how a job grant is made (review 9, H2). Answers
    like a submission, so a refusal reads the same."""
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    with SessionLocal() as db:
        try:
            return _Answer(200, al.append(db, entry, actor=al.Actor(person_id, al.ORIGIN_PAGE,
                                                                     f"page:{person_id}")))
        except al.EntryRefused as exc:
            return _Answer(exc.status, {"detail": str(exc)})

def refresh_client(token: str) -> str:
    """The client a refresh token was issued to: what its client names when it refreshes (review
    11, M1)."""
    from jose import jwt as jose_jwt
    claims = jose_jwt.get_unverified_claims(token)
    return str(claims.get("client_id") or claims.get("aud") or "")


def deleted_member(c, credential, owner_id: str, src: str, member: str, grant_id: str,
                   actions=("read", "update", "delete")) -> dict:
    """`member` made in `src` by its owner with their creation grant, then deleted on the same
    credential: the creation edge removed and the grant retired, in one batch (review 12: the
    grant change a token Mantle holds may still make). Returns the retirement's receipt, which
    Mantle withdraws when its write fails."""
    made, gone = f"made-{member}", f"gone-{member}"
    ok(submit(c, credential, edge(src, member), batch=made, via_session=False))
    ok(submit(c, credential, grant(grant_id, owner_id, member, list(actions)), batch=made,
              via_session=False))
    ok(submit(c, credential, unedge(src, member), batch=gone, via_session=False))
    return ok(submit(c, credential, grant(grant_id, owner_id, member, list(actions),
                                          state="deleted"), batch=gone, via_session=False))
