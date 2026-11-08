"""A software passkey and the operator console calls that use it, for tests.

`Authenticator` is a P-256 WebAuthn authenticator in a few lines: it registers a credential for a
person straight into `passkey_credentials`, and answers an authentication challenge with a real
assertion (authenticator data with user presence and verification, client data, an ECDSA
signature) that `webauthn.verify_authentication_response` checks like any other. Nothing in the
verification path is replaced.

`call(c, method, path, json=...)` is one operator action: sign in to the console once per client,
obtain a step-up challenge bound to this request, sign it, send the request.

Imports happen inside the functions: the `origin_app` fixture reloads `origin.config`, so a module
level import would bind to a stale copy.
"""
from __future__ import annotations

import base64
import hashlib
import json as jsonlib
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Authenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0

    def cose_key(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"),
                            -3: n.y.to_bytes(32, "big")})

    def register(self, person_id: str) -> "Authenticator":
        from origin.db import passkey_credentials as db_passkeys
        from origin.db.session import SessionLocal

        with SessionLocal() as db:
            db_passkeys.create(db, {"id": _b64(self.cred_id), "person_id": person_id,
                                    "public_key": self.cose_key(), "sign_count": 0,
                                    "transports": ["internal"]})
            db.commit()
        return self

    def assertion(self, options: dict, *, verified: bool = True, origin: str = None) -> dict:
        """An assertion made on `origin` (Origin's own page unless given)."""
        from origin.services import passkey_service

        client_data = jsonlib.dumps({"type": "webauthn.get", "challenge": options["challenge"],
                                     "origin": origin or passkey_service.expected_origin(),
                                     "crossOrigin": False}).encode()
        self.count += 1
        flags = 0x05 if verified else 0x01             # user present, user verified
        auth_data = (hashlib.sha256(options["rpId"].encode()).digest() + bytes([flags])
                     + self.count.to_bytes(4, "big"))
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(),
                            ec.ECDSA(hashes.SHA256()))
        return {"id": _b64(self.cred_id), "rawId": _b64(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": _b64(client_data),
                             "authenticatorData": _b64(auth_data), "signature": _b64(sig)}}


def sign_in(c, authenticator: Authenticator) -> str:
    opts = c.post("/oracle/console/sign-in-options")
    assert opts.status_code == 200, opts.text
    r = c.post("/oracle/console/sign-in", json={"challenge": opts.json()["challenge"],
                                                 "credential": authenticator.assertion(opts.json())})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def console(c):
    """The operator's (authenticator, console token) for this client, set up on first use. The
    operator must already be set (`authority_fixtures.operator`)."""
    from origin.tests import authority_fixtures as af

    held = getattr(c, "_operator_console", None)
    if held is None:
        auth = Authenticator().register(af.OPERATOR)
        held = (auth, sign_in(c, auth))
        c._operator_console = held
    return held


def step_up(c, token: str, authenticator: Authenticator, method: str, path: str,
            body: bytes, *, verified: bool = True) -> str:
    from origin.services import operator_console

    opts = c.post("/oracle/console/step-up-options",
                  json={"method": method, "path": path,
                        "body_sha256": hashlib.sha256(body).hexdigest()},
                  headers={"Authorization": f"Bearer {token}"})
    assert opts.status_code == 200, opts.text
    step = {"challenge": opts.json()["challenge"],
            "credential": authenticator.assertion(opts.json(), verified=verified)}
    assert operator_console.STEP_UP_HEADER
    return _b64(jsonlib.dumps(step).encode())


def call(c, method: str, path: str, json=None, *, token: str = None, step: str = None):
    """One operator action, with the console token and a fresh step-up for this request."""
    from origin.services import operator_console

    auth, console_token = console(c)
    token = token or console_token
    body = b"" if json is None else jsonlib.dumps(json).encode()
    step = step if step is not None else step_up(c, console_token, auth, method, path, body)
    headers = {"Authorization": f"Bearer {token}", operator_console.STEP_UP_HEADER: step}
    if json is not None:
        headers["Content-Type"] = "application/json"
    return c.request(method, path, content=body if json is not None else None, headers=headers)


def origin_page_session(c, person_id: str) -> None:
    """The person's own Origin session (the cookie Origin's own sign-in sets) on this client: what
    a change to how they sign in is made in (review 8, R1)."""
    from origin.db.session import SessionLocal
    from origin.services import origin_session

    with SessionLocal() as db:
        raw = origin_session.issue(db, person_id)
        db.commit()
    c.cookies.set(origin_session.cookie_name(), raw)


def person_reauth(c, token: str, person_id: str, method: str, path: str, body: bytes) -> str:
    """A person with no passkey steps up for one request by signing in again through a method
    already theirs (here their local sign-in, recorded first): the ticket, proven at
    `/auth/reauth/complete` with a sign-in code Origin minted for it. Returns the header value."""
    from datetime import datetime, timezone

    from origin import config
    from origin.db import person_identities as db_identities
    from origin.db.session import SessionLocal
    from origin.routers import auth_router
    from origin.services import person_step_up

    with SessionLocal() as db:
        if db_identities.get_by_identity(db, method="oidc", provider="local",
                                         subject=str(person_id)) is None:
            db_identities.add(db, person_id=person_id, method="oidc", provider="local",
                              subject=str(person_id), verified=True)
            db.commit()
    origin_page_session(c, person_id)
    opts = c.post("/auth/me/step-up-options",
                  json={"method": method, "path": path,
                        "body_sha256": hashlib.sha256(body).hexdigest(),
                        **({"body": body.decode()} if body else {})},
                  headers={"Authorization": f"Bearer {token}"})
    assert opts.status_code == 200 and opts.json()["kind"] == "reauth", opts.text
    ticket = opts.json()["ticket"]
    # The start page shows the action; the person confirms it there.
    start = c.get("/auth/reauth/start", params={"ticket": ticket})
    assert start.status_code == 200, start.text
    csrf = start.text.split('name="csrf" value="')[1].split('"')[0]
    go = c.post("/auth/reauth/start", data={"ticket": ticket, "csrf": csrf},
                follow_redirects=False)
    assert go.status_code == 303, go.text
    code = "reauth-" + os.urandom(12).hex()
    auth_router.authorization_codes[code] = {
        "user_info": {"provider": "local", "sub": str(person_id), "email": "", "name": "",
                      "picture": None, "email_verified": True},
        "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "redirect_uri": person_step_up.complete_uri(), "scope": "openid",
        "code_challenge": person_step_up.code_challenge(ticket), "code_challenge_method": "S256",
        "timestamp": datetime.now(timezone.utc),
        "auth_time": int(datetime.now(timezone.utc).timestamp())}
    done = c.get("/auth/reauth/complete", params={"code": code, "state": ticket})
    assert done.status_code == 200, done.text
    return f"reauth:{ticket}"
