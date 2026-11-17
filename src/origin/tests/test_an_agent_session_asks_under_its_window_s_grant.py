"""An agent session's Mantle token (FR-032): the window's standing grant, the session's signed ask,
Origin's approval token, and its RFC 8693 exchange with the session key as the RFC 7523 actor.

Research's three checks:
1. The window key only signs asks: Origin takes it as no actor and no subject, and it alone yields
   no Mantle token.
2. An ask stays within its grant's collections and actions; the token it exchanges for is the
   person's (`sub`) acted by the agent (`act.sub`), scope `mantle:agent`, never a person's own.
3. Revoking the grant (or signing out everywhere) revokes every approval made under it, and the
   next exchange is refused.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwk as jose_jwk
from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_background_work_runs_on_a_job_grant as _jobs

custody_client = _jobs.custody_client
people = _jobs.people

ACTIONS = ["create", "read", "update"]
REACH = ["ws-home", "ws-2"]


class Key:
    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.priv.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()).decode()
        pub = jose_jwk.construct(self.priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "ES256").to_dict()
        self.jwk = {k: pub[k] for k in ("kty", "crv", "x", "y")}
        from origin.services.agent_sessions import jkt
        self.jkt = jkt(self.jwk)

    def sign(self, claims, typ):
        return jose_jwt.encode(claims, self.pem, algorithm="ES256",
                               headers={"typ": typ, "jwk": self.jwk})


def _endpoint():
    from origin import config
    return f"{config.AUTHORITY_ISSUER.rstrip('/')}/auth/token"


def _window_grant(gid, person, window: Key, *, reach=REACH, actions=ACTIONS, days=1):
    return {**_jobs.job_grant(gid, f"agent.window.{window.jkt}", person,
                              expires_at=(datetime.now(timezone.utc)
                                          + timedelta(days=days)).isoformat()),
            "reach": list(reach), "actions": list(actions)}


def _ask(window: Key, person, session: Key, *, grant="jg-w", actions=("read",),
         collections=("ws-home",), home="ws-home", agent=None):
    now = int(time.time())
    claims = {"sub": person, "aud": _endpoint(), "iat": now, "exp": now + 120,
              "jti": secrets.token_hex(8), "grant": grant,
              "agent": agent or {"name": "Build agent", "role": "builder"},
              "actions": list(actions), "collections": list(collections),
              "home": home, "cnf": {"jkt": session.jkt}}
    return window.sign({k: v for k, v in claims.items() if v is not None}, "agent-ask+jwt")


def _actor(session: Key, agent, approval):
    now = int(time.time())
    return session.sign({"iss": agent, "sub": agent, "aud": _endpoint(), "iat": now,
                         "exp": now + 60, "jti": secrets.token_hex(8),
                         "subject_digest": hashlib.sha256(approval.encode()).hexdigest()}, "JWT")


def _exchange(c, subject, subject_type, actor=None):
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject, "subject_token_type": subject_type}
    if actor:
        data["actor_token"] = actor
    return c.post("/auth/token", data=data)


ASK = "urn:agience:params:oauth:token-type:agent-ask"
APPROVAL = "urn:agience:params:oauth:token-type:agent-approval"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"


@pytest.fixture
def filed(monkeypatch):
    """Mantle stubbed: the agent and approval artifacts filed are recorded here."""
    from origin.services import agent_sessions
    seen = []

    async def filer(db, ask, jti):
        seen.append((ask, jti))
        return ask.agent_id or f"agent-{len(seen)}"
    monkeypatch.setattr(agent_sessions, "file_in_mantle", filer)
    return seen


def _approved(c, person, window, session, **kw):
    r = _exchange(c, _ask(window, person, session, **kw), ASK)
    assert r.status_code == 200, r.text
    return r.json()


def test_an_approval_carries_everything_and_exchanges_for_an_agent_token(custody_client, people,
                                                                          filed):
    c, alice = custody_client, people["alice"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    out = _approved(c, alice, window, session, actions=("read", "create"))
    approval = out["access_token"]
    claims = jose_jwt.get_unverified_claims(approval)
    assert jose_jwt.get_unverified_header(approval)["typ"] == "agent-approval+jwt"
    assert claims["sub"] == alice and claims["aud"] == [out["agent"]]
    assert claims["cnf"] == {"jkt": session.jkt} and claims["role"] == "builder"
    assert claims["actions"] == ["create", "read"] and claims["collections"] == ["ws-home"]
    assert claims["job_grant"] == "jg-w" and claims["exp"] - claims["iat"] <= 7 * 86400
    assert len(filed) == 1 and filed[0][1] == claims["jti"]
    r = _exchange(c, approval, APPROVAL, _actor(session, out["agent"], approval))
    assert r.status_code == 200, r.text
    tok = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert tok["sub"] == alice and tok["act"] == {"sub": out["agent"]} and tok["aud"] == "mantle"
    assert tok["scope"] == "mantle:agent" and tok["narrowed"] is True
    assert tok["job_reach"] == ["ws-home"] and tok["reach_actions"] == ["create", "read"]
    assert tok["exp"] - tok["iat"] <= 300


# -- 1. the window key only signs asks -------------------------------------------------------------

def test_the_window_key_is_no_actor_and_no_subject(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    approval = _approved(c, alice, window, session)
    agent = jose_jwt.get_unverified_claims(approval["access_token"])["agent"]
    # As the actor: its thumbprint is not the approval's cnf.jkt.
    r = _exchange(c, approval["access_token"], APPROVAL,
                  _actor(window, agent, approval["access_token"]))
    assert r.status_code == 403
    # As a subject, an ask or anything it signs is no access token and no approval.
    ask = _ask(window, alice, session)
    for typ in (ACCESS, APPROVAL):
        assert _exchange(c, ask, typ).status_code in (400, 401, 403), typ
    forged = window.sign({**jose_jwt.get_unverified_claims(approval["access_token"])},
                         "agent-approval+jwt")
    assert _exchange(c, forged, APPROVAL, _actor(session, agent, forged)).status_code == 401
    # An ask whose session key is the window's own is refused.
    assert _exchange(c, _ask(window, alice, window), ASK).status_code == 400


def test_an_ask_is_signed_by_its_grant_s_window_and_used_once(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, other, session = Key(), Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    assert _exchange(c, _ask(other, alice, session), ASK).status_code == 403
    ask = _ask(window, alice, session)
    assert _exchange(c, ask, ASK).status_code == 200
    assert _exchange(c, ask, ASK).status_code == 401                 # replayed


def test_an_actor_token_is_used_once_and_bound_to_its_approval(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    a1 = _approved(c, alice, window, session)["access_token"]
    a2 = _approved(c, alice, window, session)["access_token"]
    agent = jose_jwt.get_unverified_claims(a1)["agent"]
    actor = _actor(session, agent, a1)
    assert _exchange(c, a2, APPROVAL, actor).status_code in (401, 403)   # bound to a1
    assert _exchange(c, a1, APPROVAL, actor).status_code == 200
    assert _exchange(c, a1, APPROVAL, actor).status_code == 401          # spent
    assert _exchange(c, a1, APPROVAL).status_code == 401                 # no actor


# -- 2. within the grant and the role's ceiling ----------------------------------------------------

def test_an_ask_stays_within_its_grant(custody_client, people, filed):
    c, alice, bob = custody_client, people["alice"][0], people["bob"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    assert _exchange(c, _ask(window, alice, session, actions=("delete",)), ASK).status_code == 403
    assert _exchange(c, _ask(window, alice, session, collections=("ws-x",), home="ws-x"),
                     ASK).status_code == 403
    assert _exchange(c, _ask(window, alice, session, home="ws-2"), ASK).status_code == 400
    assert _exchange(c, _ask(window, bob, session), ASK).status_code == 403   # not bob's grant
    assert _exchange(c, _ask(window, alice, session, grant="jg-none"), ASK).status_code == 403


def test_a_window_grant_is_bounded_where_it_is_made(custody_client, people):
    alice = people["alice"][0]
    window = Key()
    assert af.page(alice, _window_grant("jg-1", alice, window, days=8)).status_code == 400
    assert af.page(alice, _window_grant("jg-2", alice, window,
                                        actions=["admin"])).status_code == 400
    assert af.page(alice, {**_window_grant("jg-3", alice, window),
                           "actions": []}).status_code == 400
    assert af.page(alice, {**_jobs.job_grant("jg-4", "platform.reindex", alice),
                           "actions": ["read"]}).status_code == 400
    from origin.services import auth_service
    claims = {"job_reach": ["a"], "job_grant": "g", "reach_actions": ["read"]}
    assert auth_service.job_reach_of(claims)["reach_actions"] == ["read"]


def test_an_approval_is_no_bearer_token(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    approval = _approved(c, alice, window, session)["access_token"]
    assert c.get("/auth/me/job-grants", headers={"Authorization": f"Bearer {approval}"}).status_code == 401
    assert _exchange(c, approval, ACCESS).status_code in (400, 401, 403)


# -- 3. revocation -------------------------------------------------------------------------------

def test_revoking_the_grant_revokes_every_approval_under_it(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, s1, s2 = Key(), Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    a1 = _approved(c, alice, window, s1)["access_token"]
    a2 = _approved(c, alice, window, s2)["access_token"]
    agent1 = jose_jwt.get_unverified_claims(a1)["agent"]
    agent2 = jose_jwt.get_unverified_claims(a2)["agent"]
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al
    with SessionLocal() as db:
        al.page_revoke_job_grant(db, alice, "jg-w")
    assert _exchange(c, a1, APPROVAL, _actor(s1, agent1, a1)).status_code == 401
    assert _exchange(c, a2, APPROVAL, _actor(s2, agent2, a2)).status_code == 401
    assert _exchange(c, _ask(window, alice, s1), ASK).status_code == 403


def test_signing_out_everywhere_revokes_the_approvals(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    a = _approved(c, alice, window, session)["access_token"]
    agent = jose_jwt.get_unverified_claims(a)["agent"]
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al
    with SessionLocal() as db:
        assert al.revoke_person_job_grants(db, alice) >= 1
        db.commit()
    assert _exchange(c, a, APPROVAL, _actor(session, agent, a)).status_code == 401


def _revoke(c, key: Key, person, *, grant="jg-w", approval=None):
    now = int(time.time())
    claims = {"sub": person, "aud": _endpoint(), "iat": now, "exp": now + 60,
              "jti": secrets.token_hex(8), "grant": grant, "approval": approval}
    tok = key.sign({k: v for k, v in claims.items() if v is not None}, "agent-revoke+jwt")
    return c.post("/auth/agent-sessions/revoke", data={"token": tok})


def test_the_window_and_a_session_revoke_with_their_own_keys(custody_client, people, filed):
    c, alice = custody_client, people["alice"][0]
    window, s1, s2, stranger = Key(), Key(), Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    a1 = _approved(c, alice, window, s1)["access_token"]
    a2 = _approved(c, alice, window, s2)["access_token"]
    j1 = jose_jwt.get_unverified_claims(a1)
    j2 = jose_jwt.get_unverified_claims(a2)
    assert _revoke(c, stranger, alice, approval=j1["jti"]).status_code == 403
    assert _revoke(c, s2, alice, approval=j1["jti"]).status_code == 403   # not its own
    r = _revoke(c, s1, alice, approval=j1["jti"])
    assert r.status_code == 200 and r.json() == {"revoked": "session", "approvals": 1}
    assert _exchange(c, a1, APPROVAL, _actor(s1, j1["agent"], a1)).status_code == 401
    assert _exchange(c, a2, APPROVAL, _actor(s2, j2["agent"], a2)).status_code == 200
    r = _revoke(c, window, alice)
    assert r.status_code == 200 and r.json()["revoked"] == "window"
    assert _exchange(c, a2, APPROVAL, _actor(s2, j2["agent"], a2)).status_code == 401


def test_an_ask_naming_no_grant_finds_its_window_s_grant_by_the_key(custody_client, people,
                                                                    filed):
    """A CLI opens the job-grant page for `agent.window.<jkt>` and then asks with the key alone:
    Origin finds the live grant by its job and takes the person from it."""
    c, alice = custody_client, people["alice"][0]
    window, other, session = Key(), Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-other", alice, other)))
    r = _exchange(c, _ask(window, None, session, grant=None), ASK)
    assert r.status_code == 403 and "no live agent window grant" in r.text
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    out = _approved(c, None, window, session, grant=None)
    claims = jose_jwt.get_unverified_claims(out["access_token"])
    assert claims["sub"] == alice and claims["job_grant"] == "jg-w"


def test_the_grant_page_opens_for_an_agent_window_without_an_app_to_answer(custody_client):
    c = custody_client
    r = c.get("/job-grant", params={"job": "agent.window.abc", "reach": "ws-home",
                                    "actions": "read"})
    assert r.status_code == 200 and "job-grant-page.js" in r.text
    assert c.get("/job-grant", params={"job": "lumen.reach.x"}).status_code == 400
    assert c.get("/job-grant", params={"job": "agent.window.abc",
                                       "revoke": "jg-w"}).status_code == 400


def test_a_window_s_revoke_naming_no_grant_ends_the_grant_for_its_key(custody_client, people,
                                                                      filed):
    c, alice = custody_client, people["alice"][0]
    window, session = Key(), Key()
    af.ok(af.page(alice, _window_grant("jg-w", alice, window)))
    a = _approved(c, alice, window, session, grant=None)["access_token"]
    agent = jose_jwt.get_unverified_claims(a)["agent"]
    r = _revoke(c, window, None, grant=None)
    assert r.status_code == 200 and r.json()["revoked"] == "window"
    assert _exchange(c, a, APPROVAL, _actor(session, agent, a)).status_code == 401
    assert _revoke(c, window, None, grant=None).status_code == 403
