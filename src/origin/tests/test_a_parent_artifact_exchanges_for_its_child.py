"""A parent artifact exchanges for its child's token along a grant it holds (FR-007).

John: "Grants are applied to artifacts. A job is an artifact and needs an invoke grant to start it.
It should pass /exchange delegate token to downstream steps, which can be verified or exchanged per
actor." Review 12's depth-1 rule is parent to child, along a grant the parent holds.

An artifact holds Invoke on a child when a person who reaches Invoke on the child and Update on the
parent grants it, in their Origin session. A persona holding the person's delegation, narrowed to
itself, exchanges it for the child's token, naming the parent and the child: Origin refuses unless
the parent holds that grant. The token reaches the child only, lives five minutes and never past
the subject, and carries `act.sub` = the parent. A child's token exchanges again only for that
child's own children, and the hop to the persona that runs the child keeps the parent on `act`.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_background_work_runs_on_a_job_grant as _jobs
from origin.tests.test_background_work_runs_on_a_job_grant import ALL
from origin.tests.test_the_eighth_review_s_sign_in_cases import _exchange
from origin.tests.test_the_twelfth_review_s_token_cases import _assertion, _hop, crystal_key  # noqa: F401

custody_client = _jobs.custody_client
people = _jobs.people


def _tree(c, who, *ids):
    for rid in ids:
        af.ok(af.submit(c, who[1], af.root(rid), batch=f"r-{rid}"))
        af.ok(af.submit(c, who[1], af.grant(f"g-{rid}", who[0], rid, [*ALL, "invoke"]),
                        batch=f"r-{rid}"))


def _hold(c, who, parent, child, gid=None, actions=("invoke",)):
    return af.session_submit(c, who[0], af.grant(gid or f"ag-{parent}-{child}", parent, child,
                                                 actions, grantee_type="artifact"))


def _child(c, caller, subject, child, parent=None):
    return _hop(c, caller, subject, "", resource=child,
                **({"parent": parent} if parent else {}))


def _crystal(c, who):
    return _exchange(c, who[1], "crystal").json()["access_token"]


# -- Origin refuses a hop the parent holds no grant for --------------------------------------------

def test_a_hop_with_no_held_grant_is_refused(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    r = _child(c, "crystal", _crystal(c, alice), "step", "wf")
    assert r.status_code == 403 and "holds no invoke grant" in r.text


def test_a_held_grant_exchanges_for_the_child_only(custody_client, people):
    from origin.db.session import SessionLocal
    from origin.models.narrow_hop import NarrowHop

    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step", "other")
    af.ok(_hold(c, alice, "wf", "step"))
    subject = _crystal(c, alice)
    r = _child(c, "crystal", subject, "step", "wf")
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    sub = jose_jwt.get_unverified_claims(subject)
    assert claims["sub"] == alice[0] and claims["aud"] == "crystal"
    assert claims["act"] == {"sub": "wf", "act": {"sub": "crystal"}}
    assert claims["artifact"] == "step" and claims["job_reach"] == ["step"]
    assert claims["job_grant"] == "ag-wf-step" and claims["narrowed"] is True
    assert claims["exp"] - claims["iat"] <= 300 and claims["exp"] <= sub["exp"]
    assert claims["hop"] == {"from": "crystal", "jti": sub["jti"], "kind": "artifact",
                             "parent": "wf"}
    with SessionLocal() as db:
        rows = db.query(NarrowHop).filter(NarrowHop.sub == alice[0]).all()
        assert [(h.from_aud, h.to_aud) for h in rows] == [("wf", "step")]
    # The grant is on that child: another child is refused.
    assert _child(c, "crystal", subject, "other", "wf").status_code == 403


def test_the_same_exchange_at_the_token_endpoint(custody_client, people, crystal_key):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    subject = _crystal(c, alice)
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": "agience-server-crystal", "resource": "step", "parent": "wf",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}
    r = c.post("/auth/token", data={**form, "client_assertion": _assertion(crystal_key,
                                                                          subject=subject)})
    assert r.status_code == 403 and "holds no invoke grant" in r.text
    af.ok(_hold(c, alice, "wf", "step"))
    r = c.post("/auth/token", data={**form, "client_assertion": _assertion(crystal_key,
                                                                          subject=subject)})
    assert r.status_code == 200, r.text
    assert jose_jwt.get_unverified_claims(r.json()["access_token"])["act"]["sub"] == "wf"


def test_a_revoked_grant_exchanges_nothing(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    af.ok(_hold(c, alice, "wf", "step"))
    af.ok(af.session_submit(c, alice[0], af.grant("ag-wf-step", "wf", "step", ("invoke",),
                                                  grantee_type="artifact", state="revoked")))
    assert _child(c, "crystal", _crystal(c, alice), "step", "wf").status_code == 403


# -- what the parent holds, and who may grant it ----------------------------------------------------

def test_the_owner_needs_their_own_invoke_on_the_child(custody_client, people):
    c, alice, bob = custody_client, people["alice"], people["bob"]
    _tree(c, alice, "wf")
    _tree(c, bob, "bobs-step")
    r = _hold(c, alice, "wf", "bobs-step")
    assert r.status_code == 403 and "no invoke on the child" in r.text


def test_the_grant_needs_update_on_the_parent(custody_client, people):
    c, alice, bob = custody_client, people["alice"], people["bob"]
    _tree(c, alice, "step")
    _tree(c, bob, "bobs-wf")
    r = _hold(c, alice, "bobs-wf", "step")
    assert r.status_code == 403 and "no update on the parent" in r.text


def test_an_artifact_holds_invoke_only(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    assert _hold(c, alice, "wf", "step", actions=("read",)).status_code == 400
    assert _hold(c, alice, "wf", "step", actions=("invoke", "update")).status_code == 400
    assert _hold(c, alice, "wf", "wf").status_code == 400


def test_an_artifact_s_grant_is_made_in_the_origin_session_only(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    r = af.submit(c, alice[1], af.grant("ag-x", "wf", "step", ("invoke",),
                                        grantee_type="artifact"), via_session=False)
    assert r.status_code == 403


def test_an_artifact_s_grant_opens_nothing_for_a_person(custody_client, people):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    af.ok(_hold(c, alice, "wf", "step"))
    with SessionLocal() as db:
        rc = al.reach(db)
        assert not rc.reaches("wf", "step", "invoke")


# -- the chain: each child invokes its own children -------------------------------------------------

def test_a_child_s_token_exchanges_only_for_its_own_children(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step", "sub-step", "elsewhere")
    af.ok(_hold(c, alice, "wf", "step"))
    af.ok(_hold(c, alice, "step", "sub-step"))
    af.ok(_hold(c, alice, "wf", "elsewhere"))
    child = _child(c, "crystal", _crystal(c, alice), "step", "wf").json()["access_token"]
    r = _child(c, "crystal", child, "sub-step")
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert claims["act"] == {"sub": "step", "act": {"sub": "crystal"}}
    assert claims["job_reach"] == ["sub-step"]
    assert claims["exp"] <= jose_jwt.get_unverified_claims(child)["exp"]
    # Not its parent's other children, and never as another parent.
    assert _child(c, "crystal", child, "elsewhere").status_code == 403
    assert _child(c, "crystal", child, "elsewhere", "wf").status_code == 403


def test_the_hop_to_the_persona_that_runs_the_child_keeps_the_parent(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    af.ok(_hold(c, alice, "wf", "step"))
    child = _child(c, "crystal", _crystal(c, alice), "step", "wf").json()["access_token"]
    r = _hop(c, "crystal", child, "sage")
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert claims["aud"] == "sage" and claims["act"] == {"sub": "wf", "act": {"sub": "sage"}}
    assert claims["artifact"] == "step" and claims["job_reach"] == ["step"]
    # A persona hop's result is not exchanged again.
    assert _hop(c, "sage", r.json()["access_token"], "iris").status_code == 403
    assert _child(c, "sage", r.json()["access_token"], "step").status_code == 403


def test_another_persona_cannot_exchange_crystal_s_token(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    af.ok(_hold(c, alice, "wf", "step"))
    assert _child(c, "lumen", _crystal(c, alice), "step", "wf").status_code == 403


# -- the child's token at a key share release -------------------------------------------------------

def _server_delegation(sub, child, parent, grant, persona="crystal"):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import SERVER_DELEGATION_AUDIENCE, issue_delegation_token

    jti = secrets.token_hex(16)
    tok = issue_delegation_token(f"agience-server-{persona}", sub, 300, signer=persona, jti=jti,
                                 narrowed_scope=f"persona:{persona}", job_reach=[child],
                                 job_grant=grant, artifact=child, parent=parent)
    with SessionLocal() as db:
        db.add(DelegationRecord(jti=jti, subject=sub, audience=SERVER_DELEGATION_AUDIENCE,
                                signer=persona,
                                expires_at=datetime.now(timezone.utc) + timedelta(seconds=300)))
        db.commit()
    return tok


def test_a_child_s_token_opens_the_child_s_key_while_the_parent_holds_the_grant(custody_client,
                                                                               people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, alice[0], "wf", "step")
    af.ok(af.store_share(c, alice[0], alice[1]))
    af.ok(_hold(c, alice, "wf", "step"))
    tok = _server_delegation(alice[0], "step", "wf", "ag-wf-step")
    r = af.release(c, alice[0], tok, artifact="step")
    assert r.status_code == 200, r.text
    assert af.release(c, alice[0], tok, artifact="wf").status_code == 403
    assert af.release(c, alice[0], _server_delegation(alice[0], "step", "wf", "ag-other"),
                      artifact="step").status_code == 403
    af.ok(af.session_submit(c, alice[0], af.grant("ag-wf-step", "wf", "step", ("invoke",),
                                                  grantee_type="artifact", state="revoked")))
    assert af.release(c, alice[0], tok, artifact="step").status_code == 403
