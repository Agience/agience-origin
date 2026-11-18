"""A parent artifact exchanges for its child's token along a grant it holds (FR-007).

John: "Grants are applied to artifacts. A job is an artifact and needs an invoke grant to start it.
It should pass /exchange delegate token to downstream steps, which can be verified or exchanged per
actor." Review 12's depth-1 rule is parent to child, along a grant the parent holds.

Grants are applied to artifacts, any kind: an artifact holds actions on another when a person who
reaches each of them there, and Update on the holder, grants it in their Origin session. A
workflow holds Invoke on its steps; a step that reads a document holds Read on it. A persona
holding the person's delegation, narrowed to itself, exchanges it for the child's token, naming
the parent and the child: Origin refuses unless the parent holds Invoke on the child. The token
reaches exactly what the child holds grants on, and the child as the parent holds it, never beyond
what the person reaches; anything else is refused. It lives five minutes and never past the
subject, and carries `act.sub` = the parent. A child's token exchanges again only for that child's
own children, and the hop to the persona that runs the child keeps the parent on `act`.
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
    assert claims["reach_by"] == {"step": ["invoke"]} and claims["reach_actions"] == ["invoke"]
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


def test_an_artifact_holds_any_job_action_but_never_delete_share_or_admin(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step")
    af.ok(_hold(c, alice, "wf", "step", "ag-r", actions=("read",)))
    af.ok(_hold(c, alice, "wf", "step", "ag-iu", actions=("invoke", "update")))
    for action in ("delete", "share", "admin", "evict"):
        assert _hold(c, alice, "wf", "step", f"ag-{action}", actions=(action,)).status_code == 400
    assert _hold(c, alice, "wf", "wf").status_code == 400


def test_the_owner_needs_each_action_they_grant(custody_client, people):
    c, alice, bob = custody_client, people["alice"], people["bob"]
    _tree(c, alice, "step")
    _tree(c, bob, "bobs-doc")
    r = _hold(c, alice, "step", "bobs-doc", actions=("read",))
    assert r.status_code == 403 and "no read on the child" in r.text


# -- the child's token reaches what the child holds -------------------------------------------------

def test_a_child_s_token_reaches_what_the_child_holds_and_nothing_else(custody_client, people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, "wf", "step", "doc", "notes", "other")
    af.ok(_hold(c, alice, "wf", "step", actions=("invoke", "read")))
    af.ok(_hold(c, alice, "step", "doc", actions=("read",)))
    af.ok(_hold(c, alice, "step", "notes", actions=("read", "update")))
    af.ok(_hold(c, alice, "wf", "other", actions=("read",)))
    claims = jose_jwt.get_unverified_claims(
        _child(c, "crystal", _crystal(c, alice), "step", "wf").json()["access_token"])
    assert claims["job_reach"] == ["doc", "notes", "step"]
    assert claims["reach_by"] == {"doc": ["read"], "notes": ["read", "update"],
                                  "step": ["invoke", "read"]}
    # What the parent holds elsewhere is not the child's: `other` is outside the token.
    assert "other" not in claims["job_reach"] and "wf" not in claims["job_reach"]


def test_a_child_s_token_never_reaches_past_the_person(custody_client, people):
    c, alice, bob = custody_client, people["alice"], people["bob"]
    _tree(c, alice, "wf", "step")
    _tree(c, bob, "bobs-doc")
    # Bob shares his document with Alice for reading, then Alice lets her step read it.
    af.ok(af.submit(c, bob[1], af.grant("g-share", alice[0], "bobs-doc", ["read"]),
                    batch="share"))
    af.ok(_hold(c, alice, "wf", "step"))
    af.ok(_hold(c, alice, "step", "bobs-doc", actions=("read",)))
    subject = _crystal(c, alice)
    claims = jose_jwt.get_unverified_claims(_child(c, "crystal", subject, "step", "wf")
                                            .json()["access_token"])
    assert claims["reach_by"]["bobs-doc"] == ["read"]
    # Bob withdraws Alice's read: the step's grant reaches nothing there any more.
    af.ok(af.submit(c, bob[1], af.grant("g-share", alice[0], "bobs-doc", ["read"],
                                        state="revoked"), batch="unshare"))
    claims = jose_jwt.get_unverified_claims(_child(c, "crystal", subject, "step", "wf")
                                            .json()["access_token"])
    assert "bobs-doc" not in claims["job_reach"] and "bobs-doc" not in claims["reach_by"]


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

def _server_delegation(sub, child, parent, grant, persona="crystal", reach_by=None):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import SERVER_DELEGATION_AUDIENCE, issue_delegation_token

    jti = secrets.token_hex(16)
    tok = issue_delegation_token(f"agience-server-{persona}", sub, 300, signer=persona, jti=jti,
                                 narrowed_scope=f"persona:{persona}",
                                 job_reach=sorted(reach_by or {child: ["read"]}),
                                 reach_by=reach_by or {child: ["read"]},
                                 job_grant=grant, artifact=child, parent=parent)
    with SessionLocal() as db:
        db.add(DelegationRecord(jti=jti, subject=sub, audience=SERVER_DELEGATION_AUDIENCE,
                                signer=persona,
                                expires_at=datetime.now(timezone.utc) + timedelta(seconds=300)))
        db.commit()
    return tok


def test_a_child_s_token_opens_keys_only_for_what_the_child_holds_read_on(custody_client,
                                                                         people):
    c, alice = custody_client, people["alice"]
    _tree(c, alice, alice[0], "wf", "step", "doc", "other")
    af.ok(af.store_share(c, alice[0], alice[1]))
    af.ok(_hold(c, alice, "wf", "step", actions=("invoke", "read")))
    af.ok(_hold(c, alice, "step", "doc", "ag-step-doc", actions=("read",)))
    held = {"doc": ["read"], "step": ["invoke", "read"]}
    tok = _server_delegation(alice[0], "step", "wf", "ag-wf-step", reach_by=held)
    for artifact in ("step", "doc"):
        r = af.release(c, alice[0], tok, artifact=artifact)
        assert r.status_code == 200, r.text
    for artifact in ("wf", "other"):
        assert af.release(c, alice[0], tok, artifact=artifact).status_code == 403
    assert af.release(c, alice[0], _server_delegation(alice[0], "step", "wf", "ag-other",
                                                      reach_by=held),
                      artifact="step").status_code == 403
    # The step lets go of the document: its key no longer opens on that token.
    af.ok(af.session_submit(c, alice[0], af.grant("ag-step-doc", "step", "doc", ("read",),
                                                  grantee_type="artifact", state="revoked")))
    assert af.release(c, alice[0], tok, artifact="doc").status_code == 403
    af.ok(af.session_submit(c, alice[0], af.grant("ag-wf-step", "wf", "step", ("invoke", "read"),
                                                  grantee_type="artifact", state="revoked")))
    assert af.release(c, alice[0], tok, artifact="step").status_code == 403
