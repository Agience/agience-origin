"""A job's delegation opens a person's content key only for the artifacts its job grant lists
(John, 2026-11-10, Q9).

A timer's firing reaches Mantle on a persona's server delegation that carries its job grant
(`job_grant`, `job_reach`). At a key share release, and there alone, Origin takes it as the
person's acting credential for an artifact the live grant lists by id, and for nothing else: not
another artifact, not a release that names none, not once the grant is revoked, and never for
storing a share or writing the ledger.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from origin.tests import authority_fixtures as af
from origin.tests import test_background_work_runs_on_a_job_grant as _jobs
from origin.tests.test_background_work_runs_on_a_job_grant import _root, job_grant

custody_client = _jobs.custody_client
people = _jobs.people

TIMER = "lumen.timer.t-1"


def _armed(c, person, gid="jg-t", reach=("t-1", "target-1")):
    _root(c, person, person[0])
    af.ok(af.page(person[0], {**job_grant(gid, TIMER, person[0]), "reach": list(reach)}))
    st = af.store_share(c, person[0], person[1])
    assert st.status_code == 200, st.text


def _job_delegation(sub, *, reach=("t-1", "target-1"), grant="jg-t", persona="lumen"):
    """Lumen's server delegation for a firing, as `/internal/delegation-token` mints it from the
    job delegation, recorded with the persona that signed for it."""
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import SERVER_DELEGATION_AUDIENCE, issue_delegation_token

    jti = secrets.token_hex(16)
    tok = issue_delegation_token(f"agience-server-{persona}", sub, 300, signer=persona, jti=jti,
                                 narrowed_scope=f"persona:{persona}", job_reach=list(reach),
                                 job_grant=grant)
    with SessionLocal() as db:
        db.add(DelegationRecord(jti=jti, subject=sub, audience=SERVER_DELEGATION_AUDIENCE,
                                signer=persona,
                                expires_at=datetime.now(timezone.utc) + timedelta(seconds=300)))
        db.commit()
    return tok


def test_it_opens_the_key_for_an_artifact_its_grant_lists(custody_client, people):
    c, alice = custody_client, people["alice"]
    _armed(c, alice)
    tok = _job_delegation(alice[0])
    for artifact in ("t-1", "target-1"):
        r = af.release(c, alice[0], tok, artifact=artifact)
        assert r.status_code == 200, r.text


def test_it_opens_the_collection_key_its_listed_artifact_is_keyed_under_and_no_other(
        custody_client, people):
    c, alice = custody_client, people["alice"]
    _armed(c, alice)
    for col in ("K", "L"):
        _root(c, alice, col)
        st = af.store_share(c, f"ck:{col}", alice[1])
        assert st.status_code == 200, st.text
    af.ok(af.submit(c, alice[1], af.edge("K", "t-1"), batch="e-t1"))
    af.ok(af.submit(c, alice[1], af.edge("L", "other-1"), batch="e-o1"))
    tok = _job_delegation(alice[0])
    r = af.release(c, "ck:K", tok, collection="K", artifact="t-1")
    assert r.status_code == 200, r.text
    # A listed top-level artifact is keyed under its own id.
    _root(c, alice, "target-1")
    af.ok(af.store_share(c, "ck:target-1", alice[1]))
    r = af.release(c, "ck:target-1", tok, collection="target-1", artifact="target-1")
    assert r.status_code == 200, r.text
    # The person reaches L too, but the listed artifact is not keyed there.
    assert af.release(c, "ck:L", tok, collection="L", artifact="t-1").status_code == 403
    assert af.release(c, "ck:L", tok, collection="L", artifact="other-1").status_code == 403


def test_it_opens_nothing_else(custody_client, people):
    c, alice, bob = custody_client, people["alice"], people["bob"]
    _armed(c, alice)
    tok = _job_delegation(alice[0])
    assert af.release(c, alice[0], tok, artifact="inbox-1").status_code == 403
    assert af.release(c, alice[0], tok).status_code == 403             # names no artifact
    _armed(c, bob, gid="jg-bob")
    assert af.release(c, bob[0], tok, artifact="t-1").status_code == 403  # another person's key


def test_it_holds_only_to_its_own_live_grant(custody_client, people):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    c, alice, bob = custody_client, people["alice"], people["bob"]
    _armed(c, alice)
    wider = _job_delegation(alice[0], reach=("t-1", "target-1", "inbox-1"))
    assert af.release(c, alice[0], wider, artifact="t-1").status_code == 403
    _armed(c, bob, gid="jg-bob")
    theirs = _job_delegation(alice[0], grant="jg-bob")
    assert af.release(c, alice[0], theirs, artifact="t-1").status_code == 403
    tok = _job_delegation(alice[0])
    assert af.release(c, alice[0], tok, artifact="t-1").status_code == 200
    with SessionLocal() as db:
        al.page_revoke_job_grant(db, alice[0], "jg-t")
    assert af.release(c, alice[0], tok, artifact="t-1").status_code == 403


def test_a_job_grant_that_is_not_a_timer_s_opens_nothing(custody_client, people):
    c, alice = custody_client, people["alice"]
    _root(c, alice, alice[0])
    af.ok(af.page(alice[0], job_grant("jg-r", "platform.reindex", alice[0])))
    af.store_share(c, alice[0], alice[1])
    tok = _job_delegation(alice[0], reach=("t-1",), grant="jg-r")
    assert af.release(c, alice[0], tok, artifact="t-1").status_code == 403


def test_it_acts_at_the_release_alone(custody_client, people):
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    c, alice = custody_client, people["alice"]
    _armed(c, alice)
    tok = _job_delegation(alice[0])
    with SessionLocal() as db:
        try:
            share_credentials.verify_share_credential(db, tok)
        except share_credentials.CredentialRefused:
            pass
        else:
            raise AssertionError("a job's delegation verified as an ordinary acting credential")
    assert af.store_share(c, alice[0], tok).status_code == 403
    r = af.submit(c, tok, af.grant("g-job", alice[0], "t-1", ("read",)), batch="j",
                  via_session=False)
    assert r.status_code == 403, r.text


def test_a_server_delegation_with_no_job_still_opens_nothing(custody_client, people):
    from origin.tests.test_review27_custody import _server_delegation

    c, alice = custody_client, people["alice"]
    _armed(c, alice)
    tok = _server_delegation(alice[0], persona="lumen", signer="lumen")
    assert af.release(c, alice[0], tok, artifact="t-1").status_code == 403
