"""Approvals: an account files a request against a workspace, whoever may update it decides on Origin's
page, the agent spends the note once.

- A request's digest is Origin's own, of the exact fields; the filer's is kept beside it.
- A request names a resource the filer can read. Whoever holds update on it approves with one click
  in their Origin session; a reader sees the request and cannot decide it; anyone else is told so
  and shown nothing of it. Nobody is named: approvers come from the ordinary grants.
- The level and the expiry are the filer's data.
- The filer withdraws an open request; nobody else does.
- A request that changed after the page opened it answers 412 and mints nothing.
- A question past its expiry takes its default.
- A note is spent once per action, and only while its approver still holds update on the
  resource; a bearer access token is not a note.
- An Origin session ends after 12 hours unused, and 7 days after its sign-in.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]
HEADS = {"agience-origin": "a" * 40, "agience-mantle": "b" * 40}
AUD = ["agience-deployment"]
RELEASE = {"release": "2026.11.15", "heads": HEADS}


def _soon(hours=6):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _page_hdr():
    from origin import config
    return {"Origin": config.ORIGIN_URI}


def _session(c, pid, amr=("pop",)):
    from origin.db.session import SessionLocal
    from origin.services import origin_session
    c.cookies.clear()
    with SessionLocal() as db:
        raw = origin_session.issue(db, pid, list(amr))
        db.commit()
    c.cookies.set(origin_session.cookie_name(), raw)
    return raw


def _share(c, owner, gid, who, actions):
    af.ok(af.session_submit(c, owner[0], af.grant(gid, who[0], "W", actions)))


@pytest.fixture
def approver(custody_client):
    """The owner of workspace W: admin on it through the ordinary grants, and nothing else."""
    who = af.person("Ann", email="ann@team.test")
    af.ok(af.submit(custody_client, who[1], af.root("W"), batch="own", via_session=False))
    af.ok(af.submit(custody_client, who[1], af.grant("g-W-own", who[0], "W", ALL), batch="own",
                    via_session=False))
    return who


@pytest.fixture
def agent(custody_client, approver):
    """The agent's own account, which can read W."""
    who = af.person("Deployment", email="deploy@team.test")
    _share(custody_client, approver, "g-W-agent", who, ("read",))
    return who


def _file(c, agent, body):
    body = {"resource": "W", "expires": _soon(), **body}
    return c.post("/notes/requests", json=body, headers={"Authorization": f"Bearer {agent[1]}"})


def _release(c, agent, **extra):
    from origin.services.decision_notes import action_digest
    body = {"kind": "release", "fields": RELEASE, "aud": AUD, "summary": "Release 2026.11.15\nthree fixes",
            "digest": action_digest("release", RELEASE),
            "evidence": [{"label": "CI green", "at": "2026-11-15T20:40:00-05:00",
                          "heads": HEADS},
                         {"label": "Tester GREEN", "heads": {"agience-origin": "a" * 12}}]}
    body.update(extra)
    r = _file(c, agent, body)
    assert r.status_code == 201, r.text
    return r.json()


def _open(c, rid):
    r = c.get(f"/notes/page/requests/{rid}", headers=_page_hdr())
    assert r.status_code == 200, r.text
    return r.json()


def _decide(c, view, decision="approve", **extra):
    body = {"req": view["id"], "decision": decision, "digest": view["digest"], "form": view["form"]}
    body.update(extra)
    return c.post("/notes/page/decide", json=body, headers=_page_hdr())


def test_the_digest_is_origin_s_of_the_exact_fields(custody_client, approver, agent):
    from origin.services.decision_notes import action_digest
    a = action_digest("release", RELEASE)
    assert a == action_digest("release", {"heads": dict(reversed(list(HEADS.items()))),
                                          "release": "2026.11.15"}), "key order is not content"
    assert a != action_digest("release", {**RELEASE, "release": "2026.11.16"})
    filed = _release(custody_client, agent)
    assert filed["digest"] == a and filed["level"] == "" and filed["resource"] == "W"


def test_a_train_s_digest_is_unchanged():
    """A train request filed as kind "train" with its name in the fields digests as before."""
    import hashlib
    import json
    from origin.services.decision_notes import action_digest, steps_digest
    steps = [action_digest("release", RELEASE), action_digest("release", {**RELEASE, "release": "x"})]
    old = {"kind": "train", "train": "2026-11-15", "actions": steps}
    want = "sha256:" + hashlib.sha256(json.dumps(old, sort_keys=True, separators=(",", ":"),
                                                 ensure_ascii=False).encode()).hexdigest()
    assert steps_digest("train", {"train": "2026-11-15"}, steps) == want


def test_level_and_expiry_are_the_filer_s_data(custody_client, approver, agent):
    c = custody_client
    when = _soon(3)
    r = _file(c, agent, {"kind": "deploy", "fields": {"x": 1}, "aud": AUD, "expires": when,
                         "level": "release"})
    assert r.status_code == 201 and r.json()["level"] == "release"
    assert datetime.fromisoformat(r.json()["expires"]) == datetime.fromisoformat(when)
    toronto = (datetime.now(timezone(timedelta(hours=-5))) + timedelta(hours=3)).replace(
        microsecond=0).isoformat()
    assert toronto.endswith("-05:00")
    r = _file(c, agent, {"kind": "deploy", "fields": {"x": 1}, "aud": AUD, "expires": toronto})
    assert r.status_code == 201, r.text
    assert datetime.fromisoformat(r.json()["expires"]) == datetime.fromisoformat(toronto)
    epoch = int((datetime.now(timezone.utc) + timedelta(hours=3)).timestamp())
    for bad in (None, "tomorrow", epoch, str(epoch),
                (datetime.now(timezone.utc) + timedelta(hours=3)).replace(tzinfo=None).isoformat(),
                (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                (datetime.now(timezone.utc) + timedelta(days=8)).isoformat()):
        r = _file(c, agent, {"kind": "deploy", "fields": {"x": 1}, "aud": AUD, "expires": bad})
        assert r.status_code == 422, (bad, r.text)


def test_a_request_names_a_resource_the_filer_can_read(custody_client, approver, agent):
    c = custody_client
    stranger = af.person("Sam", email="sam@team.test")
    for who, resource in ((agent, None), (agent, "elsewhere"), (stranger, "W")):
        body = {"kind": "deploy", "fields": {"x": 1}, "aud": AUD, "resource": resource}
        r = _file(c, who, body)
        assert r.status_code == 422, r.text
        assert r.json()["detail"] == "resource names a workspace or collection you can read"


def test_the_page_answers_only_a_session_on_origin_s_page(custody_client, approver, agent):
    c = custody_client
    filed = _release(c, agent)
    c.cookies.clear()
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401
    _session(c, approver[0])
    assert c.get("/notes/page/state").status_code == 403, "no Origin or Referer: not the page"
    assert c.get("/notes/page/state", headers={"Origin": "https://evil.test"}).status_code == 403
    state = c.get("/notes/page/state", headers=_page_hdr()).json()
    assert [p["id"] for p in state["pending"]] == [filed["id"]]
    # A bearer token is no way onto the page.
    c.cookies.clear()
    assert c.get("/notes/page/state", headers={**_page_hdr(),
                                               "Authorization": f"Bearer {approver[1]}"}).status_code == 401


def test_an_updater_approves_with_one_click_and_no_passkey(custody_client, approver, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, approver[0], amr=("fed",))
    view = _open(c, filed["id"])
    assert view["can_decide"] is True and view["resource"] == "W"
    done = _decide(c, view)
    assert done.status_code == 200 and done.json()["state"] == "approved"


def test_an_update_grant_on_the_workspace_approves_too(custody_client, approver, agent):
    c = custody_client
    bea = af.person("Bea", email="bea@team.test")
    _share(c, approver, "g-W-bea", bea, ("read", "update"))
    filed = _release(c, agent)
    _session(c, bea[0])
    state = c.get("/notes/page/state", headers=_page_hdr()).json()
    assert [p["id"] for p in state["pending"]] == [filed["id"]]
    assert _decide(c, _open(c, filed["id"])).status_code == 200


def test_admin_without_update_does_not_approve(custody_client, approver, agent):
    """The update grant decides; admin carries no approval of its own."""
    from origin.services.decision_notes import CANNOT_APPROVE
    c = custody_client
    dee = af.person("Dee", email="dee@team.test")
    _share(c, approver, "g-W-dee", dee, ("read", "admin"))
    filed = _release(c, agent)
    _session(c, dee[0])
    assert c.get("/notes/page/state", headers=_page_hdr()).json()["pending"] == []
    view = _open(c, filed["id"])
    assert view["can_decide"] is False
    r = _decide(c, view)
    assert r.status_code == 403 and r.json()["detail"] == CANNOT_APPROVE


def test_the_filer_gains_nothing_by_filing(custody_client, approver, agent):
    """Filing writes the request and no grant: a filer holding read and add on the collection,
    and nothing more, cannot decide its own request, and is told why."""
    from origin.services.decision_notes import FILER_CANNOT_APPROVE
    c = custody_client
    _share(c, approver, "g-W-agent-add", agent, ("add",))
    filed = _release(c, agent)
    _session(c, agent[0])
    assert c.get("/notes/page/state", headers=_page_hdr()).json()["pending"] == []
    view = _open(c, filed["id"])
    assert view["can_decide"] is False
    r = _decide(c, view)
    assert r.status_code == 403 and r.json()["detail"] == FILER_CANNOT_APPROVE
    _session(c, approver[0])
    assert _decide(c, _open(c, filed["id"])).status_code == 200


def test_a_filer_holding_update_approves_its_own_request(custody_client, approver, agent):
    """Holding update on the resource is the right to approve, for the filer too."""
    c = custody_client
    _share(c, approver, "g-W-agent-update", agent, ("read", "update"))
    filed = _release(c, agent)
    _session(c, agent[0])
    view = _open(c, filed["id"])
    assert view["is_filer"] is True and view["can_decide"] is True and view["withdraw_form"]
    assert _decide(c, view).status_code == 200


def test_a_reader_sees_the_request_and_cannot_decide_it(custody_client, approver, agent):
    from origin.services.decision_notes import FILER_CANNOT_APPROVE
    c = custody_client
    filed = _release(c, agent)
    _session(c, agent[0])
    assert c.get("/notes/page/state", headers=_page_hdr()).json()["pending"] == [], \
        "the list holds what the viewer can approve"
    view = _open(c, filed["id"])
    assert view["can_decide"] is False and view["fields"] == RELEASE
    for decision in ("approve", "decline"):
        r = _decide(c, view, decision=decision)
        assert r.status_code == 403 and r.json()["detail"] == FILER_CANNOT_APPROVE
    got = c.get(f"/notes/requests/{filed['id']}", headers={"Authorization": f"Bearer {agent[1]}"})
    assert got.status_code == 200 and got.json()["state"] == "pending"


def test_a_stranger_is_refused_and_shown_nothing(custody_client, approver, agent):
    from origin.services.decision_notes import CANNOT_APPROVE
    c = custody_client
    filed = _release(c, agent)
    sam = af.person("Sam", email="sam@team.test")
    _session(c, sam[0])
    r = c.get(f"/notes/page/requests/{filed['id']}", headers=_page_hdr())
    assert r.status_code == 403
    assert set(r.json()) == {"detail", "app_uri"} and r.json()["detail"] == CANNOT_APPROVE
    assert c.get("/notes/page/state", headers=_page_hdr()).json()["pending"] == []
    got = c.get(f"/notes/requests/{filed['id']}", headers={"Authorization": f"Bearer {sam[1]}"})
    assert got.status_code == 404


def test_a_changed_request_answers_412_and_mints_nothing(custody_client, approver, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, approver[0])
    view = _open(c, filed["id"])
    r = _decide(c, {**view, "digest": "sha256:" + "0" * 64})
    assert r.status_code == 412
    assert r.json()["detail"] == "This request changed after you opened it. Here is the new version."
    again = _open(c, filed["id"])
    assert again["state"] == "pending" and "note" not in again


def test_an_approval_mints_one_note_spent_once(custody_client, approver, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, approver[0])
    view = _open(c, filed["id"])
    assert view["filer_digest"] == view["digest"]
    done = _decide(c, view).json()
    assert done["state"] == "approved" and done["note"] and done["revoke_form"]
    note = done["note"]
    r = c.post("/notes/spend", json={"note": note, "action": filed["digest"]})
    assert r.status_code == 200, r.text
    assert isinstance(r.json()["receipt"]["spent_at"], int)
    again = c.post("/notes/spend", json={"note": note, "action": filed["digest"]})
    assert again.status_code == 409 and again.json()["detail"] == "already spent"
    other = c.post("/notes/spend", json={"note": note, "action": "sha256:" + "1" * 64})
    assert other.status_code == 422 and other.json()["detail"] == "action not covered by the note"
    after = _open(c, filed["id"])
    assert after["spent"] is True and "revoke_form" not in after


def test_a_bearer_token_is_not_a_note(custody_client, approver, agent):
    r = custody_client.post("/notes/spend", json={"note": approver[1], "action": "sha256:" + "1" * 64})
    assert r.status_code == 400 and r.json()["detail"] == "not a decision note"


def test_a_revoked_note_is_refused(custody_client, approver, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, approver[0])
    done = _decide(c, _open(c, filed["id"])).json()
    r = c.post("/notes/page/revoke", json={"form": done["revoke_form"], "jti": done["note_jti"]},
               headers=_page_hdr())
    assert r.status_code == 200
    spent = c.post("/notes/spend", json={"note": done["note"], "action": filed["digest"]})
    assert spent.status_code == 410 and spent.json()["detail"] == "revoked"


def test_another_updater_may_revoke_a_note_and_a_reader_may_not(custody_client, approver, agent):
    c = custody_client
    bea = af.person("Bea", email="bea@team.test")
    _share(c, approver, "g-W-bea", bea, ("read", "update"))
    filed = _release(c, agent)
    _session(c, bea[0])
    done = _decide(c, _open(c, filed["id"])).json()
    _session(c, agent[0])
    assert "revoke_form" not in _open(c, filed["id"]), "a reader gets no revoke form"
    _session(c, approver[0])
    view = _open(c, filed["id"])
    r = c.post("/notes/page/revoke", json={"form": view["revoke_form"], "jti": done["note_jti"]},
               headers=_page_hdr())
    assert r.status_code == 200
    spent = c.post("/notes/spend", json={"note": done["note"], "action": filed["digest"]})
    assert spent.status_code == 410


def test_a_decline_keeps_its_reason(custody_client, approver, agent):
    c = custody_client
    filed = _release(c, agent, level="policy")
    assert filed["level"] == "policy"
    _session(c, approver[0])
    d = _decide(c, _open(c, filed["id"]), decision="decline", reason="at my desk")
    assert d.status_code == 200 and d.json()["state"] == "declined" and d.json()["reason"] == "at my desk"


def test_a_question_s_option_with_an_action_mints_its_note(custody_client, approver, agent):
    from origin.services.decision_notes import action_digest
    c = custody_client
    r = _file(c, agent, {"kind": "question", "aud": AUD, "summary": "Ship tonight or hold?",
                         "options": [{"label": "Ship", "action": {"kind": "release", "fields": RELEASE}},
                                     "Hold"], "default": "Hold"})
    assert r.status_code == 201, r.text
    _session(c, approver[0])
    view = _open(c, r.json()["id"])
    assert view["default"] == "Hold"
    done = _decide(c, view, option="Ship").json()
    assert done["state"] == "answered" and done["answer"] == "Ship" and done["note"]
    s = c.post("/notes/spend", json={"note": done["note"], "action": action_digest("release", RELEASE)})
    assert s.status_code == 200, s.text


def test_a_default_needs_no_note(custody_client, approver, agent):
    r = _file(custody_client, agent, {
        "kind": "question", "aud": AUD, "summary": "Ship?",
        "options": [{"label": "Ship", "action": {"kind": "release", "fields": RELEASE}}, "Hold"],
        "default": "Ship"})
    assert r.status_code == 422


def test_an_expired_question_takes_its_default(custody_client, approver, agent):
    from origin.db.session import SessionLocal
    from origin.models.decision_note import DecisionRequest
    from origin.services import decision_notes
    c = custody_client
    r = _file(c, agent, {"kind": "question", "aud": AUD, "summary": "Rerun?", "options": ["Yes", "No"],
                         "default": "No"})
    rid = r.json()["id"]
    with SessionLocal() as db:
        row = db.get(DecisionRequest, rid)
        row.expires_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        settled = decision_notes.get_request(db, rid)
        assert settled.state == "answered" and settled.answer == "No"


def test_sign_out_everywhere_ends_every_session(custody_client, approver, agent):
    c = custody_client
    other = _session(c, approver[0])
    _session(c, approver[0])
    state = c.get("/notes/page/state", headers=_page_hdr()).json()
    r = c.post("/notes/page/sign-out-everywhere", json={"form": state["sign_out_form"]},
               headers=_page_hdr())
    assert r.status_code == 200, r.text
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401
    from origin.services import origin_session
    c.cookies.clear()
    c.cookies.set(origin_session.cookie_name(), other)
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401


def test_a_form_token_from_another_session_is_refused(custody_client, approver, agent):
    c = custody_client
    _session(c, approver[0])
    form = c.get("/notes/page/state", headers=_page_hdr()).json()["revoke_all_form"]
    _session(c, approver[0])
    r = c.post("/notes/page/revoke-all", json={"form": form}, headers=_page_hdr())
    assert r.status_code == 403


def test_a_session_ends_idle_after_12_hours_and_after_7_days(custody_client, approver):
    from origin.db.session import SessionLocal
    from origin.models.origin_session import OriginSession
    from origin.services import origin_session
    c = custody_client
    raw = _session(c, approver[0])
    digest = origin_session._digest(raw)
    with SessionLocal() as db:
        row = db.get(OriginSession, digest)
        life = origin_session._aware(row.expires_time) - origin_session._aware(row.created_time)
        assert abs(life - timedelta(days=7)) < timedelta(seconds=1)
        row.last_seen_time = datetime.now(timezone.utc) - timedelta(hours=11)
        db.commit()
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 200
    with SessionLocal() as db:
        seen = origin_session._aware(db.get(OriginSession, digest).last_seen_time)
        assert datetime.now(timezone.utc) - seen < timedelta(minutes=1), "a use is recorded"
        db.get(OriginSession, digest).last_seen_time = \
            datetime.now(timezone.utc) - timedelta(hours=12, minutes=1)
        db.commit()
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401


def test_a_retired_key_outlives_any_note():
    from origin.services.decision_notes import MAX_NOTE_LIFE
    from origin.services.signing_keys import retired_key_lifetime
    assert retired_key_lifetime() >= MAX_NOTE_LIFE >= timedelta(days=7)


def test_the_page_runs_no_inline_script_and_sends_its_referer():
    from pathlib import Path
    web = Path(__file__).resolve().parents[1] / "web"
    html = (web / "approvals.html").read_text(encoding="utf-8")
    js = (web / "approvals-page.js").read_text(encoding="utf-8")
    assert "<script>" not in html and 'src="/web/approvals-page.js"' in html
    assert 'referrerPolicy: "same-origin"' in js and 'credentials: "same-origin"' in js
    assert "Nothing waiting for you" in js and "Revoke this note" in js
    assert "You can't approve this request. Approving needs Editor access to it." in js
    assert "Back to Agience" in js and "Ask for access" in js
    assert "innerHTML" not in js
    for gone in ("next_cut", "Phone approval"):
        assert gone not in js


def test_the_notes_service_holds_no_release_vocabulary():
    from origin.services import decision_notes
    for gone in ("LEVELS", "_OUTWARD_KINDS", "next_cut"):
        assert not hasattr(decision_notes, gone)


def test_a_note_is_unspendable_once_its_approver_loses_update(custody_client, approver, agent):
    from origin.services.decision_notes import APPROVER_LOST_UPDATE
    c = custody_client
    bea = af.person("Bea", email="bea@team.test")
    _share(c, approver, "g-W-bea", bea, ("read", "update"))
    filed = _release(c, agent)
    _session(c, bea[0])
    done = _decide(c, _open(c, filed["id"])).json()
    af.ok(af.session_submit(c, approver[0], af.grant("g-W-bea", bea[0], "W", ("read", "update"),
                                                  state="revoked")))
    spent = c.post("/notes/spend", json={"note": done["note"], "action": filed["digest"]})
    assert spent.status_code == 403 and spent.json()["detail"] == APPROVER_LOST_UPDATE


def test_the_filer_withdraws_an_open_request_and_nobody_else_does(custody_client, approver, agent):
    from origin.db.session import SessionLocal
    from origin.services import decision_notes as notes
    c = custody_client
    filed = _release(c, agent)
    _session(c, approver[0])
    approver_view = _open(c, filed["id"])
    assert approver_view["is_filer"] is False and "withdraw_form" not in approver_view
    with SessionLocal() as db:
        with pytest.raises(notes.NoteRefused) as no:
            notes.withdraw(db, notes.get_request(db, filed["id"]), person_id=approver[0])
    assert no.value.status == 403
    _session(c, agent[0])
    mine = _open(c, filed["id"])
    assert mine["is_filer"] is True and mine["can_decide"] is False and mine["withdraw_form"]
    _session(c, approver[0])
    forged = c.post("/notes/page/withdraw", json={"req": filed["id"], "form": mine["withdraw_form"]},
                    headers=_page_hdr())
    assert forged.status_code == 403, "a form is bound to the session it was issued in"
    _session(c, agent[0])
    mine = _open(c, filed["id"])
    r = c.post("/notes/page/withdraw", json={"req": filed["id"], "form": mine["withdraw_form"]},
               headers=_page_hdr())
    assert r.status_code == 200 and r.json()["state"] == "withdrawn"
    assert "withdraw_form" not in r.json()
    _session(c, approver[0])
    assert c.get("/notes/page/state", headers=_page_hdr()).json()["pending"] == []
    late = _decide(c, _open(c, filed["id"]))
    assert late.status_code == 409
