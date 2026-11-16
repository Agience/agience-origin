"""Phone approvals: an agent files a request, the chair decides on Origin's page, the agent spends
the note once.

- A request's digest is Origin's own, of the exact fields; the filer's is kept beside it.
- The page answers only the chair's Origin session, sent from Origin's own page; approving needs a
  passkey or one-time-code sign-in.
- A request that changed after the page opened it answers 412 and mints nothing.
- Governance is shown and only declined. A question past its expiry takes its default.
- A note is spent once per action; a bearer access token is not a note.
- An Origin session ends after 12 hours unused, and 7 days after its sign-in.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

HEADS = {"agience-origin": "a" * 40, "agience-mantle": "b" * 40}
AUD = ["agience-deployment"]
RELEASE = {"release": "2026.11.15", "heads": HEADS}


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


@pytest.fixture
def chair(custody_client, monkeypatch):
    who = af.person("chair", email="chair@team.test")
    monkeypatch.setenv("CHAIR_EMAIL", "Chair@team.test")
    return who


@pytest.fixture
def agent(custody_client):
    return af.person("Deployment", email="deploy@team.test")


def _file(c, agent, body):
    return c.post("/notes/requests", json=body, headers={"Authorization": f"Bearer {agent[1]}"})


def _release(c, agent, **extra):
    from origin.services.chair_notes import action_digest
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


def test_the_digest_is_origin_s_of_the_exact_fields(custody_client, chair, agent):
    from origin.services.chair_notes import action_digest
    a = action_digest("release", RELEASE)
    assert a == action_digest("release", {"heads": dict(reversed(list(HEADS.items()))),
                                          "release": "2026.11.15"}), "key order is not content"
    assert a != action_digest("release", {**RELEASE, "release": "2026.11.16"})
    filed = _release(custody_client, agent)
    assert filed["digest"] == a and filed["level"] == "Outward"


def test_the_next_cut_is_21_00_toronto():
    from origin.services.chair_notes import next_cut
    # 15 November 2026 is EST (UTC-5): 21:00 is 02:00 UTC the next day.
    assert next_cut(datetime(2026, 11, 15, 18, 0, tzinfo=timezone.utc)) == \
        datetime(2026, 11, 16, 2, 0, tzinfo=timezone.utc)
    assert next_cut(datetime(2026, 11, 16, 3, 0, tzinfo=timezone.utc)) == \
        datetime(2026, 11, 17, 2, 0, tzinfo=timezone.utc)
    # 15 July is EDT (UTC-4).
    assert next_cut(datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)) == \
        datetime(2026, 7, 16, 1, 0, tzinfo=timezone.utc)


def test_the_page_answers_only_the_chair_s_session_on_origin_s_page(custody_client, chair, agent):
    c = custody_client
    filed = _release(c, agent)
    c.cookies.clear()
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401
    _session(c, agent[0])
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 403
    _session(c, chair[0])
    assert c.get("/notes/page/state").status_code == 403, "no Origin or Referer: not the page"
    assert c.get("/notes/page/state", headers={"Origin": "https://evil.test"}).status_code == 403
    state = c.get("/notes/page/state", headers=_page_hdr()).json()
    assert [p["id"] for p in state["pending"]] == [filed["id"]]
    # A bearer token is no way onto the page.
    c.cookies.clear()
    assert c.get("/notes/page/state", headers={**_page_hdr(),
                                               "Authorization": f"Bearer {chair[1]}"}).status_code == 401


def test_approving_needs_a_passkey_sign_in(custody_client, chair, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, chair[0], amr=("fed",))
    view = _open(c, filed["id"])
    assert view["strong"] is False
    r = _decide(c, view)
    assert r.status_code == 401 and "passkey" in r.json()["detail"]
    _session(c, chair[0], amr=("pop",))
    view = _open(c, filed["id"])
    assert _decide(c, view).status_code == 200


def test_a_changed_request_answers_412_and_mints_nothing(custody_client, chair, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, chair[0])
    view = _open(c, filed["id"])
    r = _decide(c, {**view, "digest": "sha256:" + "0" * 64})
    assert r.status_code == 412
    assert r.json()["detail"] == "This request changed after you opened it. Here is the new version."
    again = _open(c, filed["id"])
    assert again["state"] == "pending" and "note" not in again


def test_an_approval_mints_one_note_spent_once(custody_client, chair, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, chair[0])
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


def test_a_bearer_token_is_not_a_note(custody_client, chair, agent):
    r = custody_client.post("/notes/spend", json={"note": chair[1], "action": "sha256:" + "1" * 64})
    assert r.status_code == 400 and r.json()["detail"] == "not a chair note"


def test_a_revoked_note_is_refused(custody_client, chair, agent):
    c = custody_client
    filed = _release(c, agent)
    _session(c, chair[0])
    done = _decide(c, _open(c, filed["id"])).json()
    r = c.post("/notes/page/revoke", json={"form": done["revoke_form"], "jti": done["note_jti"]},
               headers=_page_hdr())
    assert r.status_code == 200
    spent = c.post("/notes/spend", json={"note": done["note"], "action": filed["digest"]})
    assert spent.status_code == 410 and spent.json()["detail"] == "revoked"


def test_governance_is_shown_and_only_declined(custody_client, chair, agent):
    c = custody_client
    filed = _release(c, agent, level="Governance")
    assert filed["level"] == "Governance"
    _session(c, chair[0])
    view = _open(c, filed["id"])
    r = _decide(c, view)
    assert r.status_code == 422
    assert r.json()["detail"] == "Decide at your desk. Phone approval for Governance comes later."
    d = _decide(c, view, decision="decline", reason="at my desk")
    assert d.status_code == 200 and d.json()["state"] == "declined" and d.json()["reason"] == "at my desk"


def test_a_question_s_option_with_an_action_mints_its_note(custody_client, chair, agent):
    from origin.services.chair_notes import action_digest
    c = custody_client
    r = _file(c, agent, {"kind": "question", "aud": AUD, "summary": "Ship tonight or hold?",
                         "options": [{"label": "Ship", "action": {"kind": "release", "fields": RELEASE}},
                                     "Hold"], "default": "Hold"})
    assert r.status_code == 201, r.text
    _session(c, chair[0])
    view = _open(c, r.json()["id"])
    assert view["default"] == "Hold"
    done = _decide(c, view, option="Ship").json()
    assert done["state"] == "answered" and done["answer"] == "Ship" and done["note"]
    s = c.post("/notes/spend", json={"note": done["note"], "action": action_digest("release", RELEASE)})
    assert s.status_code == 200, s.text


def test_a_default_needs_no_note(custody_client, chair, agent):
    r = _file(custody_client, agent, {
        "kind": "question", "aud": AUD, "summary": "Ship?",
        "options": [{"label": "Ship", "action": {"kind": "release", "fields": RELEASE}}, "Hold"],
        "default": "Ship"})
    assert r.status_code == 422


def test_an_expired_question_takes_its_default(custody_client, chair, agent):
    from origin.db.session import SessionLocal
    from origin.models.chair_note import ChairRequest
    from origin.services import chair_notes
    c = custody_client
    r = _file(c, agent, {"kind": "question", "aud": AUD, "summary": "Rerun?", "options": ["Yes", "No"],
                         "default": "No"})
    rid = r.json()["id"]
    with SessionLocal() as db:
        row = db.get(ChairRequest, rid)
        row.expires_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        settled = chair_notes.get_request(db, rid)
        assert settled.state == "answered" and settled.answer == "No"


def test_sign_out_everywhere_ends_every_session(custody_client, chair, agent):
    c = custody_client
    other = _session(c, chair[0])
    _session(c, chair[0])
    state = c.get("/notes/page/state", headers=_page_hdr()).json()
    r = c.post("/notes/page/sign-out-everywhere", json={"form": state["sign_out_form"]},
               headers=_page_hdr())
    assert r.status_code == 200, r.text
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401
    from origin.services import origin_session
    c.cookies.clear()
    c.cookies.set(origin_session.cookie_name(), other)
    assert c.get("/notes/page/state", headers=_page_hdr()).status_code == 401


def test_a_form_token_from_another_session_is_refused(custody_client, chair, agent):
    c = custody_client
    _session(c, chair[0])
    form = c.get("/notes/page/state", headers=_page_hdr()).json()["revoke_all_form"]
    _session(c, chair[0])
    r = c.post("/notes/page/revoke-all", json={"form": form}, headers=_page_hdr())
    assert r.status_code == 403


def test_a_session_ends_idle_after_12_hours_and_after_7_days(custody_client, chair):
    from origin.db.session import SessionLocal
    from origin.models.origin_session import OriginSession
    from origin.services import origin_session
    c = custody_client
    raw = _session(c, chair[0])
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
    from origin.services.chair_notes import MAX_NOTE_LIFE
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
    assert "innerHTML" not in js


def test_without_a_verified_chair_the_routes_answer_503(custody_client, agent, monkeypatch):
    c = custody_client
    monkeypatch.delenv("CHAIR_EMAIL", raising=False)
    r = c.post("/notes/spend", json={"note": "x", "action": "y"})
    assert r.status_code == 503 and r.json()["detail"] == "approvals are not set up on this node"
    af.person("unverified", email="nobody@team.test", verified=False)
    monkeypatch.setenv("CHAIR_EMAIL", "nobody@team.test")
    r = _file(c, agent, {"kind": "question", "aud": AUD, "summary": "?", "options": ["a", "b"]})
    assert r.status_code == 503
    assert r.json()["detail"] == "the chair has no verified account on this node"
