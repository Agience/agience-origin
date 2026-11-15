"""Feedback is filed in the Feedback collection as the feedback account, never as the sender, and
only for a real request; the sender hears the same thank-you either way (John, 2026-11-14)."""
from __future__ import annotations

import json

import pytest

from origin.routers import feedback_router as R
from origin.services import feedback_intake
from origin.tests import authority_fixtures as af


class _Mantle:
    def __init__(self, status=201):
        self.status, self.calls = status, []

    def __call__(self, *a, **kw):
        mantle = self

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None, headers=None):
                mantle.calls.append({"url": url, "json": json, "headers": headers})
                return type("R", (), {"status_code": mantle.status})()
        return _Client()


@pytest.fixture()
def feedback(client, monkeypatch):
    feedback_intake._reset_for_tests()
    from origin.db.base import Base
    from origin.db.session import get_engine
    Base.metadata.create_all(get_engine())
    bot_id, _ = af.person("feedback-bot", email="feedback-bot@example.invalid")
    monkeypatch.setenv("FEEDBACK_BOT_ID", bot_id)
    monkeypatch.setenv("FEEDBACK_COLLECTION_ID", "feedback-collection")
    monkeypatch.setattr(R.config, "MANTLE_URI", "https://mantle.test", raising=False)
    mantle = _Mantle()
    monkeypatch.setattr(R.httpx, "AsyncClient", mantle)
    return client, bot_id, mantle


def _send(client, text="The picker is slow.", website="", headers=None):
    token = client.get("/feedback/form").json()["form_token"]
    return client.post("/feedback", json={"text": text, "website": website, "form_token": token},
                       headers=headers or {})


def test_it_is_filed_in_the_feedback_collection_as_the_feedback_account(feedback):
    client, bot_id, mantle = feedback
    r = _send(client)
    assert r.status_code == 200 and r.json() == R.THANKS
    (call,) = mantle.calls
    assert call["url"] == "https://mantle.test/artifacts"
    body = call["json"]
    assert body["container_id"] == "feedback-collection"
    assert body["content"] == "The picker is slow." and body["content_type"] == "text/plain"
    assert json.loads(body["context"])["from"] == "signed out"
    from origin.services.auth_verifier import verify_token
    claims = verify_token(call["headers"]["Authorization"][7:], expected_audience="mantle")
    assert claims and claims["sub"] == bot_id, "filed as the feedback account, not anyone else"


def test_a_signed_in_sender_is_named_by_account_id(feedback):
    client, _bot, mantle = feedback
    sender, token = af.person("alice", email="alice@team.test")
    _send(client, headers={"Authorization": f"Bearer {token}"})
    assert json.loads(mantle.calls[0]["json"]["context"])["from"] == sender


def test_a_request_that_is_not_real_files_nothing_and_hears_the_same(feedback):
    client, _bot, mantle = feedback
    r = _send(client, website="http://spam.example")
    assert r.status_code == 200 and r.json() == R.THANKS
    assert mantle.calls == []


def test_unconfigured_or_refused_is_unavailable_so_the_app_offers_mail(feedback, monkeypatch):
    client, _bot, mantle = feedback
    mantle.status = 500
    assert _send(client).status_code == 503
    monkeypatch.delenv("FEEDBACK_COLLECTION_ID")
    assert client.get("/feedback/form").status_code == 503
    assert client.post("/feedback", json={"text": "x"}).status_code == 503
