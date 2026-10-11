"""The `outbox` provider sends nothing and writes each message to `EMAIL_OUTBOX_DIR`, whole, so a
test stack (the release candidate, the browser journeys) can read a reset link or a sign-in code."""
from __future__ import annotations

import asyncio
import json


def test_a_message_is_written_whole_and_nothing_is_sent(tmp_path, monkeypatch):
    from origin.services import email_service

    monkeypatch.setenv("EMAIL_PROVIDER", "outbox")
    monkeypatch.setenv("EMAIL_OUTBOX_DIR", str(tmp_path / "outbox"))
    assert email_service.is_configured()

    ok = asyncio.run(email_service.send_email("a@example.invalid", "Subject", "<p>html</p>", "text"))

    assert ok
    files = list((tmp_path / "outbox").iterdir())
    assert len(files) == 1 and not files[0].name.startswith(".")
    mail = json.loads(files[0].read_text(encoding="utf-8"))
    assert (mail["to"], mail["subject"], mail["text"], mail["html"]) == (
        "a@example.invalid", "Subject", "text", "<p>html</p>")


def test_without_a_folder_the_outbox_is_not_configured(monkeypatch):
    from origin.services import email_service

    monkeypatch.setenv("EMAIL_PROVIDER", "outbox")
    monkeypatch.delenv("EMAIL_OUTBOX_DIR", raising=False)
    assert not email_service.is_configured()
    assert asyncio.run(email_service.send_email("a@example.invalid", "S", "<p>h</p>")) is False
