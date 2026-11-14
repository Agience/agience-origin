"""A test node (`AGIENCE_PLANE=home`) never mails a real address (2026-11-14): 71/test inherited the
user environment's Gmail sender, and its sign-ups and invites could have reached real people."""
from __future__ import annotations

import asyncio

from origin.services import email_service


def test_a_home_node_mails_only_its_outbox_whatever_it_inherited(monkeypatch, tmp_path):
    monkeypatch.setenv("AGIENCE_PLANE", "home")
    monkeypatch.setenv("EMAIL_PROVIDER", "gmail")
    monkeypatch.setenv("GMAIL_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GMAIL_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GMAIL_OAUTH_REFRESH_TOKEN", "refresh")
    monkeypatch.setattr(email_service.settings, "get",
                        lambda key, default=None: "smtp" if key == "email.provider" else default)
    called = []
    for name in ("_send_gmail", "_send_smtp", "_send_ses", "_send_sendgrid", "_send_resend"):
        monkeypatch.setattr(email_service, name, lambda *a, **k: called.append(a) or True)
    monkeypatch.setenv("EMAIL_OUTBOX_DIR", str(tmp_path / "outbox"))
    assert email_service._provider() == "outbox"
    assert asyncio.run(email_service.send_email("someone@gmail.com", "s", "<p>h</p>", "t"))
    assert not called, "a real provider was reached from a test node"
    assert list((tmp_path / "outbox").iterdir()), "the mail was not written to the outbox"


def test_a_home_node_without_an_outbox_mails_nothing(monkeypatch):
    monkeypatch.setenv("AGIENCE_PLANE", "home")
    monkeypatch.setenv("EMAIL_PROVIDER", "gmail")
    monkeypatch.delenv("EMAIL_OUTBOX_DIR", raising=False)
    assert email_service._provider() == "outbox" and not email_service.is_configured()


def test_production_keeps_its_configured_provider(monkeypatch):
    monkeypatch.setenv("AGIENCE_PLANE", "production")
    monkeypatch.setenv("EMAIL_PROVIDER", "gmail")
    monkeypatch.setattr(email_service.settings, "get", lambda key, default=None: default)
    assert email_service._provider() == "gmail"
