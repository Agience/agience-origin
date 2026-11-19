"""The operator's shell may export a real mail sender (`EMAIL_PROVIDER=gmail`). Under pytest no
send reaches a real provider: the suite starts without it, and a send that still selects one raises."""
from __future__ import annotations

import asyncio
import os

import pytest

from origin.services import email_service


def test_the_suite_starts_without_the_inherited_sender():
    for name in ("EMAIL_PROVIDER", "PLATFORM_EMAIL_ADDRESS", "GMAIL_OAUTH_REFRESH_TOKEN"):
        assert name not in os.environ, name


@pytest.mark.parametrize("provider", sorted(email_service.REAL_PROVIDERS))
def test_a_real_provider_under_test_raises(monkeypatch, provider):
    monkeypatch.setenv("AGIENCE_PLANE", "production")
    monkeypatch.setenv("EMAIL_PROVIDER", provider)
    monkeypatch.setattr(email_service.settings, "get", lambda key, default=None: default)
    reached = []
    for name in ("_send_gmail", "_send_smtp", "_send_ses", "_send_sendgrid", "_send_resend"):
        monkeypatch.setattr(email_service, name, lambda *a, **k: reached.append(a) or True)
    with pytest.raises(RuntimeError, match="real mail under test"):
        asyncio.run(email_service.send_email("someone@example.com", "s", "<p>h</p>", "t"))
    with pytest.raises(RuntimeError, match="real mail under test"):
        asyncio.run(email_service.test_connection({"provider": provider}))
    assert not reached


def test_the_outbox_still_sends_under_test(monkeypatch, tmp_path):
    monkeypatch.setenv("EMAIL_PROVIDER", "outbox")
    monkeypatch.setenv("EMAIL_OUTBOX_DIR", str(tmp_path))
    monkeypatch.setattr(email_service.settings, "get", lambda key, default=None: default)
    assert asyncio.run(email_service.send_email("someone@example.com", "s", "<p>h</p>", "t"))
    assert list(tmp_path.iterdir())
