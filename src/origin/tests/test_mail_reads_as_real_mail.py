"""Every message Origin sends is a whole document with a plain-text twin and the headers real mail
carries, and nothing a caller supplies is written into its HTML unescaped.

2026-10-11: reset mail went to Outlook's Junk folder. It was a bare HTML fragment holding one
button, with a one-line text part, and the SMTP and Gmail paths set no `Date`, `Message-ID` or
`Reply-To`. Invitations wrote the inviter's name and message into the HTML as given.
"""

from __future__ import annotations

import asyncio
from email import message_from_bytes

import pytest

from origin.services import email_service as E

_URL = "https://my.example/reset-password?token=abc&x=1"


@pytest.fixture
def sent(monkeypatch):
    out: list[tuple] = []

    async def capture(to, subject, html_body, text_body=None):
        out.append((to, subject, html_body, text_body))
        return True

    monkeypatch.setattr(E, "send_email", capture)
    return out


@pytest.mark.parametrize("send", [
    lambda: E.send_password_reset("a@example.com", _URL),
    lambda: E.send_email_verification("a@example.com", _URL),
    lambda: E.send_otp("a@example.com", "123456"),
    lambda: E.send_invite("a@example.com", "Ann", "Notes", _URL, "hello"),
], ids=["reset", "verify", "code", "invite"])
def test_every_message_is_a_whole_document_with_a_text_twin(sent, send):
    asyncio.run(send())
    (to, subject, body, text), = sent
    assert body.startswith("<!DOCTYPE html><html lang=\"en\">") and body.endswith("</body></html>")
    assert f"<title>{subject}</title>" in body and "sent by" in body
    assert text and len(text) > 80 and "a@example.com" in text or "Ann" in text


def test_every_message_carries_the_logo_this_origin_serves(sent, monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.example")
    asyncio.run(E.send_password_reset("a@example.com", _URL))
    (_, _, body, _), = sent
    assert '<img src="https://origin.example/web/logo_mail.png" alt="Agience"' in body
    from pathlib import Path
    logo = Path(E.__file__).resolve().parents[1] / "web" / "logo_mail.png"
    assert logo.is_file() and logo.stat().st_size < 40_000, "a small file, for mail"


def test_links_are_escaped_into_the_html_and_kept_whole_in_the_text(sent):
    asyncio.run(E.send_password_reset("a@example.com", _URL))
    (_, _, body, text), = sent
    assert 'href="https://my.example/reset-password?token=abc&amp;x=1"' in body
    assert _URL in text


def test_an_invitation_never_writes_caller_text_into_the_html(sent):
    asyncio.run(E.send_invite("a@example.com", '<img src=x onerror="alert(1)">', "<b>doc</b>", _URL,
                              '<script>steal()</script>'))
    (_, _, body, _), = sent
    for raw in ("<img src=x", "<b>doc</b>", "<script>"):
        assert raw not in body, raw
    assert "&lt;script&gt;steal()&lt;/script&gt;" in body


def test_smtp_and_gmail_messages_carry_the_headers_of_real_mail():
    cfg = {"from_name": "Agience", "from_address": "connect@agience.ai", "reply_to": ""}
    msg = message_from_bytes(E._mime(cfg, "a@example.com", "Subject", "<p>x</p>", "x").as_bytes())
    assert msg["From"] == "Agience <connect@agience.ai>"
    assert msg["Reply-To"] == "connect@agience.ai"
    assert msg["Date"] and msg["Message-ID"].endswith("@agience.ai>")
    assert [p.get_content_type() for p in msg.get_payload()] == ["text/plain", "text/html"]
    cfg["reply_to"] = "support@agience.ai"
    assert E._mime(cfg, "a@example.com", "S", "<p/>", None)["Reply-To"] == "support@agience.ai"


@pytest.mark.parametrize("ua,said", [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
     "from Chrome on Windows."),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
     "from Safari on iPhone."),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6; rv:131.0) Gecko/20100101 Firefox/131.0",
     "from Firefox on macOS."),
    ("<script>evil()</script>", "from a web browser."),
    (None, "from a web browser."),
])
def test_the_request_line_names_only_known_browsers_and_systems(ua, said):
    from datetime import datetime, timezone

    line = E.request_context(ua, datetime(2026, 10, 11, 15, 48, tzinfo=timezone.utc))
    assert line == f"Requested on 11 Oct 2026 at 15:48 UTC {said}"


@pytest.mark.parametrize("send", [
    lambda c: E.send_password_reset("a@example.com", _URL, c),
    lambda c: E.send_email_verification("a@example.com", _URL, c),
    lambda c: E.send_otp("a@example.com", "123456", c),
], ids=["reset", "verify", "code"])
def test_the_request_line_is_in_both_parts(sent, send):
    asyncio.run(send("Requested on 11 Oct 2026 at 15:48 UTC from Chrome on Windows."))
    (_, _, body, text), = sent
    assert "from Chrome on Windows." in body and "from Chrome on Windows." in text
