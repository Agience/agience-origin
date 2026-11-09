"""An invite mail carries one link, Origin's own, and says who sent it by their verified address.

2026-11-09: an account on my.agience.ai sent a real Agience invite whose text was phishing. What an
inviter chooses (their display name, the name of what they share) reaches the invitee's inbox, so
it arrives inert in both parts: no URL-like thing in it stays clickable, by the website's lead-mail
rules (`origin.services.defang`). The invitee can tell who sent it: the mail names the sender and
their address, and only an account whose address is verified sends one.

`MAIL_CLIENT_LINK` is a pattern of the kind mail clients use to find links, so these tests check
what the mail says, not only the input's exact spelling. No test here touches the network: the
mail is handed to a stand-in sender.
"""
from __future__ import annotations

import asyncio
import re

import pytest

from origin.services import email_service as E
from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]
_CLAIM = "https://app.example/invite/tok-abc"

_TLDS = ("com|net|org|io|ai|co|cafe|example|invalid|info|biz|us|uk|ca|de|ru|cn|app|dev|xyz|top|"
         "online|site|link|click|me|tv|ly|gl|test|рф|xn--[a-z0-9-]+")
_DOTS = "[.。．｡]"
MAIL_CLIENT_LINK = re.compile(
    r"(?<![\w\[\]])(?:https?|ftps?|file|javascript|vbscript|data|mailto)\s*:"
    r"|\bwww" + _DOTS +
    r"|[\w-]+(?:" + _DOTS + r"[\w-]+)*" + _DOTS + r"(?:" + _TLDS + r")\b"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|\]\("
    r"|<a\s[^>]*href",
    re.IGNORECASE,
)

#: What an attacker types, and a fragment of what the mail must say instead.
PHISH = {
    "plain url": ("verify at https://evil.example/login", "hxxps://evil[.]example/login"),
    "markdown link": ("[Agience support](https://evil.example/x)",
                      "Agience support (hxxps://evil[.]example/x)"),
    "html anchor": ('<a href="http://evil.example/x">your account</a>',
                    "your account (hxxp://evil[.]example/x)"),
    "bare domain": ("go to agience-security.com now", "agience-security[.]com"),
    "idn": ("visit пример.рф", "пример[.]рф"),
    "lookalike": ("visit аgience.ai", "аgience[.]ai"),
    "ideographic dot": ("evil。example", "evil[.]example"),
    "ipv4": ("http://203.0.113.9/login", "hxxp://203[.]0[.]113[.]9/login"),
}


@pytest.fixture
def sent(monkeypatch):
    out: list[tuple] = []

    async def capture(to, subject, html_body, text_body=None):
        out.append((to, subject, html_body, text_body))
        return True

    monkeypatch.setattr(E, "send_email", capture)
    return out


def _links_outside_the_claim(text: str) -> list[str]:
    return [m.group(0) for m in MAIL_CLIENT_LINK.finditer(text.replace(_CLAIM, ""))]


@pytest.mark.parametrize("case", sorted(PHISH))
@pytest.mark.parametrize("field", ["from_name", "resource_name"])
def test_what_the_inviter_types_arrives_inert_in_both_parts(sent, case, field):
    typed, fragment = PHISH[case]
    args = {"from_name": "Ann", "resource_name": "Notes", field: typed}
    asyncio.run(E.send_invite("bob@example.com", args["from_name"], args["resource_name"], _CLAIM,
                              from_email="ann@team.test"))
    (_, subject, body, text), = sent
    assert fragment in text
    assert _links_outside_the_claim(subject + "\n" + text) == []
    # The HTML says the same, escaped; nothing the inviter typed is markup or a link.
    import html as _html
    assert _html.escape(fragment, quote=False) in body
    assert _links_outside_the_claim(_html.unescape(re.sub(r"<[^>]+>", " ", body))) == []


def test_the_invite_link_is_the_only_link(sent):
    asyncio.run(E.send_invite("bob@example.com", '<a href="https://evil.example">Ann</a>',
                              "[Notes](https://evil.example/n)", _CLAIM, from_email="ann@team.test"))
    (_, _, body, text), = sent
    assert re.findall(r'href="([^"]*)"', body) == [_CLAIM]
    assert body.count("<a ") == 1
    assert _CLAIM in text and _links_outside_the_claim(text) == []


def test_the_mail_names_the_sender_and_their_address(sent):
    asyncio.run(E.send_invite("bob@example.com", "Ann Lee", "Notes", _CLAIM,
                              from_email="ann@team.test"))
    (_, _, body, text), = sent
    assert "Ann Lee (ann@team[.]test)" in text
    assert "Ann Lee" in body and "ann@team[.]test" in body


# -- the route ------------------------------------------------------------------------------------

def _hdr():
    from origin import config
    return {"Origin": config.APP_URI or config.ORIGIN_URI, "X-Origin-Session": "1"}


@pytest.fixture
def mailed(monkeypatch):
    out = []

    async def send_invite(to_email, from_name, resource_name, claim_url, *, from_email):
        out.append({"to": to_email, "from_name": from_name, "from_email": from_email})
        return True

    monkeypatch.setattr(E, "is_configured", lambda: True)
    monkeypatch.setattr(E, "send_invite", send_invite)
    return out


def _invite_from(c, verified):
    pid, tok = af.person("Ann Lee", email="ann@team.test", verified=verified)
    af.ok(af.submit(c, tok, af.root("W"), batch="own", via_session=False))
    af.ok(af.submit(c, tok, af.grant("g-W-own", pid, "W", ALL), batch="own", via_session=False))
    c.cookies.clear()
    oc.origin_page_session(c, pid)
    seen = c.post("/auth/me/authority/preview", json={"resource_id": "W"}, headers=_hdr())
    return c.post("/auth/me/authority/invites",
                  json={"resource_id": "W", "actions": ["read"], "email": "bob@team.test",
                        "preview": seen.json().get("preview")}, headers=_hdr())


def test_the_route_mails_the_senders_verified_address(custody_client, mailed):
    r = _invite_from(custody_client, verified=True)
    assert r.status_code == 200, r.text
    assert mailed == [{"to": "bob@team.test", "from_name": "Ann Lee",
                       "from_email": "ann@team.test"}]


def test_an_unverified_sender_cannot_send_an_invite(custody_client, mailed):
    r = _invite_from(custody_client, verified=False)
    assert r.status_code == 403, r.text
    assert "verif" in r.json()["detail"]
    assert mailed == []
