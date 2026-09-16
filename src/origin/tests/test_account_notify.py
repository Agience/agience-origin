"""The account-created notification goes to the operator, and to nobody else.

The first test is the one that matters, and it is a negative. This notification carries a new
account's address, name and id. Sending it to the person who just registered would mail them their
own details unprompted, and sending it anywhere derived from their input would let the registering
party choose the recipient. The recipient is read from `ACCOUNT_NOTIFY_TO` and from nowhere else,
and that is pinned here rather than left to reading.

The rest pin what this module decides in isolation: which addresses are announced, how a person is
described, and that a send failure is swallowed. The commit-versus-rollback behaviour lives in the
listeners `install()` wires, which no test here drives.
"""
from __future__ import annotations

import types

import pytest

from origin.services import account_notify


def _install(monkeypatch, fake):
    """Put `fake` where `account_notify._send` will actually find it.

    Patching `sys.modules` alone is not enough, and what it leaves behind is order-dependent.
    `_send` does `from origin.services import email_service`, which reads the `email_service`
    attribute off the already-imported `origin.services` package; the import machinery consults
    `sys.modules` only while that attribute does not yet exist.

    Run this file alone and nothing has imported the real module, so the `sys.modules` entry is
    what gets bound and the fake is used. Run the whole suite and some earlier test has imported
    it, the attribute is set, the real `email_service` is returned, `is_configured()` is False on
    a test box, `_send` returns without sending, and the capture dict stays empty — the tests
    asserting that a new account is never mailed its own details would then hold only in
    isolation, which is not a guard at all. Both bindings are patched, so no import order can
    bypass the fake.
    """
    import sys

    import origin.services

    monkeypatch.setitem(sys.modules, "origin.services.email_service", fake)
    monkeypatch.setattr(origin.services, "email_service", fake, raising=False)


class _Person:
    """Just enough of the model for `_describe` — the notifier only reads attributes."""

    def __init__(self, email="newcomer@example.com"):
        self.id = "11111111-2222-3333-4444-555555555555"
        self.email = email
        self.username = email
        self.name = "A Newcomer"
        self.email_verified = False
        self.created_time = "2026-09-10T00:00:00+00:00"


# ── the one that matters ─────────────────────────────────────────────────────────────────────
def test_it_never_mails_the_person_who_registered(monkeypatch):
    """The recipient is the configured operator, not the new account's own address."""
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")
    person = _Person(email="newcomer@example.com")

    sent = {}

    async def _capture(to, subject, html, text=None):
        sent["to"] = to
        return True

    fake = types.SimpleNamespace(is_configured=lambda: True, send_email=_capture)
    _install(monkeypatch, fake)

    account_notify._send(person)

    assert sent["to"] == "connect@agience.ai"
    assert sent["to"] != person.email, "the new account must never receive this notification"


def test_the_recipient_cannot_be_chosen_by_the_registering_party(monkeypatch):
    """Everything the new account controls — address, name, username — must not steer delivery."""
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")
    # A deliverable domain, deliberately. `_is_probe` filters RFC 2606 reserved TLDs, so a hostile
    # address on one of those (`evil.example`, say) sends no mail at all and "the recipient was not
    # steered" holds for the wrong reason. The property under test is that nothing the registrant
    # controls chooses the recipient, and that has to be checked on a registration the notifier
    # actually acts on.
    hostile = _Person(email="attacker@evil.example.com")
    hostile.name = "connect@agience.ai"
    hostile.username = "someone-else@elsewhere.example"

    sent = {}

    async def _capture(to, subject, html, text=None):
        sent["to"] = to
        return True

    fake = types.SimpleNamespace(is_configured=lambda: True, send_email=_capture)
    _install(monkeypatch, fake)

    account_notify._send(hostile)
    assert sent["to"] == "connect@agience.ai"


def test_unset_recipient_disables_it_entirely(monkeypatch):
    """No configured operator address means no notification — not a fallback to anyone."""
    monkeypatch.delenv("ACCOUNT_NOTIFY_TO", raising=False)
    assert account_notify.is_enabled() is False


@pytest.mark.parametrize("value", ["", "   "])
def test_a_blank_recipient_is_the_same_as_unset(monkeypatch, value):
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", value)
    assert account_notify.is_enabled() is False


# ── it must never break a registration ───────────────────────────────────────────────────────
def test_a_send_failure_is_swallowed(monkeypatch):
    """The account exists and the person is signed in. A failed notification changes nothing for
    them, so it must not raise into the request that created them."""
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")

    async def _boom(*a, **k):
        raise RuntimeError("smtp is on fire")

    fake = types.SimpleNamespace(is_configured=lambda: True, send_email=_boom)
    _install(monkeypatch, fake)

    account_notify._send(_Person())  # must not raise


def test_no_email_provider_is_not_an_error(monkeypatch):
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")
    fake = types.SimpleNamespace(is_configured=lambda: False,
                                 send_email=lambda *a, **k: pytest.fail("must not send"))
    _install(monkeypatch, fake)
    account_notify._send(_Person())  # must not raise, must not send


# ── what the operator actually reads ─────────────────────────────────────────────────────────
def test_the_body_names_the_account_and_its_verified_state(monkeypatch):
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")
    subject, body = account_notify._describe(_Person(email="someone@example.com"))
    assert "someone@example.com" in subject
    assert "someone@example.com" in body
    # `verified` decides whether this is a person or a throwaway, and it is the field a reader
    # needs: an address on a reserved TLD can never receive mail, so a verified flag on one says
    # nothing about a person having been reached.
    assert "verified" in body


# ── probe addresses ──────────────────────────────────────────────────────────────────────────
def test_a_reserved_tld_address_is_not_announced(monkeypatch):
    """The platform's own e2e registers an account on every --allow-write run. Announcing those
    turns the one alert that says a real person signed up into noise."""
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")
    sent = {}

    async def _capture(to, subject, html, text=None):
        sent["to"] = to
        return True

    fake = types.SimpleNamespace(is_configured=lambda: True, send_email=_capture)
    _install(monkeypatch, fake)

    for domain in ("example.invalid", "example.test", "foo.example", "box.localhost"):
        account_notify._send(_Person(email=f"e2e-probe@{domain}"))
    assert "to" not in sent, "a reserved-TLD address was announced as a new account"


def test_a_real_address_is_still_announced(monkeypatch):
    """The guard on the guard. Without this, `_is_probe` returning True for everything would
    silence the notifier entirely and every other test in this file would still pass."""
    monkeypatch.setenv("ACCOUNT_NOTIFY_TO", "connect@agience.ai")
    sent = {}

    async def _capture(to, subject, html, text=None):
        sent["to"] = to
        return True

    fake = types.SimpleNamespace(is_configured=lambda: True, send_email=_capture)
    _install(monkeypatch, fake)

    account_notify._send(_Person(email="a.real.person@example.com"))
    assert sent.get("to") == "connect@agience.ai"


def test_the_filter_does_not_match_a_lookalike_domain():
    """A domain whose name contains a reserved word but whose TLD is not reserved.

    `_is_probe` matches on the TLD, not on a substring. `invalid.example.com` ends in `.com`,
    so it is a real address that must be notified — while carrying both `invalid` and
    `.example` inside the name, which is exactly what a substring check would trip on.
    The fixture sits under `example.com`, itself reserved, never on a buyable domain."""
    assert not account_notify._is_probe(_Person(email="someone@invalid.example.com"))
    assert not account_notify._is_probe(_Person(email="test@example.com"))
    assert account_notify._is_probe(_Person(email="x@example.invalid"))
