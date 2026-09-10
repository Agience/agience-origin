"""The account-created notification goes to the operator, and to nobody else.

⛔ THE FIRST TEST IS THE ONE THAT MATTERS AND IT IS A NEGATIVE.
This notification carries a new account's address, name and id. Sending it to the person who
just registered would mail them their own details unprompted, and sending it anywhere derived
from their input would let the registering party choose the recipient. The recipient is read from
`ACCOUNT_NOTIFY_TO` and from nowhere else, and that is pinned here rather than left to reading.

The rest pin the properties that keep it from touching a registration: it fires once per
COMMITTED insert, never on a rollback, and a send failure is swallowed.
"""
from __future__ import annotations

import types

import pytest

from origin.services import account_notify


def _install(monkeypatch, fake):
    """Put `fake` where `account_notify._send` will actually find it.

    ⛔ PATCHING `sys.modules` ALONE IS NOT ENOUGH, and the failure is order-dependent, which is
    the worst kind. `_send` does `from origin.services import email_service` — that reads the
    `email_service` ATTRIBUTE off the already-imported `origin.services` package, and the import
    machinery only consults `sys.modules` while that attribute does not yet exist.

    Run this file alone and nothing has imported the real module, so the `sys.modules` entry is
    what gets bound and the fake is used. Run the whole suite and some earlier test has imported
    it, the attribute is set, the real `email_service` is returned, `is_configured()` is False on
    a test box, `_send` returns without sending, and the capture dict stays empty.

    That is what happened: these two tests passed alone and failed in the suite. They are the ones
    asserting a new account is never mailed its own details — a guard that only holds when run in
    isolation is not a guard. Both bindings are patched, so neither import order can bypass it.
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
    hostile = _Person(email="attacker@evil.example")
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
    # `verified` decides whether this is a person or a throwaway — an `.invalid` address is
    # auto-verified by the allowlist and can never receive mail.
    assert "verified" in body
