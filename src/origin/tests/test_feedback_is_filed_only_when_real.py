"""Feedback is filed only when the request is real, within its length, and under its ceilings;
otherwise nothing is filed and the sender is told nothing different (John, 2026-11-14)."""
from __future__ import annotations

import pytest

from origin.services import feedback_intake as F
from origin.services import signup_guard

#: The form check runs as production runs it, not as the suite's stand-in.
pytestmark = pytest.mark.real_signup_form

T0 = 1_800_000_000.0


@pytest.fixture(autouse=True)
def fresh():
    F._reset_for_tests()
    yield
    F._reset_for_tests()


def _token():
    return signup_guard.form_token(now=T0)


def test_a_real_request_files_the_trimmed_text():
    assert F.admit("  The picker is slow.  ", "", _token(), "198.51.100.7", now=T0 + 10) == "The picker is slow."


@pytest.mark.parametrize("text, honeypot, token, at", [
    ("hello", "http://spam.example", None, T0 + 10),      # the hidden field was filled
    ("hello", "", "123.bad", T0 + 10),                     # not our token
    ("hello", "", None, T0 + 1),                           # sent faster than a person types
    ("hello", "", None, T0 + signup_guard.MAX_FORM_AGE + 5),  # a stale form
    ("   ", "", None, T0 + 10),                            # nothing to file
    ("x" * (F.MAX_CHARS + 1), "", None, T0 + 10),          # too long
])
def test_a_request_that_is_not_real_files_nothing(text, honeypot, token, at):
    assert F.admit(text, honeypot, token if token is not None else _token(), "198.51.100.7", now=at) is None


def test_one_address_is_held_to_its_hourly_ceiling_and_others_are_not():
    for i in range(F.PER_ADDRESS_PER_HOUR):
        assert F.admit(f"note {i}", "", _token(), "198.51.100.7", now=T0 + 10 + i)
    assert F.admit("one more", "", _token(), "198.51.100.7", now=T0 + 20) is None
    assert F.admit("from elsewhere", "", _token(), "203.0.113.9", now=T0 + 21)
    # An hour on, the address may send again.
    later = signup_guard.form_token(now=T0 + 3600)
    assert F.admit("later", "", later, "198.51.100.7", now=T0 + 3600 + 30) == "later"


def test_all_addresses_together_are_held_to_the_global_ceiling():
    for i in range(F.GLOBAL_PER_HOUR):
        assert F.admit(f"note {i}", "", _token(), f"198.51.100.{i % 250}", now=T0 + 10)
    assert F.admit("over", "", _token(), "192.0.2.1", now=T0 + 11) is None
