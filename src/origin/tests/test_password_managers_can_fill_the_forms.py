"""A password manager can fill origin's password forms: each has a username field it can tie the
password to, and every input is named.

2026-10-11: Proton Pass would not fill the reset page, whose form held two new-password fields and
nothing saying whose password they were; a manager that cannot tie a new password to an account
cannot save it, and keeps offering the old one at sign-in.
"""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "web"


def _forms(page: str) -> dict[str, list[dict]]:
    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms, self.current = {}, None

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self.current = a.get("id")
                self.forms[self.current] = []
            elif tag == "input" and self.current is not None:
                self.forms[self.current].append(a)

        def handle_endtag(self, tag):
            if tag == "form":
                self.current = None

    p = P()
    p.feed((WEB / page).read_text(encoding="utf-8"))
    return p.forms


def test_the_reset_form_names_the_account_beside_the_new_password():
    inputs = _forms("reset-password.html")["confForm"]
    kinds = [i.get("autocomplete") for i in inputs]
    assert "username" in kinds and kinds.count("new-password") == 2
    assert kinds.index("username") < kinds.index("new-password"), "the account comes first"
    assert all(i.get("name") for i in inputs), "every input is named"


def test_the_sign_in_form_has_named_username_and_password_fields():
    inputs = _forms("index.html")["loginForm"]
    by = {i.get("autocomplete"): i for i in inputs}
    assert by["username"].get("name") and by["current-password"].get("name")
