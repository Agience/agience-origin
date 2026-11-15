"""Origin's approval pages tell the app that opened them of a refusal, with its reason, at once.

2026-11-15, the Tester: a key over a collection the person could not grant was refused on Origin's
page, which said so and told the app nothing; the app waited ("Generating...") until its window
closed or ten minutes passed. Each page's `refused` now answers the opener, as Approve and Cancel do.
The app's side (`askOrigin` stops on a `-refused` answer and shows its reason) is chorus's test.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1] / "web"


@pytest.mark.parametrize("page, kind", [("key-page.js", "agience.key-refused"),
                                        ("job-grant-page.js", "agience.job-grant-refused")])
def test_a_refusal_answers_the_app_with_its_reason(page, kind):
    js = (WEB / page).read_text(encoding="utf-8")
    body = re.search(r"function refused\(detail\) \{(.*?)\n  \}", js, re.S)
    assert body, f"{page} has no refused()"
    assert "answer(" in body.group(1) and kind in body.group(1) and "detail" in body.group(1)
