"""Every relative link on the sign-in page must resolve against the app that serves it.

⛔ BOTH LEGAL LINKS 404'd IN PRODUCTION, AND NOTHING NOTICED. Measured 2026-09-16 in a browser:
`origin.agience.ai/terms` and `/privacy` both returned 404 while `/` returned 200. The footer of
the sign-in page — and of the *create account* form — linked to `/terms` and `/privacy`, which this
service has never served. A user clicking either got the raw body `{"detail":"Not Found"}`.

The pages existed the whole time, at `https://agience.ai/terms` and `/privacy`, served by the
marketing site from `www.agience.ai/src/pages/Terms.tsx`. Only the hrefs were wrong: two hardcoded
copies of one line, in `auth_router.py` and `web/index.html`.

⚠ THIS CLASS OF DEFECT IS INVISIBLE TO EVERY OTHER TEST. The page renders, returns 200, has zero
console errors and loads all seven of its resources. Nothing is broken until somebody clicks. The
suite asserted the page's *behaviour* — sign-in, reset, signup — and never that its links go
anywhere, so a credential-collecting beta advertised terms nobody could read.

This checks the general property rather than those two paths, because naming them would pass the
day someone adds a third. Only 404 counts as dead: a link that redirects or demands auth resolves.
"""

from __future__ import annotations

import re

import pytest


def _relative_hrefs(html: str) -> list[str]:
    hrefs = re.findall(r'href="([^"]+)"', html)
    # `//host/path` is protocol-relative and therefore external, not a route on this app.
    return sorted({h for h in hrefs if h.startswith("/") and not h.startswith("//")})


#: Both entry points, because production does not use the one that is convenient to test.
#: `/` is what you get locally; `/login?redirect_uri=…` is where `my.agience.ai` sends every real
#: user, and it was carrying the same broken footer. They render from the same two sources today —
#: asserting both is what keeps that true.
SIGN_IN_PATHS = ("/", "/login?redirect_uri=https%3A%2F%2Fmy.agience.ai%2F&state=t")


@pytest.mark.parametrize("path", SIGN_IN_PATHS)
def test_every_relative_link_on_the_sign_in_page_resolves(client, path):
    """The assertion the 404s would have failed."""
    body = client.get(path).text
    relative = _relative_hrefs(body)

    # ⚠ An empty extraction would satisfy the loop below perfectly. The page has at least
    # `/reset-password`, so finding nothing means the regex stopped matching, not that the page
    # became clean.
    assert relative, (
        "no relative links extracted from %s — this check is measuring nothing" % path)

    dead = [h for h in relative if client.get(h).status_code == 404]
    assert not dead, (
        "%s links to %d path(s) this service does not serve: %s. A user clicking one gets a raw "
        "JSON error." % (path, len(dead), dead))


def test_the_legal_links_are_present_and_point_somewhere_real(client):
    """The complement, and the reason the check above is not enough on its own.

    Deleting the footer would make every remaining relative link resolve, so the first test would
    pass on a signup form with no terms link at all. That is a worse outcome than the defect, not a
    better one — so the links must exist, and must be absolute, since this service does not serve
    the pages.
    """
    body = client.get("/").text
    for name in ("Terms", "Privacy"):
        assert ">%s<" % name in body, (
            "the sign-in footer no longer offers a %s link. This is a beta that collects an email "
            "and a password; it does not get to stop saying where its terms are." % name)

    for path in ("terms", "privacy"):
        assert 'href="https://agience.ai/%s"' % path in body, (
            "the %s link is not the absolute apex URL. `origin` does not serve /%s — that is the "
            "defect this file exists for, and a relative href reintroduces it." % (path, path))
