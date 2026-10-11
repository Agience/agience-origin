"""`/logout` ends Origin's session for the browser: the server session, and (in the page) the stored
token, then returns only to an address Origin lists.

2026-10-11: with my.agience.ai on Origin's SSO list, signing out of my.agience.ai came straight back
signed in. Its own sign-out cleared only its own token; Origin still held a session and handed a
new token to the next visit.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

WEB = Path(__file__).resolve().parents[1] / "web"


def test_the_route_clears_the_server_session_and_serves_the_sign_out_page(origin_app):
    import origin.main as m

    request = SimpleNamespace(session={"sub": "person-1", "user_id": "person-1"})
    response = m.logout_page(request)
    assert request.session == {}
    assert Path(response.path).name == "logout.html"


def test_the_page_clears_the_token_and_returns_only_to_a_listed_address():
    page = (WEB / "logout.html").read_text(encoding="utf-8")
    assert "clearToken();" in page
    assert 'get("/auth/providers")' in page and "isListedReturn(back, listed)" in page
    assert 'let to = "/";' in page, "an unlisted return goes to Origin's own sign-in"


def test_the_account_page_signs_out_through_logout():
    assert 'location.href="/logout"' in (WEB / "account.html").read_text(encoding="utf-8")
