"""Every operator route, one by one, refuses a caller without the console token and a caller
without a fresh passkey step-up for that very request.

The routes are read from the app, not listed here: every route under `/oracle/` other than the
three that open the console depends on `oracle_router._require_operator`, so a route added without
the guard fails `test_every_oracle_route_but_the_console_s_own_carries_the_guard` before any
refusal is checked. Each guarded route is then called four ways: an ordinary operator access token,
the console token with no step-up, the console token with a step-up made for another request, and
the console token with a step-up already spent on this one.

Imports happen inside the tests: the `origin_app` fixture reloads `origin.config`.
"""
from __future__ import annotations

import json as jsonlib
import re

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

#: The console's own entrances: they are how a console token and a step-up are obtained.
CONSOLE_ENTRANCES = {("POST", "/oracle/console/sign-in-options"),
                     ("POST", "/oracle/console/sign-in"),
                     ("POST", "/oracle/console/step-up-options")}

REFUSED = (401, 403)


def _calls(dependant):
    yield dependant.call
    for sub in dependant.dependencies:
        yield from _calls(sub)


#: The console's surfaces: the operator routes, and server credentials (`/auth/clients`).
CONSOLE_PREFIXES = ("/oracle/", "/auth/clients")


def oracle_routes(app):
    """`(method, path, guarded)` for every route on the console's surfaces in `app`."""
    from fastapi.routing import APIRoute

    from origin.routers import oracle_router, server_credentials_router

    guards = (oracle_router._require_operator, server_credentials_router._require_operator)
    out = []
    for r in app.routes:
        if not isinstance(r, APIRoute) or not r.path.startswith(CONSOLE_PREFIXES):
            continue
        calls = list(_calls(r.dependant)) + [d.dependency for d in r.dependencies]
        guarded = any(c in guards for c in calls)
        for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
            out.append((m, r.path, guarded))
    return out


def unguarded(app):
    return [(m, p) for m, p, g in oracle_routes(app) if not g and (m, p) not in CONSOLE_ENTRANCES]


def test_every_oracle_route_but_the_console_s_own_carries_the_guard(custody_client):
    app = custody_client.app
    routes = oracle_routes(app)
    assert len([r for r in routes if r[2]]) >= 30, routes        # the routes were found at all
    assert unguarded(app) == []


def _concrete(path):
    return re.sub(r"\{[^}]+\}", "probe-1", path)


def _send(c, method, path, token, step=None):
    from origin.services import operator_console

    body = b"" if method in ("GET", "DELETE") else jsonlib.dumps({}).encode()
    headers = {"Authorization": f"Bearer {token}"}
    if body:
        headers["Content-Type"] = "application/json"
    if step is not None:
        headers[operator_console.STEP_UP_HEADER] = step
    return c.request(method, path, content=body or None, headers=headers), body


def _access_token():
    from origin import config
    from origin.services.auth_service import create_jwt_token

    return create_jwt_token({"sub": af.OPERATOR, "email": "op@x.test", "name": "Op",
                             "client_id": "platform", "aud": config.AUTHORITY_ISSUER})


def test_each_operator_route_refuses_without_the_console_token_or_a_fresh_step_up(
        custody_client, monkeypatch):
    c = custody_client
    af.operator(monkeypatch)
    auth, console_token = oc.console(c)
    access = _access_token()
    guarded = [(m, _concrete(p)) for m, p, g in oracle_routes(c.app) if g]
    assert guarded
    wrong = []
    for method, path in guarded:
        body = b"" if method in ("GET", "DELETE") else jsonlib.dumps({}).encode()
        # An ordinary operator access token, with a step-up the console signed for this request.
        step = oc.step_up(c, console_token, auth, method, path, body)
        r, _ = _send(c, method, path, access, step)
        if r.status_code not in REFUSED:
            wrong.append((method, path, "access token", r.status_code))
        # The console token, no step-up.
        r, _ = _send(c, method, path, console_token)
        if r.status_code not in REFUSED:
            wrong.append((method, path, "no step-up", r.status_code))
        # The console token, a step-up made for another request.
        elsewhere = ("/oracle/secrets" if path != "/oracle/secrets"
                     else "/oracle/authority-ledger/verify")
        other = oc.step_up(c, console_token, auth, "GET", elsewhere, b"")
        r, _ = _send(c, method, path, console_token, other)
        if r.status_code not in REFUSED:
            wrong.append((method, path, "another request's step-up", r.status_code))
        # The console token, a step-up spent once on this very request.
        step = oc.step_up(c, console_token, auth, method, path, body)
        _send(c, method, path, console_token, step)
        r, _ = _send(c, method, path, console_token, step)
        if r.status_code not in REFUSED:
            wrong.append((method, path, "a spent step-up", r.status_code))
    assert wrong == []
