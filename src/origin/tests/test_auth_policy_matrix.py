"""Origin's auth policy, asserted route by route: **authentication is the default**.

Every mounted operation must reach `get_auth`, unless it appears in `PUBLIC` below with a
reason. Adding a route gets it covered the day it is mounted; making a route public requires
an explicit, reviewable entry here.

**Why inverted, rather than a list of protected routes.** An enumerated list cannot cover a
route added tomorrow, and absence from it is indistinguishable from "not critical yet".

**This test flattens the dependency tree, and must.** Five operations reach `get_auth` only
through `get_person`, which depends on it. A top-level scan of `route.dependant.dependencies`
reports 23 authenticated operations; the transitive set is 28. A top-level-only check would
fail those five for no reason and teach the next reader to loosen the assertion.

`_require_operator` is an AUTHORIZATION layer, never authentication: no operation carries it
without also reaching `get_auth`. It is deliberately not accepted as a substitute below — if that
ever changes, this test fails, which is the point.

This suite needs no database: it inspects the route table only.
"""

import pytest
from fastapi.routing import APIRoute

from origin.main import app
from origin.services.dependencies import get_auth
from origin.services.operator_console import get_console_auth

#: The authenticators. `get_auth` everywhere; `get_console_auth` (the operator console's own token,
#: an audience no other service receives) on `/oracle/*` alone, which by decision (John,
#: 2026-11-01) must not accept an ordinary access token. `_require_operator` is still not one: it
#: is the authorization and step-up on top of the console's authentication.
AUTHENTICATORS = {get_auth, get_console_auth}


# =============================================================================
# The operations that answer without authentication, and why each one may.
# Read individually against the mounted app; an entry here is a decision, not a default.
# =============================================================================

_DISCOVERY = "discovery document — a client must read it BEFORE it can hold a token"
_SHELL = "static HTML shell; the page checks its own session. Serving a document grants nothing"
_PREAUTH = "the authentication surface itself — you cannot require a token to obtain a token"
_SETUP = (
    "first-boot wizard: guarded by an `X-Setup-Token` header compared with "
    "`secrets.compare_digest`, BEHIND `if not platform_settings.needs_setup(): raise 410`. The "
    "token can outlive setup — `delete_setup_token()` cannot unlink the file when `KEYS_DIR` is "
    "read-only, and `init_setup_token()` revives it on restart — so DB state is the real gate"
)
_PROBE = "liveness/build identity; touches no store and discloses no identity"

PUBLIC = {
    # A person's re-authentication at Origin's own pages (`services.person_step_up`): the ticket
    # names the request, `start` only sends the browser on to the ordinary sign-in, and `complete`
    # proves the ticket only with a sign-in code Origin minted for it and consumes there.
    ("GET", "/auth/reauth/start"): "a re-authentication's own page; grants nothing",
    ("GET", "/auth/reauth/complete"): "proven by the sign-in's code, consumed here; mints nothing",
    ("POST", "/auth/reauth/start"): "the start page's confirm, bound by its form token; leads to a sign-in",
    ("POST", "/auth/sign-out"): "ends the presented refresh token's own family; the token is the proof",
    ("POST", "/auth/me/authority/narrow"): "a delegation narrowed in the person's Origin session "
    "(cookie, custom header, the web app's Origin), never on a bearer (review 23)",
    ("POST", "/auth/me/authority/mantle-token"): "the token for Mantle, issued in the person's Origin "
    "session (cookie, custom header, the web app's Origin), never on a bearer (review 23)",
    ("POST", "/auth/me/authority/entries"): "authenticated by the person's Origin session cookie, "
                                            "with a custom header and the web app's origin (review 12)",
    ("POST", "/auth/me/authority/preview"): "what Origin holds about a resource, read in the person's Origin "
                                            "session cookie, with the custom header and the web app's origin (review 15)",
    ("POST", "/auth/me/authority/claim"): "an invite claimed by its token in the claimant's Origin session "
                                          "cookie, with the custom header and the web app's origin",
    # Review 13: grants and invites from Origin's own record, in the same session as above.
    ("GET", "/auth/me/authority/grants"): "Origin's record of a resource's grants, shown in the person's "
                                          "Origin session to a holder of Share or Admin",
    ("POST", "/auth/me/authority/grants"): "a grant made in the person's Origin session (cookie, custom "
                                           "header, the web app's origin); Origin mints its id",
    ("POST", "/auth/me/authority/grants/{grant_id}/change"): "a change to a grant Origin holds, built from "
                                                             "its own row, in the Origin session",
    ("POST", "/auth/me/authority/grants/{grant_id}/revoke"): "a revocation of a grant Origin holds, built "
                                                             "from its own row, in the Origin session",
    ("POST", "/auth/me/authority/invites"): "an invite Origin makes and mails to the address given, in the "
                                            "owner's Origin session; the token is in the mail alone",
    ("POST", "/auth/me/authority/invite-context"): "what an invite is, shown in the opener's Origin "
                                                   "session; carries nothing that claims it",
    # FR-004: invites that name the person arrive in the app; the same Origin session as above.
    ("GET", "/auth/me/authority/invites/incoming"): "the live invites naming the person (their id or verified "
                                                    "address), listed in their Origin session",
    ("POST", "/auth/me/authority/invites/{invite_id}/accept"): "the invite's target claims it in their Origin "
                                                               "session, by the ledger's claim rule",
    ("POST", "/auth/me/authority/invites/{invite_id}/decline"): "the invite's target retires it in their "
                                                                "Origin session",
    ("GET", "/auth/not-before"): "the signed not-before list peers enforce: person ids and times only, "
                                 "public like the JWKS (review 11, M2)",
    ("GET", "/"): _SHELL,
    ("GET", "/account"): _SHELL,
    ("GET", "/login"): _SHELL,
    ("GET", "/reset-password"): _SHELL,
    # Clears this browser's Origin session and serves the sign-out page; it grants nothing.
    ("GET", "/logout"): _SHELL,
    ("GET", "/verify-email"): _SHELL,
    ("GET", "/passkey"): _SHELL,
    ("GET", "/job-grant"): _SHELL,

    ("GET", "/.well-known/agience"): _DISCOVERY,
    ("GET", "/.well-known/jwks.json"): _DISCOVERY + " — public keys, published on purpose",
    ("GET", "/.well-known/oauth-authorization-server"): _DISCOVERY,
    ("GET", "/.well-known/openid-configuration"): _DISCOVERY,
    ("GET", "/.well-known/security.txt"): _DISCOVERY + " (RFC 9116)",

    ("GET", "/auth/authorize"): _PREAUTH,
    ("GET", "/auth/authorize/federate"): _PREAUTH,
    ("POST", "/auth/authorize/otp/request"): _PREAUTH,
    ("POST", "/auth/authorize/otp/verify"): _PREAUTH,
    ("POST", "/auth/authorize/password"): _PREAUTH,
    # Registration inside a sign-in already in flight. Pre-auth for the plainest reason there is:
    # the caller is creating the account, so there is no token they could hold. It is the sibling
    # of the `password` and `otp` legs above and ends at the same `_complete_local_signin`; the
    # account-creation gates it must not skip (`auth.password.enabled`, the allow-lists, email
    # verification) are asserted in `test_authorize_local_methods.py`, not here — this file asks
    # only whether authentication is required, and here it cannot be.
    ("POST", "/auth/authorize/register"): _PREAUTH + " — creating the account IS the request",
    ("GET", "/auth/callback"): _PREAUTH + " — the redirect target, by definition pre-auth",
    ("GET", "/auth/providers"): _PREAUTH + " — which providers exist, to render the login page, "
                                "and the public app URL the account page continues to",
    ("POST", "/auth/token"): _PREAUTH + " — the token endpoint IS the thing being obtained",
    ("POST", "/auth/register"): _PREAUTH,
    ("POST", "/auth/password/login"): _PREAUTH,
    ("POST", "/auth/password/register"): _PREAUTH,
    ("POST", "/auth/password/reset-request"): _PREAUTH,
    ("POST", "/auth/password/reset-confirm"): _PREAUTH,
    # Names the account a reset link resets; the link's signed, single-use token is the credential.
    ("POST", "/auth/password/reset-check"): _PREAUTH,
    ("POST", "/auth/otp/request"): _PREAUTH,
    ("POST", "/auth/otp/verify"): _PREAUTH,
    ("POST", "/auth/passkey/login-options"): _PREAUTH,
    ("POST", "/auth/passkey/login-complete"): _PREAUTH,
    ("POST", "/auth/email/verify-request"): _PREAUTH,
    ("POST", "/auth/email/verify-confirm"): _PREAUTH,
    ("POST", "/auth/bootstrap/claim"): _PREAUTH + " — claims the first operator, before one exists",
    # The operator console's passkey sign-in: the console token is what it issues.
    ("POST", "/oracle/console/sign-in-options"): _PREAUTH,
    ("POST", "/oracle/console/sign-in"): _PREAUTH,

    ("POST", "/setup/complete"): _SETUP,
    ("GET", "/setup/status"): _SETUP,
    ("POST", "/setup/validate-connection"): _SETUP,
    ("POST", "/setup/validate-token"): _SETUP,

    ("GET", "/healthz"): _PROBE,
    ("GET", "/version"): _PROBE,
}


def _iter_api_routes(container, _seen=None):
    """Every mounted APIRoute, descending included routers.

    FastAPI includes routers lazily, so `app.routes` can hold marker objects rather than the
    flattened routes; a plain `isinstance` scan of `app.routes` misses everything mounted with
    `include_router`.
    """
    _seen = _seen if _seen is not None else set()
    for route in getattr(container, "routes", []):
        if isinstance(route, APIRoute):
            yield route
        else:
            inner = getattr(route, "original_router", None) or getattr(route, "router", None)
            if inner is not None and id(inner) not in _seen:
                _seen.add(id(inner))
                yield from _iter_api_routes(inner, _seen)


def _flat_dependencies(dependant, acc=None):
    """Every dependency reachable from a route, INCLUDING sub-dependencies."""
    acc = acc if acc is not None else set()
    for dep in dependant.dependencies:
        if dep.call is not None:
            acc.add(dep.call)
        _flat_dependencies(dep, acc)
    return acc


def _get_route(path: str, method: str) -> APIRoute:
    method = method.upper()
    for route in _iter_api_routes(app):
        if route.path == path and method in route.methods:
            return route
    raise AssertionError("Route not found for %s %s" % (method, path))


def _all_operations():
    out = []
    for route in _iter_api_routes(app):
        for method in sorted((route.methods or set()) - {"HEAD", "OPTIONS"}):
            out.append((method, route.path))
    return sorted(set(out))


@pytest.mark.parametrize("method,path", _all_operations())
def test_every_route_requires_auth_unless_declared_public(method, path):
    """Authentication is the default. Exemption requires an entry in `PUBLIC` with a reason."""
    if (method, path) in PUBLIC:
        pytest.skip("declared public: %s" % PUBLIC[(method, path)])
    route = _get_route(path, method)
    deps = _flat_dependencies(route.dependant)
    if get_console_auth in deps:
        assert path.startswith(("/oracle/", "/auth/clients")), (
            f"{method} {path}: the console token is for /oracle/* and server credentials")
    assert deps & AUTHENTICATORS, (
        "%s %s does not reach get_auth, directly or through a sub-dependency. If it is meant to "
        "answer without authentication, add it to PUBLIC in this file WITH A REASON — do not "
        "delete this assertion, and do not accept `_require_operator` as a substitute: that is "
        "authorization, and it presumes an authenticated caller." % (method, path)
    )


@pytest.mark.parametrize("method,path", [op for op in _all_operations()
                                         if op[1].startswith("/oracle/") and op not in PUBLIC])
def test_an_operator_route_takes_the_console_token_and_no_access_token(method, path):
    deps = _flat_dependencies(_get_route(path, method).dependant)
    assert get_console_auth in deps and get_auth not in deps, f"{method} {path}"


@pytest.mark.parametrize("method,path", sorted(PUBLIC))
def test_the_public_allowlist_is_not_stale(method, path):
    """Every exemption must still be real, and must still BE an exemption.

    An allowlist rots two silent ways: the route is deleted or renamed, leaving an entry that
    documents a policy for something that no longer exists; or the route GAINS authentication,
    leaving an exemption nobody uses — and the day the dependency comes off again, nothing
    complains. Asserting both means the list can only shrink by someone noticing.
    """
    route = _get_route(path, method)          # raises if the route is gone
    assert not _flat_dependencies(route.dependant) & AUTHENTICATORS, (
        "%s %s is listed in PUBLIC but now reaches get_auth. Remove it from PUBLIC — the route is "
        "protected, and leaving the entry preserves a stale exemption." % (method, path)
    )
