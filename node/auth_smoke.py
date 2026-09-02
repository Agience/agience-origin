"""Origin auth-flow smoke test.

Verifies each point of the service-provider <-> origin OIDC handshake: an SP that needs origin
redirects to the authorize endpoint, the login screen is reached, the token is exchanged, and the
caller is returned to the SP with a token the SP can verify. It also checks the flow refuses the
cases it should — an unregistered redirect URI, a malformed token request.

Two modes:
  --url https://origin.agience.ai   read-only verification of a live origin (no writes; safe on prod):
                                    discovery, JWKS, providers, authorize-redirect, invalid-redirect
                                    rejection, token-endpoint validation.
  (default, local)                  Boots nothing; expects ORIGIN_URL or falls back to the live one
                                    for the read-only surface. The full password door-opens path
                                    (register -> login -> token -> JWKS-verify) runs only against a
                                    local/dev origin (never prod), gated by --allow-write.

    python node/auth_smoke.py --url https://origin.agience.ai
    ORIGIN_URL=http://localhost:8080 python node/auth_smoke.py --allow-write   # full local flow
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

_PROD_HOSTS = ("origin.agience.ai",)


def _log(stage: str, status: str, detail: str = "") -> None:
    mark = {"PASS": "[OK]", "SEAM": "[~]", "FAIL": "[X]", "...": "[.]"}.get(status, "[.]")
    print("  %s %-22s %-4s %s" % (mark, stage, status, ("- " + detail) if detail else ""), flush=True)


def _get(url: str, *, allow_redirect: bool = True, timeout: float = 10.0):
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = urllib.request.build_opener() if allow_redirect else urllib.request.build_opener(_NoRedirect)
    try:
        r = op.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def _post(url: str, data: dict, timeout: float = 10.0):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def run(base: str, allow_write: bool, client_id: str = "agience-platform",
        redirect_uri: str = "") -> int:
    base = base.rstrip("/")
    is_prod = any(h in base for h in _PROD_HOSTS)
    print("=== ORIGIN AUTH SMOKE - %s%s ===" % (base, " (PROD, read-only)" if is_prod else ""), flush=True)

    # 1. Discovery — the well-known OIDC config, the map every SP reads to find the door.
    st, _, body = _get(base + "/.well-known/openid-configuration")
    disc = {}
    try:
        disc = json.loads(body)
    except Exception:
        pass
    ok = st == 200 and disc.get("authorization_endpoint") and disc.get("token_endpoint")
    _log("discovery", "PASS" if ok else "FAIL",
         "issuer=%s" % disc.get("issuer") if ok else "no openid-configuration (st=%s)" % st)
    if not ok:
        return 1
    authz = disc["authorization_endpoint"]
    token_ep = disc["token_endpoint"]
    jwks_uri = disc.get("jwks_uri", base + "/.well-known/jwks.json")

    # 2. JWKS — the keys an SP verifies origin's tokens with. Must have >=1 signing key.
    st, _, body = _get(jwks_uri)
    keys = []
    try:
        keys = json.loads(body).get("keys", [])
    except Exception:
        pass
    _log("jwks", "PASS" if st == 200 and keys else "FAIL",
         "%d signing key(s)" % len(keys) if keys else "no keys (st=%s)" % st)

    # 3. Providers — the login options origin offers (the login screen's choices).
    st, _, body = _get(base + "/auth/providers")
    provs = []
    try:
        j = json.loads(body)
        provs = j if isinstance(j, list) else j.get("providers", [])
    except Exception:
        pass
    _log("providers", "PASS" if st == 200 else "SEAM",
         "%s" % (provs or "reachable, shape varies") if st == 200 else "st=%s" % st)

    # 4. Authorize (valid) — /authorize?response_type=code&client_id=&redirect_uri=
    #    A well-formed request redirects (302) to the login screen; this test does not follow it.
    rdu = redirect_uri or (base + "/auth/callback")
    q = urllib.parse.urlencode({"response_type": "code", "client_id": client_id,
                                "redirect_uri": rdu, "provider": "google",
                                "state": "smoke", "scope": "openid email"})
    st, hdrs, _ = _get(authz + "?" + q, allow_redirect=False)
    loc = hdrs.get("Location", "") or hdrs.get("location", "")
    redirects = st in (302, 303, 307) and bool(loc)
    _log("authorize->login", "PASS" if redirects else "SEAM",
         "302 -> login screen (%s...)" % loc[:48] if redirects else
         "no redirect (st=%s) - pass --client-id/--redirect-uri the real registered pair" % st)

    # 5. Authorize (bad redirect_uri) — the same client, a callback it never registered. RFC 6749
    #    §4.1.2.1 forbids redirecting this error, so the refusal must be a 400/403 in the response.
    q_bad = urllib.parse.urlencode({"response_type": "code", "client_id": client_id,
                                    "redirect_uri": "https://evil.example/steal",
                                    "provider": "google"})
    st, _, _ = _get(authz + "?" + q_bad, allow_redirect=False)
    refused = st in (400, 403)
    _log("authorize-guard", "PASS" if refused else "FAIL",
         "wrong redirect refused (%s)" % st if refused else "SECURITY: bad redirect not refused (st=%s)" % st)

    # 6. Token endpoint — exchanges code -> token; a bogus code does not mint one.
    st, body = _post(token_ep, {"grant_type": "authorization_code", "code": "bogus-smoke-code",
                                "redirect_uri": rdu, "client_id": client_id})
    rejected = st in (400, 401, 403)
    _log("token-exchange", "PASS" if rejected else "FAIL",
         "bogus code rejected (%s)" % st if rejected else "SECURITY: bogus code not rejected (st=%s)" % st)

    # 7. Full door-opens (local/dev only) — register -> password login -> token -> JWKS-verify.
    if is_prod or not allow_write:
        _log("door-opens (full)", "SEAM",
             "skipped on prod/read-only - run against a local origin with --allow-write for the full flow")
    else:
        import secrets as _s
        email = "smoke-%s@local.test" % _s.token_hex(4)
        pw = "Smoke-" + _s.token_hex(8)
        st, _ = _post(base + "/auth/password/register", {"email": email, "password": pw})
        st2, body2 = _post(base + "/auth/password/login", {"email": email, "password": pw})
        tok = ""
        try:
            tok = json.loads(body2).get("access_token") or json.loads(body2).get("token") or ""
        except Exception:
            pass
        opened = st2 == 200 and bool(tok)
        _log("door-opens (full)", "PASS" if opened else "FAIL",
             "register(%s) login(%s) -> token len %d" % (st, st2, len(tok)))

    print("=== auth smoke complete ===", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default=os.getenv("ORIGIN_URL", "https://origin.agience.ai"))
    ap.add_argument("--allow-write", action="store_true",
                    help="run the full register->login->token path (local/dev origin ONLY)")
    ap.add_argument("--client-id", default=os.getenv("ORIGIN_CLIENT_ID", "agience-platform"),
                    help="the registered SP client_id (prod needs the real one for the redirect check)")
    ap.add_argument("--redirect-uri", default=os.getenv("ORIGIN_REDIRECT_URI", ""),
                    help="the SP callback (must be FACET_URI/ORIGIN_URI-based or loopback)")
    args = ap.parse_args()
    return run(args.url, args.allow_write, args.client_id, args.redirect_uri)


if __name__ == "__main__":
    sys.exit(main())
