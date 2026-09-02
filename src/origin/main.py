"""Origin — FastAPI app entry point.

Listens on port 8080. Owns identity, OIDC, passkeys, OTP, server credentials, platform settings,
setup, and the key oracle. It exposes no grant or API-key HTTP surface — see the routers section.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse as _urlparse

from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from origin import config
from origin.authority_trust import get_authority_manifest
from origin.key_manager import (
    get_jwk_public,
    get_key_id,
    init_encryption_key,
    init_jwt_keys,
    init_nonce_secret,
    init_setup_token,
)
from origin.db.session import SessionLocal, build_database_url, init_engine
from origin.routers.auth_router import auth_router as auth_router_module
from origin.routers.auth_router import internal_router as auth_internal_router
from origin.routers.auth_router import root_router as auth_root_router
from origin.routers.otp_router import otp_router
from origin.routers.passkey_router import passkey_router
from origin.routers.system_router import system_router
from origin.routers.server_credentials_router import router as server_credentials_router
from origin.routers.setup_router import setup_router
from origin.routers.oracle_router import oracle_router
from origin.services import manifest as manifest_loader
from origin.services.oidc_providers import reload_oauth_providers
from origin.services.platform_settings_service import settings as platform_settings
from origin.logging_utils import configure_logging

# Apply the shared logging config in-process so timestamps land on uvicorn's
# own startup + access lines regardless of the --log-config CLI flag.
configure_logging()
logger = logging.getLogger("agience.origin")


# ---------------------------------------------------------------------------
# Build info
# ---------------------------------------------------------------------------
#: An optional file a deployment may stamp with the revision it built. Absent — the ordinary case
#: for a `pip install` — the version comes from the installed distribution's own metadata instead.
BUILD_INFO_PATH = os.getenv("BUILD_INFO_PATH", "")


def _parse_components(raw: str) -> dict:
    """`"a=sha,b=sha"` -> `{"a": "sha", "b": "sha"}`. Never raises.

    A stamped revision set arrives as one flat string and is widened here. Malformed pairs are
    DROPPED rather than guessed at: a component this service cannot name a revision for must be
    absent rather than wrong, because a wrong sha sends someone to verify against a commit that does
    not exist and read the failure as a compromised node.
    """
    out = {}
    for pair in (raw or "").split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        name, _, rev = pair.partition("=")
        name, rev = name.strip(), rev.strip()
        if name and rev:
            out[name] = rev
    return out


def _installed_version() -> str:
    """The version pip recorded for this distribution, or "" when it is not installed.

    A checkout run with `pip install -e .` reports its version too, so `/version` says something
    true in every way Origin is actually run. Never raises: a source tree on `PYTHONPATH` with no
    distribution at all is a development shape, not a fault.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("agience-origin")
    except PackageNotFoundError:
        return ""


def _load_build_info() -> dict:
    """What `/version` reports.

    A deployment that stamps `BUILD_INFO_PATH` gets exactly what it stamped — a commit sha, a build
    time, a revision set across several components. Everything else gets the installed
    distribution's version, which is the honest answer for a `pip install` and is what identifies
    the code running.

    Empty fields mean "this deployment did not say", which reads differently from a wrong value: a
    sha that names a commit the tree does not contain sends someone to verify against nothing and
    read the failure as a compromised node.
    """
    for candidate in [BUILD_INFO_PATH, str(Path(__file__).resolve().parent.parent / "build_info.json")]:
        if not candidate:
            continue
        try:
            data = json.loads(Path(candidate).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        data.setdefault("build_time", "")
        # A stamp that names no version still identifies the code, via the distribution metadata.
        if not data.get("version"):
            data["version"] = _installed_version()
        data["components"] = _parse_components(data.get("components") or "")
        return data

    return {"version": _installed_version(), "build_time": "", "components": {}}


BUILD_INFO = _load_build_info()


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
def _run_migrations() -> None:
    """`alembic upgrade head`, in-process, on every boot.

    A restart is Origin's deploy, so a merged revision is applied by the next restart — whatever
    caused it. The only control is `ORIGIN_SKIP_MIGRATIONS=1`, which is all-or-nothing and has to
    be set before the boot that would have run it.

    A migration that raises aborts the lifespan and Origin does not serve, which is loud and
    recoverable. Write revisions so that the ones which SUCCEED are safe to apply unattended: a
    downgrade/re-upgrade round trip that restores a column with a permissive default, or recreates
    a table empty, reports success either way.

    There is no advisory lock, so two replicas booting together both run `upgrade head` against one
    database.
    """
    here = Path(__file__).resolve().parent
    cfg = AlembicConfig(str(here / "alembic.ini"))
    cfg.set_main_option("script_location", str(here / "alembic"))
    cfg.set_main_option("sqlalchemy.url", build_database_url())
    logger.info("Origin: running alembic upgrade to head")
    command.upgrade(cfg, "head")


# ---------------------------------------------------------------------------
# Config rebinding from platform_settings (SQLite-backed)
# ---------------------------------------------------------------------------
def _apply_db_settings_to_config() -> None:
    """Read platform_settings from the DB and rebind origin.config attributes.

    Only the subset of settings Origin consumes is rebound here; every other key keeps the default
    `config` read at import.
    """
    # OAuth providers — secrets come from `secret_value`, plain values from `value`. The
    # environment wins whenever the variable is set and non-empty (see `_pref` below); assigning
    # DB values unconditionally would let an empty DB row overwrite a value `config.load_env()`
    # already read from `.env`, and a provider with no client_id does not register.
    #
    # `config._SETTING_MAP` supplies the environment-variable name that outranks each stored
    # setting; the keys it does not cover are hand-tuned below.
    def _pref(setting_key: str, *, secret: bool = False, default=None):
        """DB value, unless the environment says otherwise — the one precedence, applied here too.

        The env variable name is taken from `config._SETTING_MAP` rather than written out again:
        a second hand-copied list of these pairs is how one of them goes stale.
        """
        mapping = getattr(config, "_SETTING_MAP", {}).get(setting_key)
        env_name = mapping[0] if mapping else None
        if env_name:
            env_val = os.getenv(env_name)
            # An empty assignment (`GOOGLE_OAUTH_CLIENT_ID=`, the usual template line) is treated
            # as unset, not as a decision to blank a key that is stored in the DB.
            if env_val is not None and env_val.strip() != "":
                return env_val
        stored = platform_settings.get_secret(setting_key) if secret else platform_settings.get(setting_key)
        return stored if stored not in (None, "") else default

    config.GOOGLE_OAUTH_CLIENT_ID = _pref("auth.google.client_id")
    config.GOOGLE_OAUTH_CLIENT_SECRET = _pref("auth.google.client_secret", secret=True)
    config.GOOGLE_OAUTH_REDIRECT_URI = _pref("auth.google.redirect_uri")

    config.MICROSOFT_ENTRA_TENANT = _pref("auth.microsoft.tenant", default="common")
    config.MICROSOFT_ENTRA_CLIENT_ID = _pref("auth.microsoft.client_id")
    config.MICROSOFT_ENTRA_CLIENT_SECRET = _pref("auth.microsoft.client_secret", secret=True)
    config.MICROSOFT_ENTRA_REDIRECT_URI = _pref("auth.microsoft.redirect_uri")

    config.AUTH0_DOMAIN = _pref("auth.auth0.domain")
    config.AUTH0_CLIENT_ID = _pref("auth.auth0.client_id")
    config.AUTH0_CLIENT_SECRET = _pref("auth.auth0.client_secret", secret=True)
    config.AUTH0_REDIRECT_URI = _pref("auth.auth0.redirect_uri")

    # The custom-OIDC keys are `auth.oidc.*` in `_SETTING_MAP`.
    config.CUSTOM_OIDC_NAME = _pref("auth.oidc.name")
    config.CUSTOM_OIDC_METADATA_URL = _pref("auth.oidc.metadata_url")
    config.CUSTOM_OIDC_CLIENT_ID = _pref("auth.oidc.client_id")
    config.CUSTOM_OIDC_CLIENT_SECRET = _pref("auth.oidc.client_secret", secret=True)
    config.CUSTOM_OIDC_REDIRECT_URI = _pref("auth.oidc.redirect_uri")
    config.CUSTOM_OIDC_SCOPES = _pref("auth.oidc.scopes", default="openid email profile")

    # Branding / URIs — Origin signs JWTs with `iss = AUTHORITY_ISSUER`. Default
    # to `ORIGIN_URI` env so dev works without DB settings.
    fe = platform_settings.get("branding.facet_uri")
    # The environment wins over the stored value: an explicitly-set `FACET_URI` is an operator's
    # deliberate instruction and outranks stored configuration (12-factor). A deployment relying
    # on the stored value sets no env var and is unaffected. `AUTHORITY_ISSUER` below applies the
    # same precedence — env first, stored value second — so the two settings agree.
    config.FACET_URI = os.getenv("FACET_URI") or fe or config.FACET_URI

    # The plural follows the same precedence as `FACET_URI` above: env wins when set and
    # non-empty; otherwise the stored list; otherwise whatever config.py read at import. The
    # comma-separated string is split here, because a base that still contained commas could never
    # match a parsed `scheme://netloc`.
    _fu_env = os.getenv("FACET_URIS")
    if _fu_env is not None and _fu_env.strip() != "":
        config.FACET_URIS = [u.strip() for u in _fu_env.split(",") if u.strip()]
    else:
        _fu_db = platform_settings.get("branding.facet_uris")
        if _fu_db:
            config.FACET_URIS = (
                [u.strip() for u in _fu_db.split(",") if u.strip()]
                if isinstance(_fu_db, str) else list(_fu_db)
            )

    config.AUTHORITY_ISSUER = (
        os.getenv("ORIGIN_URI") or fe or getattr(config, "AUTHORITY_ISSUER", "http://localhost:8080")
    )

    # Allow lists (used by `is_person_allowed`).
    raw = platform_settings.get("auth.allowed_emails", "")
    config.ALLOWED_EMAILS = [e.strip() for e in (raw or "").split(",") if e.strip()]
    raw = platform_settings.get("auth.allowed_domains", "")
    config.ALLOWED_DOMAINS = [d.strip() for d in (raw or "").split(",") if d.strip()]
    raw = platform_settings.get("auth.allowed_google_ids", "")
    config.ALLOWED_GOOGLE_IDS = [g.strip() for g in (raw or "").split(",") if g.strip()]

    # Email verification — platform settings (if present) win over the env defaults.
    config.EMAIL_VERIFICATION_ENABLED = platform_settings.get_bool(
        "auth.email_verification.enabled", getattr(config, "EMAIL_VERIFICATION_ENABLED", False)
    )
    raw = platform_settings.get("auth.email_verification.allowlist", "")
    if raw:
        config.EMAIL_VERIFICATION_ALLOWLIST = [e.strip().lower() for e in raw.split(",") if e.strip()]


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
def _refuse_multiple_workers() -> None:
    """Refuse to start with more than one worker, by name, before anything else runs.

    `routers/auth_router.py` holds `authorization_codes` and `pkce_challenges` as **per-process
    dicts**, which is correct on one worker only. Add a second and the OAuth code exchange breaks
    for whichever share of requests lands on a worker that did not mint the code — an intermittent
    `invalid_grant` with every worker healthy, every log clean and nothing to grep for. Refusing to
    boot and saying why is far cheaper to diagnose than a login that fails one time in N.

    This is a guard, not a fix. The fix is to move both stores out of the process, the way
    `models/passkey_challenge.py` already holds WebAuthn challenges server-side; when they move,
    delete this function.
    """
    import os

    signals = {
        "WEB_CONCURRENCY": os.getenv("WEB_CONCURRENCY"),
        "UVICORN_WORKERS": os.getenv("UVICORN_WORKERS"),
        "GUNICORN_CMD_ARGS": os.getenv("GUNICORN_CMD_ARGS"),
    }
    for name, raw in signals.items():
        # Strip before testing for empty. `WEB_CONCURRENCY="  "` is truthy, so an unstripped
        # check sends whitespace on to `int()` and refuses the boot — and whitespace is how a
        # templated or shell-exported environment renders a variable it has no value for. Caught by
        # `test_an_unreadable_worker_count_is_refused_not_ignored[  ]`, which is the case that
        # separates "malformed" from "absent".
        raw = (raw or "").strip()
        if not raw:
            continue
        if name == "GUNICORN_CMD_ARGS":
            if "--workers" in raw or "-w " in raw:
                raise RuntimeError(
                    "Origin refuses to start: %s requests multiple workers (%r), and its OAuth "
                    "authorization codes and PKCE challenges are per-process "
                    "(routers/auth_router.py). A second worker breaks the code exchange "
                    "intermittently and silently. Run one worker, or move those two stores to the "
                    "database first — models/passkey_challenge.py is the pattern." % (name, raw))
            continue
        try:
            n = int(str(raw).strip())
        except ValueError:
            # An unparseable value is not permission to continue: it is a setting somebody meant.
            raise RuntimeError(
                "Origin refuses to start: %s=%r could not be read as a worker count, and Origin "
                "must know it is single-process (see routers/auth_router.py)." % (name, raw))
        if n > 1:
            raise RuntimeError(
                "Origin refuses to start: %s=%d, and its OAuth authorization codes and PKCE "
                "challenges are per-process (routers/auth_router.py). With more than one "
                "worker the code exchange fails for whichever share of requests lands on a worker "
                "that did not mint the code — an intermittent invalid_grant with every worker "
                "healthy. Run one worker, or move those two stores to the database first; "
                "models/passkey_challenge.py is the pattern that already did it." % (name, n))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Before anything else: this service is only correct single-process. See the function.
    _refuse_multiple_workers()
    # Load this service's own `.env` at startup (defaults only; the environment already set wins).
    # At startup, not module import: config is a shared module, and importing it (e.g. in a test)
    # does not pull a `.env` beside it into the process.
    config.load_env(Path(__file__).resolve().parent.parent)
    # Key material from disk (must exist; the installer or a key-init step writes it)
    # kid="origin-1" matches the kid published in the authority manifest
    # (key init writes origin's JWKS with that kid) and the service_identity kid.
    init_jwt_keys(key_id="origin-1")
    init_encryption_key()
    init_nonce_secret()
    init_setup_token()
    # Origin's service identity (origin.private.pem) — same key used for both
    # service-to-service mutual JWTs AND user tokens (the OIDC issuer signing key).
    from origin import service_identity
    service_identity.init_service_identity("origin")

    # DB engine, then migrations
    init_engine()
    if os.getenv("ORIGIN_SKIP_MIGRATIONS") != "1":
        _run_migrations()

    # Load settings, apply the manifest if present, rebind config, register providers
    if os.getenv("ORIGIN_SKIP_DB_SETTINGS") != "1":
        with SessionLocal() as session:
            platform_settings.load_all(session)
            manifest_doc = manifest_loader.load()
            if manifest_doc:
                manifest_loader.apply(session, manifest_doc)
                session.commit()
                # Re-load cache so downstream code sees manifest-applied values.
                platform_settings.load_all(session)
        _apply_db_settings_to_config()
    reload_oauth_providers()

    logger.info("Origin: ready (kid=%s, providers=%d)", get_key_id(), len(_registered_providers()))
    yield


def _registered_providers() -> dict:
    from origin.services.oidc_providers import REGISTERED_PROVIDERS

    return REGISTERED_PROVIDERS


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Agience Origin",
    description="Identity, OIDC, grants, passkeys, OTP, API keys, server credentials.",
    version=BUILD_INFO.get("version") or "0.0.0-dev",
    lifespan=lifespan,
)


def _as_origin(url: str) -> str:
    """`scheme://host[:port]` — what a browser puts in an `Origin` header, and nothing else.

    A configured URL may carry a path (`https://app.example.com/ui`); a browser never sends one, so
    an allowlist entry with a path is an entry that can never match.
    """
    parts = _urlparse((url or "").strip())
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def _allowed_origins() -> list[str]:
    """The browser origins Origin answers cross-site, never `["*"]`.

    The default is derived from configuration Origin already requires to be right: the issuer, its
    own public URI, and the facet bases `is_client_redirect_allowed` admits as redirect targets.
    Those are exactly the first-party browser surfaces — a page Origin will redirect a sign-in back
    to is a page it should answer XHR for, and one it will not is not.

    A wildcard is survivable only while every endpoint stays bearer-only and the OAuth cookies stay
    same-site, and that is not a property the service minting every token in the platform should be
    one handler away from losing.

    In development the derived set is the localhost defaults, so nothing an operator has to notice
    changes. In production it is the front ends the node already declares, and an operator with one
    more sets `ORIGIN_ALLOWED_ORIGINS` — which `.env.example` documents and which the startup log
    names on every boot, so a missing entry reads as a listed allowlist that omits it rather than as
    a sign-in that mysteriously fails.

    Environment only. `branding.facet_uri` and `branding.origin_uri` are also platform settings,
    loaded from the database inside `lifespan` — after this list has been handed to the middleware
    and frozen. A facet configured only in the settings store must be named in
    `ORIGIN_ALLOWED_ORIGINS` as well.
    """
    raw = os.getenv("ORIGIN_ALLOWED_ORIGINS", "").strip()
    if raw:
        configured = [_as_origin(o) for o in raw.split(",")]
        return sorted({o for o in configured if o})

    derived = [config.AUTHORITY_ISSUER, config.ORIGIN_URI, config.FACET_URI, *config.FACET_URIS]
    return sorted({o for o in (_as_origin(u) for u in derived) if o})


_ALLOWED_ORIGINS = _allowed_origins()
logger.info("Origin: CORS allow_origins=%s", _ALLOWED_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _read_session_secret() -> str:
    """The key the login-flow session cookie is signed with, read from `platform_internal.secret`."""
    from origin.config import KEYS_DIR
    secret_path = KEYS_DIR / "platform_internal.secret"
    if secret_path.exists():
        try:
            return secret_path.read_text().strip()
        except OSError:
            pass
    # No persisted secret yet (pre-first-boot): use a random per-process key rather
    # than a known constant, so OAuth PKCE-state cookies are never signed with a
    # published value. Sessions reset on restart until the secret file is provisioned.
    import logging
    import secrets as _secrets
    logging.getLogger("origin.main").warning(
        "session secret %s absent — using an ephemeral random key (sessions reset on restart)",
        secret_path,
    )
    return _secrets.token_urlsafe(48)


def _session_cookie_is_https_only() -> bool:
    """Whether the login-flow session cookie carries `Secure`.

    The cookie holds `pkce_challenges` state and the half-finished sign-in; without `Secure` a
    browser will put it on a plain-HTTP request, so anything that can downgrade one navigation
    reads it.

    Keyed on the scheme of `AUTHORITY_ISSUER` because that is the one value in Origin's config that
    names the address a *browser* uses. `ORIGIN_URI` may be the internal `http://origin:8080` peers
    dial while users arrive over TLS at a reverse proxy, and the request's own scheme is likewise
    the proxy's back leg rather than the browser's — reading either would mark the cookie insecure
    on exactly the deployment that most needs it secure.

    Secure by default, in the sense that matters: every deployment that is not plain-HTTP gets the
    flag, and the only configuration that does not is one already saying its browser-facing URL is
    `http://`, where a `Secure` cookie is never sent at all and local development would simply stop
    working. An operator behind TLS who has not set `AUTHORITY_ISSUER` is not a case this can
    rescue — the tokens Origin signs already carry `iss: http://localhost:8080` and no peer in the
    mesh accepts them.
    """
    return _urlparse(config.AUTHORITY_ISSUER or "").scheme == "https"


app.add_middleware(
    SessionMiddleware,
    secret_key=_read_session_secret(),
    max_age=12 * 60 * 60,
    https_only=_session_cookie_is_https_only(),
)


# ---------------------------------------------------------------------------
# Global exception handler — keep tracebacks out of HTTP responses.
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def unhandled_exception_logger(request: Request, exc: Exception):
    logger.exception(
        "HTTP 500 %s %s error=%s",
        request.method,
        request.url.path,
        repr(exc),
    )
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router_module)
app.include_router(auth_root_router)
app.include_router(auth_internal_router)
app.include_router(passkey_router)
app.include_router(otp_router)
app.include_router(server_credentials_router)
# Origin exposes no grant or API-key HTTP surface: its own grants and keys tables serve its own
# auth and platform-admin management, and are never read over the wire.
app.include_router(setup_router)
app.include_router(system_router)
app.include_router(oracle_router)


# ---------------------------------------------------------------------------
# The account surface — served by the authority
# ---------------------------------------------------------------------------
# The login form is served here rather than by a separate frontend service, so the page that
# collects a credential is the same origin that verifies it and sets the session: no CORS, and no
# session cookie treated as third-party. This is also how every OIDC provider works, and what
# `/auth/authorize` already assumes.
#
# `web/index.html` ("Sign in · Agience") carries `#login`/`#identifier`/`#password`/`#register`;
# `web/account.html` ("Account · Agience") is the signed-in view.
#
# The surface lives inside the package, beside the module that serves it, which is why the path is
# one `.parent` deep. Asking the module where it is gives one answer in all three places the code
# runs: `src/origin/web` in a checkout and `<site-packages>/origin/web` in an install. A path resolved from the repo root works only in a checkout: an installed
# distribution has no repository above it, so the same expression names a directory nothing creates
# and every page route answers 500 while the suite stays green.
#
# `pyproject.toml`'s `[tool.setuptools.package-data]` is what puts the surface in the distribution,
# and `tests/test_the_package_ships_what_it_serves.py` holds both halves: that the assets are inside
# the package, and that the packaging declares them.
_WEB_DIR = Path(__file__).resolve().parent / "web"


def _page(filename: str) -> Response:
    """One page of the account surface — or a plain statement that this deployment has none.

    `FileResponse` on a path that does not exist raises when the response is SENT, after the route
    has already returned; the global handler above catches that and answers 500 "Internal Server
    Error". A 500 says the request provoked a bug, and it is the wrong sentence: nothing is wrong
    with the request, and nothing is wrong with the code. The deployment simply has no static
    surface mounted.

    Not 404. `/login` is not a URL that does not exist here — it is part of Origin's contract,
    published in the sign-in links other services build. A 404 tells a client the address is wrong
    and invites it to stop asking; the address is right and the instance is incomplete.

    So 503, `no-store`, and a body naming the missing file. That is the same answer
    `/.well-known/agience` already gives when the authority manifest is absent (see
    `authority_discovery` below) — one condition, "Origin was not fully provisioned", one code —
    and it is the answer a load balancer can act on, which 500 and 404 both are not.
    """
    path = _WEB_DIR / filename
    if not path.is_file():
        logger.error(
            "account surface missing: %s is not on disk — this deployment did not ship "
            "origin/web/ — the distribution needs it declared as package-data", path)
        return JSONResponse(
            status_code=503,
            content={"error": "account_surface_missing", "detail": f"{filename} is not deployed"},
            headers={"Cache-Control": "no-store"},
        )
    return FileResponse(path)


@app.get("/login", include_in_schema=False)
def login_page() -> Response:
    """The sign-in form. Same-origin with the endpoint that verifies it."""
    return _page("index.html")


@app.get("/", include_in_schema=False)
def account_or_signin(request: Request) -> Response:
    """Serves the account page when the request carries a session, the sign-in form otherwise.

    The session is a claim to render against — every endpoint behind this page still verifies for
    itself; serving a page here grants nothing.
    """
    signed_in = bool((request.session or {}).get("user_id") or (request.session or {}).get("sub"))
    return _page("account.html" if signed_in else "index.html")


@app.get("/account", include_in_schema=False)
def account_page() -> Response:
    """The account page. `app.js::finishLogin` and `/`'s signed-in branch both route here.

    The page checks its own session; serving the document grants nothing, as `/` already
    assumes.
    """
    return _page("account.html")


@app.get("/reset-password", include_in_schema=False)
def reset_password_page() -> Response:
    """The "Forgot your password?" target on the sign-in form."""
    return _page("reset-password.html")


@app.get("/verify-email", include_in_schema=False)
def verify_email_page() -> Response:
    """Where the verification mail lands, and where `index.html` sends a fresh registration
    (`/verify-email?sent=1`). This is the step that marks an email verified, which the
    identity-linking rule in `person_service` requires before it links an identity."""
    return _page("verify-email.html")


# The assets those pages reference, mounted under a prefix rather than at `/` — so a future
# route can never be shadowed by a filename, and nothing outside `web/` is reachable. Every HTML
# file under `web/` references its assets at this `/web/...` prefix accordingly.
if _WEB_DIR.is_dir():
    app.mount("/web", StaticFiles(directory=str(_WEB_DIR)), name="web")
else:                       # a checkout without the surface logs the gap, rather than 404ing blankly
    logger.warning("origin web surface missing at %s — /login and / will fail", _WEB_DIR)


# ---------------------------------------------------------------------------
# Health / version
# ---------------------------------------------------------------------------
@app.get("/healthz", tags=["health"])
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/version", tags=["health"])
def version() -> dict:
    return BUILD_INFO


# This is the only JWKS endpoint Origin has. `auth_router.root_router` serves
# `/.well-known/openid-configuration` and nothing else, and that document's `jwks_uri` field points
# straight back here. Deleting this route would leave every peer verifying Origin-signed tokens
# with no key source at all.
@app.get("/.well-known/jwks.json", include_in_schema=False)
def jwks_root() -> dict:
    return {"keys": [get_jwk_public()]}


# Origin is the identity authority and owns the /.well-known namespace
# (it already serves jwks.json + openid-configuration). security.txt is a
# site-level security-contact file (RFC 9116), so it belongs here too.
# `Expires` is computed ~1 year out per request so it never goes stale.
@app.get("/.well-known/security.txt", include_in_schema=False)
def security_txt() -> PlainTextResponse:
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = (
        "Contact: mailto:connect@agience.ai\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n"
    )
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Agience discovery — one URL to find the mesh
# ---------------------------------------------------------------------------
#: Manifest fields that never reach this endpoint. `bootstrap_token_hash` gates first-boot
#: enrolment; publishing it would hand an attacker the offline target for the one secret that
#: admits a new service. The projection below is an allow-list for that reason — a deny-list
#: would publish every field a future manifest version adds.
_DISCOVERY_PUBLIC_ANCHOR_FIELDS = ("uri", "jwks")

#: How a client should treat each service. Anything unlisted defaults to `peer` (another ember).
_ROLES = {"origin": "authority", "mantle": "lattice"}


@app.get("/.well-known/agience", include_in_schema=False)
def agience_discovery(request: Request) -> JSONResponse:
    """The one URL a new peer needs: `https://origin.agience.ai/.well-known/agience`.

    A projection of the authority manifest, not a second source of truth. The manifest already
    records, per service, the deployment `uri` and the inline public `jwks` — this endpoint
    republishes the public half so a client can find the mesh without being handed a config file.

    Origin is the courier here, not the trust root. Everything in the response is verifiable
    against the authority manifest a peer already holds (from its bundle, a USB stick, or another
    peer): same `artifact_id`, same per-service JWKS. A client verifies this document against the
    anchor it already has, rather than trusting it because it arrived over TLS from this hostname
    — trusting the hostname would substitute DNS control for cryptographic trust. This is also
    what lets a peer serve the document itself when origin is unreachable.

    `mantle` is published with role `lattice`, not `peer`: there is deliberately no ember at the
    mantle endpoint, only a plain REST service that embers reconcile against rather than with. An
    ember holds its own lattice and reconciles with peer embers directly; it does not read through
    this URI. The distinction is the difference between a leaf that works unplugged and a thin
    client that does not.
    """
    # The configured identity, not the request: `request.base_url` reports `http://` behind any
    # TLS-terminating proxy, which would publish the wrong scheme, and a peer that bootstraps from
    # this document would then pin a JWKS URL that redirects or fails.
    base_url = (getattr(config, "AUTHORITY_ISSUER", "") or config.ORIGIN_URI or "").rstrip("/")
    try:
        manifest = get_authority_manifest()
    except FileNotFoundError:
        # Fails loudly and machine-readably. A discovery document that 200s with an empty service
        # map is worse than a 503: every client would cache "the mesh has no members" as a fact.
        return JSONResponse(
            status_code=503,
            content={"error": "authority_manifest_missing",
                     "detail": "Origin has no authority manifest; run init before serving discovery."},
            headers={"Cache-Control": "no-store"},
        )

    services = {}
    for name, anchor in (manifest.trust_anchors or {}).items():
        pub = {k: anchor[k] for k in _DISCOVERY_PUBLIC_ANCHOR_FIELDS if k in anchor}
        if pub.get("uri"):
            # `role` says how to treat the service, so a client never infers it from the name.
            #   authority — verify against it (origin)
            #   lattice   — the shared substrate: a REST service holding the store (mantle)
            #   peer      — another ember, reconciled with directly
            pub["role"] = _ROLES.get(name, "peer")
            services[name] = pub

    return JSONResponse(
        content={
            "issuer": manifest.issuer,
            "authority_artifact": manifest.artifact_id,
            "origin": base_url,
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "openid_configuration": f"{base_url}/.well-known/openid-configuration",
            "services": services,
        },
        headers={"Cache-Control": "public, max-age=300"},
    )
