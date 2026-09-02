"""
origin/config.py — Platform configuration.

Origin is the identity authority and owns the platform settings. Peers ask Origin for them over
HTTP; each service still reads its own service URIs from its own environment.

Runtime settings live in Origin's `platform_settings` table and are loaded into module-level
variables at boot. An operator may override a value through the environment, which always wins.

Read values as ``config.X`` in a function body, never ``from origin.config import X``: the
latter snapshots the value at import time and misses the Phase 2 rebinding below.

Boot phases, in the order they run:
  Phase 0                 — load_env(): reads `.env` into os.environ, before any os.getenv call.
  Phase 1  (import time)  — static constants, and safe defaults for every variable.
  Phase 2                 — `main._apply_db_settings_to_config()` rebinds the subset Origin
                            consumes from the platform-settings cache, environment first.
"""

import os
import uuid as _uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse as _urlparse, urlunparse as _urlunparse

from dotenv import load_dotenv as _load_dotenv


def _origin_only(uri: str) -> str:
    """Return scheme+host+port (strip path, query, fragment)."""
    p = _urlparse(uri)
    return _urlunparse((p.scheme, p.netloc, "", "", "", ""))

# ---------------------------------------------------------------------------
#  Phase 0: Load .env into os.environ (before any os.getenv calls)
# ---------------------------------------------------------------------------

_BACKEND_ROOT = Path(__file__).resolve().parent.parent


def load_env(base_dir: Optional[Path] = None) -> Optional[Path]:
    """Load a service's `.env` — called explicitly by each service at startup, never at import.

    Config is a module several services import; auto-loading a `.env` relative to this file (origin)
    would inject origin's `.env` into every importer's process and clobber the environment a service
    (or a test) has already set. So each service calls this once from its own `main.py` with its own
    `base_dir`, and a `.env` only ever provides defaults: the process environment always wins
    (`override=False`, standard 12-factor). A supervisor that sets the environment directly and
    ships no `.env` makes this a no-op.
    """
    # Tests set AGIENCE_NO_DOTENV=1 so a real dev `.env` on the machine can never leak into a test's
    # environment (`load_dotenv` mutates os.environ outside monkeypatch's restore, so it would persist).
    if os.getenv("AGIENCE_NO_DOTENV"):
        return None
    root = Path(base_dir).resolve() if base_dir else _BACKEND_ROOT
    for candidate in (root / ".env", root.parent / ".env"):
        if candidate.is_file():
            _load_dotenv(candidate, override=False)
            return candidate
    return None

# ---------------------------------------------------------------------------
#  Phase 1: Static constants (safe at import time, never change)
# ---------------------------------------------------------------------------

# In a checkout this package lives at <repo>/src/origin/, so the repo root is one level above
# _BACKEND_ROOT. Installed into a virtualenv it sits in site-packages, where the on-disk layout
# reveals nothing about where the deployment keeps its data — so AGIENCE_BASE_DIR pins the root
# explicitly and a managed install sets it.
_BASE_DIR_OVERRIDE = os.getenv("AGIENCE_BASE_DIR")
BASE_DIR = (
    Path(_BASE_DIR_OVERRIDE).resolve()
    if _BASE_DIR_OVERRIDE
    else (_BACKEND_ROOT.parent if _BACKEND_ROOT.name == "src" else _BACKEND_ROOT)
)
KEYS_DIR = Path(os.getenv("KEYS_DIR", str(BASE_DIR / ".data" / "keys")))

# Platform identity — deterministic UUID, never changes.
AGIENCE_PLATFORM_USER_ID = str(_uuid.uuid5(_uuid.NAMESPACE_URL, "agience://platform"))


# ---------------------------------------------------------------------------
#  Phase 1: DB-backed variables — initialized to safe defaults.
#  These are rebound in Phase 2 after settings are loaded from origin's database.
# ---------------------------------------------------------------------------

# Email verification — require new password sign-ups to confirm their email via
# a link before they can sign in. Disabled by default; enable with
# EMAIL_VERIFICATION_ENABLED=true. EMAIL_VERIFICATION_ALLOWLIST (comma-separated
# emails and/or bare domains) is auto-verified (skips the email). Both can also
# be set as platform settings (auth.email_verification.*) which win at runtime.
EMAIL_VERIFICATION_ENABLED: bool = os.getenv(
    "EMAIL_VERIFICATION_ENABLED", ""
).strip().lower() in ("1", "true", "yes", "on")
EMAIL_VERIFICATION_ALLOWLIST: list = [
    e.strip().lower()
    for e in os.getenv("EMAIL_VERIFICATION_ALLOWLIST", "").split(",")
    if e.strip()
]
# OAuth providers (all optional, configured via settings UI)
GOOGLE_OAUTH_CLIENT_ID: Optional[str] = None
GOOGLE_OAUTH_CLIENT_SECRET: Optional[str] = None
GOOGLE_OAUTH_REDIRECT_URI: Optional[str] = None

MICROSOFT_ENTRA_TENANT: str = "common"
MICROSOFT_ENTRA_CLIENT_ID: Optional[str] = None
MICROSOFT_ENTRA_CLIENT_SECRET: Optional[str] = None
MICROSOFT_ENTRA_REDIRECT_URI: Optional[str] = None

AUTH0_DOMAIN: Optional[str] = None
AUTH0_CLIENT_ID: Optional[str] = None
AUTH0_CLIENT_SECRET: Optional[str] = None
AUTH0_REDIRECT_URI: Optional[str] = None

CUSTOM_OIDC_NAME: Optional[str] = None
CUSTOM_OIDC_METADATA_URL: Optional[str] = None
CUSTOM_OIDC_CLIENT_ID: Optional[str] = None
CUSTOM_OIDC_CLIENT_SECRET: Optional[str] = None
CUSTOM_OIDC_REDIRECT_URI: Optional[str] = None
CUSTOM_OIDC_SCOPES: str = "openid email profile"

# Password auth. `auth.password.enabled` and `auth.password.min_length` are platform settings and
# are read straight from the settings cache at each call site, so they have no module variable here.
#
# OWASP's current PBKDF2-HMAC-SHA256 floor for password storage. Raising it is safe for stored
# hashes because `auth_service.hash_password` writes the count into the hash and `verify_password`
# reads it back per hash — an account created at 200000 keeps verifying, and
# `auth_router._upgrade_password_hash_if_stale` re-derives it at this cost on its owner's next
# successful sign-in. Read from the environment here or nowhere.
PASSWORD_PBKDF2_ITERS: int = int(os.getenv("PASSWORD_PBKDF2_ITERS") or 600000)

# URIs & identity.
#   FACET_URI   — where users reach the front end
#   ORIGIN_URI  — this service: identity, OIDC issuer, JWT `iss`
FACET_URI: str = os.getenv("FACET_URI", "http://localhost:8080")
# `FACET_URIS` lists every facet base this authority admits, not just the one in `FACET_URI`.
# `is_client_redirect_allowed` accepts only `FACET_URI` and `ORIGIN_URI` as redirect bases, but a
# node runs many facets (e.g. `aria.`, `sage.`, `pharos.` alongside whichever facet holds the slot),
# and each one needs to begin a sign-in through this authority. `FACET_URIS` adds the rest without
# renaming or replacing `FACET_URI`, which remains first: it is read on its own elsewhere
# (branding, the local-dev detection just below in `is_client_redirect_allowed`), and every
# existing node declares it.
FACET_URIS: list = [
    u.strip() for u in os.getenv("FACET_URIS", "").split(",") if u.strip()
]
ORIGIN_URI: str = os.getenv("ORIGIN_URI", "http://localhost:8080")
PLATFORM_CLIENT_ID: str = os.getenv("PLATFORM_CLIENT_ID", "agience-client")
# `PLATFORM_CLIENT_IDS` lists every first-party OAuth client this authority mints full user JWTs
# for, not just the one in `PLATFORM_CLIENT_ID`. Same shape as `FACET_URI`/`FACET_URIS`, for the
# same reason: `PLATFORM_CLIENT_ID` stays first and every existing node declares it, while a node
# in fact runs several first-party surfaces — mantle's browser sign-in reads its own
# `MANTLE_OIDC_CLIENT_ID`, which has no default and is under no obligation to equal this value.
#
# Membership is the whole of the first-party test: a client id is first-party because an operator
# enrolled it here and third-party otherwise. Every id absent from this set gets the scoped,
# PII-free `mcp_client` token — including one that enrolled itself through `POST /auth/register`,
# which writes `oauth_clients` and which no first-party check reads. A client vouching for itself
# is not an operator naming it.
#
# This is an admission list as well as a trust list, and Mantle's browser client needs it.
# `/authorize` refuses a `client_id` that is neither named here nor registered in `oauth_clients`,
# so an unenrolled `MANTLE_OIDC_CLIENT_ID` does not reach a login page at all. Unenrolled, the
# browser would receive an `mcp_client` token with no email, no name and no roles.
PLATFORM_CLIENT_IDS: list = [
    c.strip() for c in os.getenv("PLATFORM_CLIENT_IDS", "").split(",") if c.strip()
]
# RFC 7591 dynamic client registration — whether `POST /auth/register` exists at all, and whether
# it demands an initial access token when it does.
#
# Off is the default because open is the unsafe half. An enabled, tokenless endpoint lets any
# anonymous caller write rows to `oauth_clients` without bound; on a node reachable from the
# internet that is a spam surface, and on a home node it is the whole point — the same endpoint,
# two deployments, so the difference belongs in configuration rather than in a fork of the handler.
# A node that does nothing gets the behaviour it has today: no `registration_endpoint` in the
# discovery document and nothing to POST to.
#
# `CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` is RFC 7591 §3's initial access token, presented as an
# RFC 6750 bearer token on the registration request. Set it and registration is gated; leave it
# empty and an enabled endpoint is open to anyone who can reach it.
#
# Read from the environment here or nowhere: `_apply_db_settings_to_config` names neither of
# these, so a platform-settings row by either name would never reach the running value.
CLIENT_REGISTRATION_ENABLED: bool = os.getenv(
    "CLIENT_REGISTRATION_ENABLED", ""
).strip().lower() in ("1", "true", "yes", "on")
CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN: str = os.getenv(
    "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", ""
).strip()
# Whether `GET /internal/persons/{id}` refuses a caller that presents no subject token.
#
# The platform-service check on that route proves the caller is one of the four named services and
# stops there: a service JWT carries `iss=sub=<service>` and no subject, so it says who is asking
# and never on whose behalf. `/internal/delegation-token` already shows the shape that closes
# that — the caller presents the subject's own token and Origin derives the subject from what it
# verified, never from a caller-asserted id. The person lookup takes the same credential in an
# `X-Subject-Token` header, and this setting decides whether its absence is refused.
#
# Off by default, because a live caller sends nothing. Chorus's platform-email path resolves a
# recipient's address while handling a Stripe webhook, where there is no user token in hand to
# forward, so turning this on before that path carries one takes receipt and usage-warning mail
# down.
#
# The flag governs the absence and nothing else. A presented `X-Subject-Token` is verified, refused
# if it is not a live user token, and required to name the person in the path — on both settings.
# So a caller that starts sending one is held to the tighter rule the moment it ships rather than at
# the flip, and no caller can weaken itself by sending one. Every call that still arrives without
# one is logged at WARNING naming the caller; when that log is quiet, the flip costs nothing.
#
# Read from the environment here or nowhere, exactly as the two settings above: `_SETTING_MAP` does
# not list it and `main.py::_apply_db_settings_to_config` does not name it, so a platform-settings
# row by this name would never reach the running value.
PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED: bool = os.getenv(
    "PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED", ""
).strip().lower() in ("1", "true", "yes", "on")
# JWT issuer/audience identity. This is the public origin URI and must be the same
# across every service (origin stamps it into `iss`; mantle/chorus validate against
# it). It is decoupled from ORIGIN_URI because mantle/chorus reach origin over the
# internal url (http://origin:8080) but must still trust the public issuer. Set
# AUTHORITY_ISSUER=https://<domain> on every service; falls back to ORIGIN_URI for
# single-host/dev where they coincide.
AUTHORITY_ISSUER: str = _origin_only(os.getenv("AUTHORITY_ISSUER") or ORIGIN_URI)
# Authority domain = host of the public issuer (e.g. my.agience.ai), not the internal
# origin host. Derived from AUTHORITY_ISSUER so it's the public domain everywhere.
AUTHORITY_DOMAIN: str = _urlparse(AUTHORITY_ISSUER).hostname or "localhost"

# Event logger (optional)
EVENT_LOGGER_URI: Optional[str] = None
EVENT_LOGGER_USERNAME: Optional[str] = None
EVENT_LOGGER_PASSWORD: Optional[str] = None

# Email
PLATFORM_EMAIL_ADDRESS: str = ""

# Access control
ALLOWED_EMAILS: list[str] = []
ALLOWED_DOMAINS: list[str] = []
ALLOWED_GOOGLE_IDS: list[str] = []

# Key material is read through `origin.key_manager` at the point of use — `get_encryption_key()`,
# `get_nonce_secret()` — and is deliberately not mirrored into a module global here. A global would
# be a second copy that is correct only if something remembered to populate it.
# ---------------------------------------------------------------------------
#  Phase 2: the settings Origin rebinds from the platform-settings cache
# ---------------------------------------------------------------------------
#
# `main._apply_db_settings_to_config()` does the rebinding, and this map is what it reads to learn
# which environment variable outranks a stored value for a given setting key. The environment wins
# whenever it is set and non-empty; an empty assignment is treated as unset, so a stock `.env`
# template line does not blank a key correctly stored in the database.
#
# Only the OAuth provider keys are here, because they are the only ones resolved by that lookup.
# Everything else Origin rebinds — the facet bases, the sign-in allow-lists, email verification —
# is named explicitly in `_apply_db_settings_to_config`, and the settings whose only source is the
# environment are read where they are declared above.
#
#: setting key -> the environment variable that overrides it
_SETTING_MAP: dict[str, tuple[str]] = {
    # Google OAuth
    "auth.google.client_id": ("GOOGLE_OAUTH_CLIENT_ID",),
    "auth.google.client_secret": ("GOOGLE_OAUTH_CLIENT_SECRET",),
    "auth.google.redirect_uri": ("GOOGLE_OAUTH_REDIRECT_URI",),

    # Microsoft Entra
    "auth.microsoft.tenant": ("MICROSOFT_ENTRA_TENANT",),
    "auth.microsoft.client_id": ("MICROSOFT_ENTRA_CLIENT_ID",),
    "auth.microsoft.client_secret": ("MICROSOFT_ENTRA_CLIENT_SECRET",),
    "auth.microsoft.redirect_uri": ("MICROSOFT_ENTRA_REDIRECT_URI",),

    # Auth0
    "auth.auth0.domain": ("AUTH0_DOMAIN",),
    "auth.auth0.client_id": ("AUTH0_CLIENT_ID",),
    "auth.auth0.client_secret": ("AUTH0_CLIENT_SECRET",),
    "auth.auth0.redirect_uri": ("AUTH0_REDIRECT_URI",),

    # Custom OIDC
    "auth.oidc.name": ("CUSTOM_OIDC_NAME",),
    "auth.oidc.metadata_url": ("CUSTOM_OIDC_METADATA_URL",),
    "auth.oidc.client_id": ("CUSTOM_OIDC_CLIENT_ID",),
    "auth.oidc.client_secret": ("CUSTOM_OIDC_CLIENT_SECRET",),
    "auth.oidc.redirect_uri": ("CUSTOM_OIDC_REDIRECT_URI",),
    "auth.oidc.scopes": ("CUSTOM_OIDC_SCOPES",),
}
