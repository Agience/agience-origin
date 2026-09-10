"""Origin's system surface — the admin endpoints, in one place.

Origin does no authorization of its own, so "platform admin" for these endpoints
means the bootstrap operator (`platform.operator_id`) and nothing more. Granting
other users platform-admin, and listing who holds it, belong to the peer that owns
the authority collection — Origin neither stores nor serves that.

Routes
------
- ``GET   /system/settings``            — every setting, grouped by category
- ``GET   /system/settings/{category}`` — one category
- ``PATCH /system/settings``            — write settings
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from origin import config
from origin.db.session import get_db
from origin.services.dependencies import AuthContext, get_auth
from origin.services.platform_settings_service import (
    is_secret_key as platform_settings_is_secret_key,
    settings as platform_settings,
)

logger = logging.getLogger(__name__)
system_router = APIRouter(prefix="/system", tags=["System"])


class SettingItem(BaseModel):
    key: str
    value: Optional[str] = None
    # `is_secret` is not accepted from the client: accepting it would let a caller store a secret
    # in plaintext (by claiming it isn't one) or silently downgrade an already-encrypted value by
    # resubmitting it with is_secret=false. The server classifies via
    # `platform_settings_service.is_secret_key`, derived from the key itself. Pydantic ignores
    # unknown fields by default, so an old client sending `is_secret` still works — the value is
    # simply disregarded.


class UpdateSettingsRequest(BaseModel):
    settings: list[SettingItem]


class UpdateSettingsResponse(BaseModel):
    updated: int
    restart_required: bool = False


# ⛔ THESE SETTINGS DO REQUIRE A RESTART, and this set was empty while they did.
#
# `_apply_db_settings_to_config()` is what copies a stored setting into `config.*`, and
# `reload_oauth_providers()` is what rebuilds `REGISTERED_PROVIDERS` from `config.*`. Both are
# called from exactly one place — `main.py`, inside the lifespan. Nothing on this router calls
# either, so writing `auth.google.client_id` here stores it and changes nothing that is serving:
# `/auth/providers` still reports `[]` and no button appears.
#
# With the set empty the response said `restart_required: false`, which is worse than saying
# nothing — an operator sets three values, is told no restart is needed, sees no Google button,
# and has no reason to suspect the write succeeded. Naming the keys is what makes the answer true.
#
# ⚠ THE PROVIDER KEYS ARE DERIVED, NOT LISTED. `_SETTING_MAP` is exactly the set
# `_apply_db_settings_to_config` resolves through `_pref()`, so reading it here cannot drift from
# what that function reads. A hand-written list here did drift, immediately and silently: it named
# 13 keys and omitted all four `auth.auth0.*` ones, which would have reported
# `restart_required: false` on an Auth0 setup that needs a restart exactly as much as Google does.
# `config.py`'s own comment on that map warns that a second hand-copied list is how one goes stale;
# this is that second list, so it is not written out.
_RESTART_REQUIRED_KEYS: set[str] = set(getattr(config, "_SETTING_MAP", {})) | {
    # The rest of what `_apply_db_settings_to_config` reads. These do NOT go through `_pref`, so
    # they are not in `_SETTING_MAP` and cannot be derived from it — they are read by name, in that
    # function, and nowhere else. Changing where Origin thinks its facet lives, or who is allowed
    # to sign in, takes effect on the next boot and not before.
    #
    # `tests/test_system_settings_restart.py` parses `main.py` and fails if this set stops matching
    # what that function actually reads, which is the only thing keeping the two in step.
    "branding.facet_uri",
    "branding.facet_uris",
    "auth.allowed_emails",
    "auth.allowed_domains",
    "auth.allowed_google_ids",
    "auth.email_verification.enabled",
    "auth.email_verification.allowlist",
}


def _platform_admin_user_id(auth: AuthContext, db: Session) -> str:
    """Resolve the caller as Origin platform admin (the operator) or 403.

    Two conditions, matching the guard in `oracle_router`, because either alone is not enough:

      • `principal_type == "user"` rejects mcp_client / service / server. `resolve_auth` also
        populates `user_id` from `sub` for a third-party `mcp_client` token, so without this check
        an MCP app the operator authorized with `scope=read` would carry `sub=<operator_id>` and
        pass as the operator — able to `PATCH /system/settings`. `scopes` is never consulted here.
      • `actor is None` rejects a delegation, which `resolve_auth` normalizes to
        `principal_type="user"` with `actor=act.sub`. A `principal_type` check alone lets a
        delegation through — a server acting on the operator's behalf for some narrow purpose must
        not thereby become the platform admin.
    """
    if auth.principal_type != "user" or auth.actor is not None or not auth.user_id:
        raise HTTPException(status_code=403, detail="Platform admin access required")
    operator_id = platform_settings.get("platform.operator_id")
    if operator_id and auth.user_id == operator_id:
        return auth.user_id
    raise HTTPException(status_code=403, detail="Platform admin access required")


def _settings_grouped(category: Optional[str] = None) -> dict[str, list[dict]]:
    """Read all settings from the cache, group by category. Secrets masked as None."""
    grouped: dict[str, list[dict]] = {}
    for key, value in platform_settings._values.items():  # noqa: SLF001 — internal
        cat = key.split(".")[0] if "." in key else "platform"
        if category and cat != category:
            continue
        grouped.setdefault(cat, []).append({"key": key, "value": value, "is_secret": False})
    for key in platform_settings._secrets:  # noqa: SLF001
        cat = key.split(".")[0] if "." in key else "platform"
        if category and cat != category:
            continue
        grouped.setdefault(cat, []).append({"key": key, "value": None, "is_secret": True})
    for entries in grouped.values():
        entries.sort(key=lambda e: e["key"])
    return grouped


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------
@system_router.get("/settings")
async def get_all_settings(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict:
    _platform_admin_user_id(auth, db)
    return {"categories": _settings_grouped()}


@system_router.get("/settings/{category}")
async def get_settings_by_category(
    category: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> list[dict]:
    _platform_admin_user_id(auth, db)
    grouped = _settings_grouped(category=category)
    return grouped.get(category, [])


@system_router.patch("/settings", response_model=UpdateSettingsResponse)
async def update_settings(
    body: UpdateSettingsRequest,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> UpdateSettingsResponse:
    admin_user_id = _platform_admin_user_id(auth, db)
    settings_dicts = []
    restart_required = False
    for item in body.settings:
        # Secrets are masked as None on read, so an unchanged secret comes back
        # empty on a round-trip. Skip those rather than blanking the stored value.
        # Classification is the server's, from the key — not the request.
        item_is_secret = platform_settings_is_secret_key(item.key)
        if item_is_secret and not item.value:
            continue
        if item.key in _RESTART_REQUIRED_KEYS:
            restart_required = True
        category = item.key.split(".")[0] if "." in item.key else "platform"
        settings_dicts.append(
            {
                "key": item.key,
                "value": item.value or "",
                "category": category,
            }
        )
    platform_settings.set_many(db, settings_dicts, updated_by=admin_user_id)
    return UpdateSettingsResponse(updated=len(settings_dicts), restart_required=restart_required)
