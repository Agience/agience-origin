"""Manifest loader — declarative platform state.

A single optional YAML file at `${DATA_PATH}/manifest.yml` (or path passed in) declares
platform state. Each service applies its own section idempotently on
startup. If absent, services come up empty and the setup wizard handles
configuration interactively.

Origin applies these sections (this file):
- `operator` — first-boot operator account (Person + `platform.operator_id`)
- `platform_settings` — DB-backed settings (plain + secret)

Other sections are deliberately not applied here — `grants` and `seed_collections`
belong to the peer that owns authorization and the store.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from origin.db import persons as db_persons
from origin.services import auth_service as origin_auth
from origin.services.platform_settings_service import settings as platform_settings

logger = logging.getLogger(__name__)


def manifest_path() -> Path | None:
    """`manifest.yml` in Origin's own folder, the one that holds its database (`ORIGIN_DB_PATH`),
    or None when that is not set (review 18). No other path is read: not a default, not a
    `DATA_PATH`."""
    db = (os.getenv("ORIGIN_DB_PATH") or "").strip()
    if not db:
        return None
    return Path(db).parent / "manifest.yml"


def _euid():
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else None


def _owner_mode(path: Path) -> dict:
    import stat
    st = os.stat(path, follow_symlinks=False)
    return {"uid": st.st_uid, "mode": stat.S_IMODE(st.st_mode)}


def _refusal(p: Path) -> str | None:
    """Why the manifest at `p` is not read, or None: the folder this process's own at 0700 (as
    `custody_refusal` asks of KEYS_DIR), the file its own and writable by no one else."""
    me = _euid()
    if me is None:
        return "this platform shows no process user to check the manifest's owner against"
    try:
        folder, file = _owner_mode(p.parent), _owner_mode(p)
    except OSError as exc:
        return f"its folder or file could not be checked ({exc})"
    if folder["uid"] != me or folder["mode"] & 0o077:
        return f"its folder {p.parent} is not this service's own at 0700"
    if file["uid"] != me or file["mode"] & 0o022:
        return "the file is not this service's own, or others may write it"
    return None


def load(path: Path | None = None) -> dict[str, Any]:
    """Read + parse the manifest. Returns `{}` when missing, empty, or not Origin's own."""
    p = path or manifest_path()
    if p is None or not p.exists():
        return {}
    why = _refusal(p)
    if why:
        logger.warning("manifest %s is not applied: %s", p, why)
        return {}
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("manifest %s could not be parsed: %s", p, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("manifest %s root is not a mapping", p)
        return {}
    return data


def apply(db: Session, manifest: dict[str, Any]) -> dict[str, int]:
    """Idempotently apply Origin's sections of a manifest.

    Returns a counts dict for the operator's audit log:
    `{operator_created, settings_written}`.
    """
    counts = {"operator_created": 0, "settings_written": 0}

    operator = manifest.get("operator") or {}
    if isinstance(operator, dict) and operator.get("email"):
        if _ensure_operator(db, operator):
            counts["operator_created"] = 1

    settings_section = manifest.get("platform_settings") or {}
    if isinstance(settings_section, dict) and settings_section:
        counts["settings_written"] = _apply_platform_settings(db, settings_section)

    if any(counts.values()):
        logger.info("manifest applied: %s", counts)
    return counts


def _ensure_operator(db: Session, operator: dict) -> bool:
    """Create the operator Person if no one with this email exists yet."""
    email = (operator.get("email") or "").strip().lower()
    if not email:
        return False
    existing = db_persons.get_by_email(db, email)
    if existing:
        # Stamp operator_id on platform_settings (idempotent).
        platform_settings.set_value(
            db,
            "platform.operator_id",
            str(existing.id),
            is_secret=False,
            category="platform",
        )
        return False

    raw_password = operator.get("password")
    password_hash = operator.get("password_hash")
    if raw_password and not password_hash:
        password_hash = origin_auth.hash_password(raw_password)

    name = operator.get("name") or email.split("@")[0]
    person = db_persons.create(
        db,
        {
            "email": email,
            "name": name,
            "username": name,
            "password_hash": password_hash,
            "email_verified": True,          # the operator's own address, from the manifest
        },
    )
    db.flush()
    platform_settings.set_value(
        db,
        "platform.operator_id",
        str(person.id),
        is_secret=False,
        category="platform",
    )
    logger.info("manifest: created operator %s (%s)", person.id, email)
    return True


def _apply_platform_settings(db: Session, settings_section: dict) -> int:
    """Write each `key: value` pair to platform_settings.

    Keys with `_secret` suffix are stored encrypted (e.g.
    `auth.google.client_secret`). The convention: a key whose name contains
    `secret`, `password`, `api_key`, `token`, or `credential` is encrypted.
    """
    secret_markers = ("secret", "password", "api_key", "token", "credential")
    written = 0
    for raw_key, raw_value in settings_section.items():
        key = str(raw_key)
        value = str(raw_value) if raw_value is not None else ""
        is_secret = any(marker in key.lower() for marker in secret_markers)
        category = key.split(".")[0] if "." in key else "platform"
        platform_settings.set_value(
            db,
            key,
            value,
            is_secret=is_secret,
            category=category,
        )
        written += 1
    return written
