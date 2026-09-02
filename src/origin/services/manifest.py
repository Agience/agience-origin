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


def manifest_path() -> Path:
    """Default manifest location. Override with `MANIFEST_PATH` env."""
    explicit = os.getenv("MANIFEST_PATH")
    if explicit:
        return Path(explicit)
    data_path = os.getenv("DATA_PATH", "/data")
    return Path(data_path) / "manifest.yml"


def load(path: Path | None = None) -> dict[str, Any]:
    """Read + parse the manifest. Returns `{}` when missing or empty."""
    p = path or manifest_path()
    if not p.exists():
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
