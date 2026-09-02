"""Origin platform settings — database-backed, with an in-memory cache.

Secrets are stored encrypted in the `secret_value` column (Fernet) and decrypted
on read. Plain settings live in `value`.

`load_all(session)` populates the cache at startup. `set_value()` writes through
to the database and the cache. `needs_setup()` is true until
`platform.setup_complete` flips to "true".
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from origin.key_manager import get_encryption_key
from origin.db import platform_settings as db_settings
from origin.models.platform_setting import PlatformSetting

logger = logging.getLogger(__name__)


# Defaults — used when no DB row exists. Trimmed
# to settings Origin actually consumes.
DEFAULTS: dict[str, str] = {
    "platform.setup_complete": "false",
    "branding.facet_uri": "http://localhost:5173",
    "branding.title": "Agience",
    "auth.password.enabled": "true",
    "auth.password.min_length": "12",
    # Kept in step with `config.PASSWORD_PBKDF2_ITERS`, which is the value the hashing path
    # actually reads (see the note there — nothing in Origin applies this row to config).
    "auth.password.pbkdf2_iters": "600000",
    "auth.invite_only": "false",
    "platform.log_level": "info",
    "email.provider": "",
    "email.from_address": "",
    "email.from_name": "Agience",
}


# Server-side secret classification.
#
# `is_secret` is not accepted from the request body of PATCH /system/settings. If it were, a
# caller could store an SMTP password with is_secret=false — written to the plaintext `value`
# column, landing in `_values`, readable back through GET /settings (which masks only what is
# flagged secret) — or rewrite an already-encrypted key's ciphertext as plaintext with no error
# and no signal, by resubmitting it with is_secret=false.
#
# The classification is the server's decision, derived from the key, and applies whether the write
# comes from the setup wizard, a PATCH, or internal code.
_SECRET_KEY_SUBSTRINGS = (
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
    "private_key",
    "credential",
)

# Keys that match a substring above but are not secrets — flags and identifiers
# that merely mention the word. Explicit so the classifier stays predictable.
_NON_SECRET_KEYS = frozenset(
    {
        "auth.password.enabled",
        "auth.password.min_length",
        "auth.password.pbkdf2_iters",
        "platform.setup_complete",
    }
)


def is_secret_key(key: str) -> bool:
    """Whether this setting must be stored encrypted. Server-side, not caller-supplied."""
    if key in _NON_SECRET_KEYS:
        return False
    lowered = key.lower()
    return any(token in lowered for token in _SECRET_KEY_SUBSTRINGS)


class _SettingsCache:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._secrets: dict[str, str] = {}

    def load_all(self, db: Session) -> None:
        self._values.clear()
        self._secrets.clear()
        for row in db_settings.list_all(db):
            self._absorb(row)
        logger.info(
            "Origin: loaded %d platform setting(s) (%d secret)",
            len(self._values) + len(self._secrets),
            len(self._secrets),
        )

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if key in self._values:
            return self._values[key]
        return DEFAULTS.get(key, default)

    def get_secret(self, key: str) -> Optional[str]:
        return self._secrets.get(key)

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.get(key)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.get(key)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def needs_setup(self) -> bool:
        return self.get("platform.setup_complete", "false") != "true"

    def set_value(
        self,
        db: Session,
        key: str,
        raw: Optional[str],
        *,
        is_secret: Optional[bool] = None,
        category: Optional[str] = None,
        updated_by: Optional[str] = None,
        commit: bool = True,
    ) -> None:
        """Write one setting.

        `is_secret=None` (the default) classifies server-side via
        :func:`is_secret_key`. An explicit value is honoured only when it
        *raises* the classification to secret — a caller may never talk the
        server out of encrypting something it considers sensitive.

        `commit=False` defers the commit so a batch can be one transaction.
        """
        classified = is_secret_key(key)
        is_secret = classified or bool(is_secret)

        if is_secret:
            ciphertext = _fernet().encrypt((raw or "").encode("utf-8")).decode("ascii")
            db_settings.set_value(
                db,
                key,
                value=None,
                secret_value=ciphertext,
                is_secret=True,
                category=category,
                updated_by=updated_by,
            )
        else:
            db_settings.set_value(
                db,
                key,
                value=raw,
                secret_value=None,
                is_secret=False,
                category=category,
                updated_by=updated_by,
            )

        if commit:
            db.commit()
            self._apply_to_cache(key, raw, is_secret)

    def _apply_to_cache(self, key: str, raw: Optional[str], is_secret: bool) -> None:
        """Mirror a committed write into the in-memory cache.

        Deliberately called only after the transaction commits: mutating the
        cache first leaves it advertising values that were rolled back, and the
        cache is what every reader consults.
        """
        if is_secret:
            self._secrets[key] = raw or ""
            self._values.pop(key, None)
        else:
            self._values[key] = raw or ""
            self._secrets.pop(key, None)

    def set_many(
        self,
        db: Session,
        items: Iterable[dict],
        *,
        updated_by: Optional[str] = None,
    ) -> int:
        """Write a batch as one transaction.

        Committing per item would leave a failure partway through with the batch half-applied —
        half-rotated credentials — and, during setup, would also commit an unrelated pending
        Person insert as a side effect of the first item's commit.
        """
        staged: list[tuple[str, Optional[str], bool]] = []
        for item in items:
            key = item["key"]
            raw = item.get("value")
            is_secret = is_secret_key(key) or bool(item.get("is_secret", False))
            self.set_value(
                db,
                key,
                raw,
                is_secret=is_secret,
                category=item.get("category"),
                updated_by=updated_by,
                commit=False,
            )
            staged.append((key, raw, is_secret))

        db.commit()
        for key, raw, is_secret in staged:
            self._apply_to_cache(key, raw, is_secret)
        return len(staged)

    def _absorb(self, row: PlatformSetting) -> None:
        if row.is_secret and row.secret_value:
            try:
                self._secrets[row.key] = _fernet().decrypt(row.secret_value.encode("ascii")).decode("utf-8")
            except Exception:
                logger.warning("Failed to decrypt secret %s — ignoring stored value", row.key)
        elif not row.is_secret and row.value is not None:
            self._values[row.key] = row.value


def _fernet() -> Fernet:
    return Fernet(get_encryption_key().encode())


# Singleton — imported as `from origin.services.platform_settings_service import settings`
settings = _SettingsCache()
