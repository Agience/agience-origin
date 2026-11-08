"""Every platform setting but a short list of harmless ones is changed only through the operator
console, with a passkey step-up (`PUT /oracle/settings/{key}`), never on the operator's ordinary
access token at `PATCH /system/settings`.

The operator's ordinary token reaches Mantle. Sign-in providers, the issuer's facet and return
URIs, the sign-in allow-lists, email verification, password rules and the mail provider (which
carries sign-in codes and resets) all decide who signs in as whom, so a token Mantle holds must
change none of them. The classification is a default: a key not on `HARMLESS_SETTINGS` is the
console's, so a setting added later is guarded before anyone thinks about it.

The keys Origin reads are taken from its source, not listed here, so a new one is classified by
the rule rather than missed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


@pytest.fixture(autouse=True)
def _settings_restored(monkeypatch):
    """The settings cache is process-wide: what a test here writes is undone after it, so a
    repointed facet or mail logo does not reach the next file."""
    from origin.services.platform_settings_service import settings as platform_settings

    monkeypatch.setattr(platform_settings, "_values", dict(platform_settings._values))
    monkeypatch.setattr(platform_settings, "_secrets", dict(platform_settings._secrets))

_SRC = Path(__file__).resolve().parents[1]
_READ = re.compile(r"""(?:settings\.get(?:_bool|_int|_list|_secret)?|get_secret|_pref)\(\s*"([a-z0-9_.]+)\"""")


def keys_origin_reads() -> set:
    found = set()
    for path in _SRC.rglob("*.py"):
        if "tests" in path.parts:
            continue
        found.update(_READ.findall(path.read_text(encoding="utf-8")))
    from origin import config
    found.update(config._SETTING_MAP)
    return found


def test_the_reader_finds_the_sign_in_keys():
    keys = keys_origin_reads()
    assert {"auth.oidc.metadata_url", "branding.sso_return_uris", "auth.allowed_domains",
            "branding.facet_uri", "email.smtp.host"} <= keys, sorted(keys)


def test_every_key_origin_reads_is_the_console_s_or_named_harmless():
    from origin.services.platform_settings_service import HARMLESS_SETTINGS, is_console_key

    unclassified = sorted(k for k in keys_origin_reads()
                          if k not in HARMLESS_SETTINGS and not is_console_key(k)
                          and not k.startswith("custody."))
    assert unclassified == []


def test_a_key_nobody_classified_is_the_console_s():
    from origin.services.platform_settings_service import is_console_key

    assert is_console_key("auth.someday.new_provider") and is_console_key("anything.else")
    assert not is_console_key("custody.share"), "custody keys are no setting at all"


SIGN_IN = [
    ("auth.oidc.metadata_url", "https://idp.attacker.test/.well-known/openid-configuration"),
    ("auth.oidc.client_id", "attacker"),
    ("auth.google.client_id", "attacker"),
    ("auth.microsoft.tenant", "attacker"),
    ("auth.auth0.domain", "attacker.test"),
    ("branding.sso_return_uris", "https://attacker.test/cb"),
    ("branding.facet_uri", "https://attacker.test"),
    ("branding.facet_uris", "https://attacker.test"),
    ("branding.app_uri", "https://attacker.test"),
    ("auth.allowed_domains", "nobody.test"),
    ("auth.allowed_emails", "mal@evil.test"),
    ("auth.allowed_google_ids", "1"),
    ("auth.shared_client_networks", "0.0.0.0/0"),
    ("auth.email_verification.enabled", "false"),
    ("auth.email_verification.allowlist", "evil.test"),
    ("auth.password.enabled", "true"),
    ("auth.password.min_length", "1"),
    ("email.provider", "smtp"),
    ("email.smtp.host", "smtp.attacker.test"),
    ("email.from_address", "noreply@attacker.test"),
]


@pytest.mark.parametrize("key,value", SIGN_IN)
def test_the_operator_s_ordinary_token_changes_no_sign_in_setting(custody_client, monkeypatch,
                                                                  key, value):
    from origin.services.platform_settings_service import settings as platform_settings

    op = af.operator(monkeypatch)
    before = platform_settings.get(key)
    r = custody_client.patch("/system/settings",
                             json={"settings": [{"key": key, "value": value}]},
                             headers={"Authorization": f"Bearer {op}"})
    assert r.status_code == 403, f"{key}: {r.status_code} {r.text}"
    assert platform_settings.get(key) == before


@pytest.mark.parametrize("key,value", SIGN_IN[:6])
def test_the_console_changes_a_sign_in_setting_with_a_step_up(custody_client, monkeypatch,
                                                              key, value):
    from origin.services.platform_settings_service import settings as platform_settings

    af.operator(monkeypatch)
    r = oc.call(custody_client, "PUT", f"/oracle/settings/{key}", json={"value": value})
    assert r.status_code == 200, r.text
    assert platform_settings.get(key) == value


def test_a_harmless_setting_stays_on_the_settings_route(custody_client, monkeypatch):
    from origin.services.platform_settings_service import HARMLESS_SETTINGS

    op = af.operator(monkeypatch)
    for key in sorted(HARMLESS_SETTINGS):
        r = custody_client.patch("/system/settings",
                                 json={"settings": [{"key": key, "value": "Agience"}]},
                                 headers={"Authorization": f"Bearer {op}"})
        assert r.status_code == 200, f"{key}: {r.text}"


def test_the_console_writes_no_custody_key(custody_client, monkeypatch):
    af.operator(monkeypatch)
    r = oc.call(custody_client, "PUT", "/oracle/settings/custody.share", json={"value": "x"})
    assert r.status_code == 400
