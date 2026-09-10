"""`restart_required` must name every setting that only reaches `config` at boot.

⛔ WHY THIS FILE EXISTS. `_RESTART_REQUIRED_KEYS` was `set()` while the settings in it genuinely
required a restart, so `PATCH /system/settings` answered `restart_required: false` to an operator
who had just configured Google sign-in and would see no Google button and no error. The first
attempt to fix it was a hand-written list, and it was already wrong when written — it omitted all
four `auth.auth0.*` keys.

So this test does not restate the list. It PARSES `main._apply_db_settings_to_config` and asserts
the two agree, because a list that has to be maintained by hand alongside a function is a list that
stops matching the function.

The rule the test encodes: a setting read inside `_apply_db_settings_to_config` reaches `config.*`
only when that function runs, and that function is called from one place — the lifespan. So every
key it reads requires a restart, and no key it does not read belongs in the set.
"""

from __future__ import annotations

import ast
import pathlib

from origin.routers.system_router import _RESTART_REQUIRED_KEYS

MAIN = pathlib.Path(__file__).resolve().parents[1] / "main.py"

#: Calls inside that function whose first string argument is a settings key. `_pref` is the OAuth
#: path; the `platform_settings.get*` family is how the branding, allow-list and email-verification
#: settings are read. Any new reader would have to be added here — which is the point: the test
#: fails loudly rather than quietly under-reporting.
_READERS = {"_pref", "get", "get_bool", "get_secret"}


def _keys_read_at_boot() -> set[str]:
    """Every settings key `_apply_db_settings_to_config` reads, straight from the source."""
    # `utf-8-sig`, not `utf-8`: `main.py` carries a BOM, and `ast.parse` rejects U+FEFF outright.
    # Plain utf-8 raises here rather than returning an empty set, but only `test_reader_is_not_
    # vacuous` guarantees a silent parse failure can never read as agreement.
    tree = ast.parse(MAIN.read_text(encoding="utf-8-sig"))
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "_apply_db_settings_to_config"),
        None,
    )
    assert fn is not None, "_apply_db_settings_to_config is gone from main.py — this test is stale"

    keys: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = (
            node.func.id if isinstance(node.func, ast.Name)
            else node.func.attr if isinstance(node.func, ast.Attribute)
            else None
        )
        if name not in _READERS:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            keys.add(first.value)
    return keys


def test_reader_is_not_vacuous():
    """The parse must actually find keys.

    Without this, a rename of the function or of `_pref` makes `_keys_read_at_boot()` return the
    empty set, every assertion below passes trivially, and the suite reports green on exactly the
    defect it was written to catch.
    """
    found = _keys_read_at_boot()
    assert len(found) >= 20, f"parsed only {len(found)} keys — the reader is broken, not the code"
    assert "auth.google.client_id" in found


def test_every_boot_only_setting_reports_restart_required():
    missing = _keys_read_at_boot() - _RESTART_REQUIRED_KEYS
    assert not missing, (
        "these settings only reach config at boot but PATCH /system/settings reports "
        f"restart_required: false for them: {sorted(missing)}"
    )


def test_no_key_claims_a_restart_it_does_not_need():
    """The converse. Over-reporting trains an operator to ignore the flag."""
    spurious = _RESTART_REQUIRED_KEYS - _keys_read_at_boot()
    assert not spurious, (
        f"these are flagged restart_required but nothing reads them at boot: {sorted(spurious)}"
    )


def test_auth0_keys_are_covered():
    """The specific regression: a hand-written list omitted this provider entirely."""
    for key in ("auth.auth0.domain", "auth.auth0.client_id",
                "auth.auth0.client_secret", "auth.auth0.redirect_uri"):
        assert key in _RESTART_REQUIRED_KEYS, key
