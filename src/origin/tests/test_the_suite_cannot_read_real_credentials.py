"""No test may inherit a real credential from the machine it runs on.

`conftest._no_real_credentials_in_the_environment` clears the platform credential variables before
every test. That fixture is only as good as its list, and a list is exactly the thing that goes
stale: the next `os.getenv("SOMETHING_OAUTH_SECRET")` added to the code is read by the suite, and
nothing notices until it prints in a failure diff on the one machine that has it set.

⛔ WHAT THIS PREVENTS, MEASURED 2026-09-16. `GMAIL_OAUTH_CLIENT_SECRET` and
`GMAIL_OAUTH_REFRESH_TOKEN` were exported in the operator's shell. `AGIENCE_NO_DOTENV=1` was
correctly in force — and it only stops the `.env` FILE being read, so it did nothing here. Three
tests in `test_email_service.py` failed because `_gmail_config()` returned the real sender's
credentials instead of the values under test, and pytest printed the client secret and the full
refresh token into the assertion diff. They passed in CI, where no such variables exist. A red test
is recoverable; a red test carrying a live OAuth refresh token is a disclosure as soon as anyone
pastes the output anywhere.

⚠ THE NAMES ARE READ OUT OF THE SOURCE WITH AN AST, NOT MATCHED WITH A REGEX. `os.getenv` is
written several ways (`os.getenv(x)`, `os.getenv(x, "")`, `os.environ.get(x)`, `os.environ[x]`) and
an alternation of call forms always misses one — the miss being silent is the whole problem. Walking
the tree finds every call regardless of spelling or formatting.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

#: The modules that resolve platform configuration. A credential reaches the suite through one of
#: these or not at all.
_MODULES = ("services/email_service.py", "config.py")

#: A name is credential-bearing if it contains one of these. Deliberately broad: a false positive
#: costs one line in the fixture's list, a false negative costs a leaked secret.
_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "OAUTH", "CREDENTIAL", "API_KEY")

#: Names that match `_MARKERS` and are NOT credentials. Each needs a reason, because an exemption
#: list is how a real secret eventually gets waved through.
_NOT_A_CREDENTIAL = {
    # A directory path, not a secret. The `jwt_keypair` fixture SETS it to a tmp dir, so clearing it
    # in the fixture would break every JWT test — the opposite of the intent here.
    "KEYS_DIR",
    # An iteration count for PBKDF2. A number that tunes cost; it authenticates nothing.
    "PASSWORD_PBKDF2_ITERS",
    # A boolean policy switch ("is a subject token REQUIRED"), not a token. It contains the marker
    # word and carries no secret; clearing it would silently change the policy a test runs under.
    "PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED",
}


def _is_environ(node: ast.expr) -> bool:
    """True for `os.environ` or a bare `environ` (from `from os import environ`)."""
    if isinstance(node, ast.Attribute):
        return node.attr == "environ"
    return isinstance(node, ast.Name) and node.id == "environ"


def _string_arg(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _env_names_read_by(path: pathlib.Path) -> set[str]:
    """Every constant environment-variable name this module reads, however the read is spelled.

    ⛔ THE RECEIVER IS CHECKED, NOT JUST THE CALL SHAPE. Matching any `.get("x")` and any
    `something["x"]` looks like it finds more and actually finds the wrong things: the first run of
    this scan returned `client_secret`, `refresh_token`, `smtp_password` and five other lowercase
    names, which are `settings.get(...)` keys and dict subscripts — not environment variables at
    all. They then failed the guard as "uncleared credentials", which would have been fixed by
    adding eight non-variables to a list of variables to unset. A matcher that cannot say WHAT it
    matched on produces exactly that kind of confident wrong answer.
    """
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
            # os.getenv("NAME")
            if node.func.attr == "getenv" and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id == "os":
                if (n := _string_arg(node.args[0])) is not None:
                    names.add(n)
            # os.environ.get("NAME")
            elif node.func.attr == "get" and _is_environ(node.func.value):
                if (n := _string_arg(node.args[0])) is not None:
                    names.add(n)
        # os.environ["NAME"]
        elif isinstance(node, ast.Subscript) and _is_environ(node.value):
            if (n := _string_arg(node.slice)) is not None:
                names.add(n)

    return names


def _credential_names() -> set[str]:
    root = pathlib.Path(__file__).resolve().parents[1]
    found: set[str] = set()
    for rel in _MODULES:
        p = root / rel
        assert p.is_file(), (
            f"{p} does not exist — this guard would scan nothing and pass. Fix the path or drop "
            f"the entry deliberately, never leave one to be silently skipped.")
        found |= _env_names_read_by(p)

    assert found, "no environment reads found at all — the AST walk is broken, not the code"
    return {n for n in found if any(m in n.upper() for m in _MARKERS)} - _NOT_A_CREDENTIAL


def test_every_credential_variable_the_code_reads_is_cleared_for_tests():
    from origin.tests.conftest import _CREDENTIAL_ENV

    uncleared = _credential_names() - set(_CREDENTIAL_ENV)
    assert not uncleared, (
        "these credential variables are read by the code and NOT cleared before tests: %s\n\n"
        "A test running on a machine where one is exported reads the real value, and prints it on "
        "failure. Add each to `_CREDENTIAL_ENV` in conftest.py, or to `_NOT_A_CREDENTIAL` here "
        "with a reason it is not a secret." % ", ".join(sorted(uncleared)))


def test_the_scan_finds_the_names_it_is_supposed_to_find():
    """The guard above passes trivially if the scan returns nothing.

    A wrong path, a parse failure or a broken walk all produce an empty set, and an empty set is a
    subset of anything. These are names the code demonstrably reads today.
    """
    found = _credential_names()
    for expected in ("GMAIL_OAUTH_CLIENT_SECRET", "GMAIL_OAUTH_REFRESH_TOKEN"):
        assert expected in found, (
            f"{expected} is read by the code but the scan did not find it — the AST walk has "
            f"stopped seeing some call form, so this guard is now weaker than it reports.")


@pytest.mark.parametrize("name", [
    "GMAIL_OAUTH_CLIENT_SECRET",
    "GMAIL_OAUTH_REFRESH_TOKEN",
    "GOOGLE_OAUTH_CLIENT_SECRET",
])
def test_the_fixture_actually_removes_them(name, monkeypatch):
    """The fixture is autouse, so by the time this body runs the variable must already be gone.

    Asserting the EFFECT, not the list. `_CREDENTIAL_ENV` naming a variable proves nothing about
    whether the fixture ran, ran early enough, or used `delenv` correctly.
    """
    import os

    assert os.getenv(name) is None, (
        f"{name} is visible to this test. The autouse fixture in conftest.py did not clear it, so "
        f"any test reading platform config here is reading this machine's real credentials.")
