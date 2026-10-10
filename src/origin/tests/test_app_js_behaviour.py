"""Runs the JavaScript behaviour suites under `node --test`: `js/app_js.test.cjs` (`web/app.js`)
and `js/page_scripts.test.cjs` (the inline scripts of `web/index.html` and `web/verify-email.html`).

The session helpers the sign-in, verify and account pages share (the verification stash, the
nonce, `SP_ALLOW`, the silent-SSO loop guard) are JavaScript, and a string match on the source
cannot tell a guard that works from one that is merely present. Node runs them against stubbed
browser storage instead. Skipped, with the reason printed under `-rs`, where no `node` is on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_SUITES = [Path(__file__).resolve().parent / "js" / n
           for n in ("app_js.test.cjs", "page_scripts.test.cjs")]


@pytest.mark.parametrize("suite", _SUITES, ids=[s.name for s in _SUITES])
def test_web_script_behaviour_under_node(suite: Path):
    node = shutil.which("node")
    if node is None:
        pytest.skip(f"node is not on PATH; {suite.name} (web script behaviour) did not run")
    proc = subprocess.run(
        # TAP named explicitly: the assertions below read TAP's `# pass N` / `# fail N`, and node's
        # default reporter is TAP on a pipe in some versions and `spec` (`ℹ fail 0`) in others.
        [node, "--test", "--test-reporter=tap", str(suite)], capture_output=True, text=True, timeout=120,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    # `node --test` on a file whose tests never registered also exits 0; require real passes.
    assert "# pass 0" not in out and "# fail 0" in out, out
