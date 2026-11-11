"""Whether this node may hold custody: only isolated production (John, 2026-11-02).

Threshold custody is a claim that no single process on the box can open a person's key alone.
The claim holds only where the services are hard-isolated from each other (each its own user,
hardened units, its own 0700 keys folder). The home and development planes run every service as
one user with one keys folder, so the claim would be false there, and custody is refused. The
home node, while it is the test gate, holds test custody instead (`home_test_refusal`): its own
keys, an issuer production never trusts, and none once it peers.

The signal is two things, both needed, because either alone can be wrong:

* the plane the release tool rendered into this service's env, `AGIENCE_PLANE=production`. It
  says what the node is meant to be, and it is the one thing that separates a production box from
  a home box running the same code with the same hardening. A setting alone can be copied, though;
* evidence, read from the running process, that the isolation that setting implies is in force:
  not running as root, the kernel's no-new-privileges flag set (`NoNewPrivs: 1` in
  `/proc/self/status`, which the hardened unit's `NoNewPrivileges=yes` sets and nothing else does
  by default), and `KEYS_DIR` owned by this process's own user with no access for anyone else
  (mode 0700). A shared keys folder, a root service or an unhardened unit each fails it.

A platform that cannot show the evidence (no `/proc`, no POSIX ids) is refused: absence of
evidence is not isolation. `TEST_OVERRIDE` lets the test suite stand in for a production box; it is
a module attribute only code can set, never a setting.

Mantle checks the same signal with the same shape (`custody_refusal(evidence=None) -> Optional[str]`).
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

#: Set by the test suite only: True accepts, False refuses, None decides from the node.
TEST_OVERRIDE: Optional[bool] = None


def evidence() -> dict:
    """What the running process shows of its isolation. Missing evidence is None."""
    out = {"euid": None, "no_new_privs": None, "keys_uid": None, "keys_mode": None,
           "db_uid": None, "db_mode": None}
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        out["euid"] = geteuid()
    status = Path("/proc/self/status")
    try:
        for line in status.read_text().splitlines():
            if line.startswith("NoNewPrivs:"):
                out["no_new_privs"] = line.split(":", 1)[1].strip() == "1"
    except OSError:
        pass
    keys = os.getenv("KEYS_DIR")
    if keys:
        try:
            st = os.stat(keys, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                out["keys_uid"], out["keys_mode"] = st.st_uid, stat.S_IMODE(st.st_mode)
        except OSError:
            pass
    db = (os.getenv("ORIGIN_DB_PATH") or "").strip()
    if db:
        try:
            st = os.stat(str(Path(db).parent), follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                out["db_uid"], out["db_mode"] = st.st_uid, stat.S_IMODE(st.st_mode)
        except OSError:
            pass
    return out


#: The home node's own domain. Test custody is held only by a node whose issuer is under it, so
#: nothing it signs or keys can be taken for production's.
HOME_DOMAIN = "home.agience.ai"


def home_test_refusal() -> Optional[str]:
    """Why the home node may not hold test custody, or None when it may (John, 2026-11-11).

    While the home node is the test gate, it holds test custody over its own keys, so a run, a
    timer and their approvals can be accepted there before promote. Test custody claims no
    separation: one user runs every service there. What keeps it apart from production is that its
    issuer is a `*.home.agience.ai` host, which production never trusts, and that it has no peers.
    It is given up when peering starts (`EMBER_PEERS`). Mantle decides by the same rule."""
    from urllib.parse import urlsplit

    from origin import config

    # Every source of the issuer must name a home host, the one Origin signs with above all
    # (`config.AUTHORITY_ISSUER`, settled at startup from `ORIGIN_URI` or the stored facet URI):
    # a node that passed on `AUTHORITY_ISSUER` alone could still sign as production (review,
    # 2026-11-11).
    sources = [os.getenv("AUTHORITY_ISSUER"), os.getenv("ORIGIN_URI"),
               getattr(config, "AUTHORITY_ISSUER", None)]
    hosts = [(urlsplit(s.strip()).hostname or "").lower() for s in sources if s and s.strip()]
    if not hosts or not all(h == HOME_DOMAIN or h.endswith("." + HOME_DOMAIN) for h in hosts):
        return (f"test custody is held only by a home node, whose every issuer is under "
                f"{HOME_DOMAIN}; this one's are {sorted(set(hosts)) or 'unset'}")
    if (os.getenv("EMBER_PEERS") or "").strip():
        return "test custody is given up once the home node peers (EMBER_PEERS is set)"
    if not (os.getenv("KEYS_DIR") or "").strip():
        return "test custody needs this node's own keys folder (KEYS_DIR)"
    return None


def custody_refusal(evidence: Optional[dict] = None) -> Optional[str]:
    """Why this node may not hold custody, or None when it may."""
    if TEST_OVERRIDE is True:
        return None
    if TEST_OVERRIDE is False:
        return "custody is refused here (test override)"
    plane = (os.getenv("AGIENCE_PLANE") or "").strip().lower()
    if plane == "home":
        return home_test_refusal()
    if plane != "production":
        return (f"custody is held only on isolated production; AGIENCE_PLANE is "
                f"{plane or 'unset'!r}")
    ev = globals()["evidence"]() if evidence is None else evidence
    if ev.get("euid") is None:
        return "custody needs evidence of isolation, and this platform shows no process user"
    if ev["euid"] == 0:
        return "custody is never held by a process running as root"
    if not ev.get("no_new_privs"):
        return "custody needs the hardened unit (NoNewPrivileges) in force"
    if ev.get("keys_uid") != ev["euid"] or ev.get("keys_mode") is None \
            or ev["keys_mode"] & 0o077:
        return "custody needs KEYS_DIR owned by this service alone, mode 0700"
    if ev.get("db_uid") != ev["euid"] or ev.get("db_mode") is None or ev["db_mode"] & 0o077:
        return ("custody needs the folder holding ORIGIN_DB_PATH owned by this service alone, "
                "mode 0700")
    return None
