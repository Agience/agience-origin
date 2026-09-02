"""`origin.service_identity` re-exports `prism.trust.service_identity`: one implementation, two names.

prism owns the implementation. `prism/trust/__init__.py` describes it as the shared
platform-service identity, JWT signing/verification, and key-management floor that every Agience
app component — and any third-party Host or MCP server — stands on. prism has no dependency on
origin, so this re-export creates no import cycle; the floor reads `KEYS_DIR` from the environment
and depends on no application config; and prism is Apache-2.0 while origin is AGPL, so the license
direction (permissive into copyleft) is compatible.

The re-export rebinds the `sys.modules` entry rather than star-importing prism's names. A
star-import shim would bind copies of the names into this module, so a test fixture writing to a
module global through the `origin.` name — `service_identity._loaded`, `authority_trust._manifest`
— would land here while the functions that read it, defined in prism's module, kept reading prism's
own globals; the fixture would silently stop taking effect rather than raise an error.
Rebinding `sys.modules[__name__]` instead makes `origin.service_identity` and
`prism.trust.service_identity` the same module object, so there is exactly one set of globals and
a write through either name is seen through both. `from origin.service_identity import x` resolves
normally, and `monkeypatch.setitem(sys.modules, "origin.service_identity", …)` (used by two ember
tests) still substitutes as expected.
"""
import sys

from prism.trust import service_identity as _real

sys.modules[__name__] = _real
