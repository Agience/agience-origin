# origin/scopes.py

"""
API key scope vocabulary — a re-export of `prism.trust.scopes`, and nothing more.

`prism.trust.scopes` is the one definition; `origin/authority_trust.py`, `key_manager.py` and
`service_identity.py` are re-exports of the prism trust floor in the same way, carrying no
implementation of their own (`tests/test_trust_floor_has_one_implementation.py::
test_the_shim_stays_a_shim` asserts as much). This module needs no web framework: it has nothing
in it that raises an `HTTPException`.

Origin does not enforce API-key scopes on content types. Access is decided by the grants the
resource server resolves — a scope string on a key grants nothing by itself.

Scope Format: [type]:[contentType]:[action][:anonymous]
Special System Scopes:
- licensing:entitlement:<entitlement_name>

Components:
- Type: resource, tool, prompt (maps to MCP primitives)
- Content Type: Standard content type or wildcard (e.g., text/markdown, text/*, *)
- Action: read, write, search, invoke, delete, create
- Anonymous: Optional :anonymous suffix (default is identified access)

Examples:
- "resource:application/vnd.agience.collection+json:read"
- "resource:text/markdown:write:anonymous"
- "tool:application/vnd.agience.collection+json:search"
- "resource:text/*:read" (wildcard - all text types)
- "tool:*:invoke" (wildcard - all tools)

URI-based Storage:
- Scopes control content type access (what you can do)
- URIs control storage location (where it lives)
- Backend routes by URI scheme: agience://, file://, s3://, https://
"""

from __future__ import annotations

# The vocabulary has one definition, and it lives in prism. Re-exported here so
# `from origin.scopes import parse_scope` resolves without origin owning any of it.
from prism.trust.scopes import (  # noqa: F401
    CONTENT_TYPE_PATTERN,
    LICENSING_SCOPE_PATTERN,
    SPECIAL_SCOPES,
    VALID_ACTIONS,
    VALID_TYPES,
    content_type_matches,
    extract_licensing_entitlements,
    is_special_scope,
    parse_scope,
)

__all__ = [
    "CONTENT_TYPE_PATTERN",
    "LICENSING_SCOPE_PATTERN",
    "SPECIAL_SCOPES",
    "VALID_ACTIONS",
    "VALID_TYPES",
    "content_type_matches",
    "extract_licensing_entitlements",
    "is_special_scope",
    "parse_scope",
]
