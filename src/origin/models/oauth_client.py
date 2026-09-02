"""OAuthClient — a public OAuth 2.0 client enrolled through RFC 7591 dynamic registration.

Deliberately not `server_credentials`. That table is Chorus-shaped and secret-shaped: `secret_hash`,
`authority`, `host_id` and `server_id` are all `NOT NULL`, and a public PKCE client has none of
them. Registering an MCP client through it would mean minting a secret nothing verifies and a host
id naming no host — two fabrications stored as facts. The two tables answer different questions and
are read by different grants: `server_credentials` by `client_credentials`, this one by whatever
comes to consult the registry.

A row here is a permission, in two separable ways. `/authorize` refuses a `client_id` that is
neither configured first-party nor present here, so the row's existence is what admits a client no
operator named. And it holds a client present here to this row's `redirect_uris` — the
authority-wide `is_client_redirect_allowed` applies on top, but it is client-blind and cannot say
that client X's code belongs at X's callback rather than at Y's. Deleting a row revokes a client;
editing `redirect_uris` moves where its codes may land.

What a row does not confer is trust: `_is_first_party_client` does not read this table, so a client
that enrolled itself is admitted to the flow and receives the scoped `mcp_client` token.

No secret column, and that is a design decision rather than an omission: every client registered
here is public (`token_endpoint_auth_method: none`) and proves itself with PKCE. A column holding a
secret this authority never checks — the token endpoint's code path for `authorization_code`
authenticates no client — would read as protection that is not there.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    # `client_id` is the primary key rather than a surrogate uuid with a unique index beside it.
    # This authority mints the value itself from `secrets`-grade entropy, so it is already globally
    # unique and already the only handle anything uses — a second identifier would name the same row
    # twice and appear in no protocol message. 64 characters leaves room above the minted length.
    client_id = Column(String(64), primary_key=True)
    # RFC 7591 §2 `client_name`. Optional there and nullable here: a client that sends none is
    # registered without one rather than given a fabricated label. It is the only human-readable
    # field an operator has when reading a table that (in open mode) anonymous callers can write to.
    client_name = Column(String(256), nullable=True)
    # RFC 7591 §2 `redirect_uris`. The security-relevant field: it is the only registered metadata
    # that says where a code may be delivered. Every entry was admitted by
    # `auth_service.is_client_redirect_allowed` at registration time.
    redirect_uris = Column(JSON, nullable=False, default=list)
    # RFC 7591 §2 `grant_types` / `response_types`. Stored because they are what a later enforcement
    # step would compare a request against; today they record what the client said it would use.
    grant_types = Column(JSON, nullable=False, default=list)
    response_types = Column(JSON, nullable=False, default=list)
    # RFC 7591 §2 `token_endpoint_auth_method`. Always `none` — see the module docstring on why
    # there is no secret. Stored rather than assumed, so admitting a confidential client is a
    # visible change in the data rather than an unstated invariant in the handler.
    token_endpoint_auth_method = Column(String(64), nullable=False)
    # RFC 7591 §3.2.1 `client_id_issued_at`, which the registration response must be able to state.
    # Serves as this table's `created_time`; a second column carrying the same instant under a
    # different name would be two records of one fact.
    client_id_issued_at = Column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
