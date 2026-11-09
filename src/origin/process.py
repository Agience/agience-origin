"""What an Origin process builds before it does anything: its configuration, keys, identity and
database engine.

Origin's startup (`main.lifespan`) calls `init_process()`, and so does a script that runs as a
process of its own on Origin's host and signs (`origin.scripts.authority_bootstrap`), so it starts
with exactly what the server starts with. What only a serving process does — migrations, the manifest, account
notifications, the identity providers — stays in the startup.
"""
from __future__ import annotations

from pathlib import Path


def init_process() -> None:
    """Load the service's `.env` (the environment already set wins), then the signing keys, the
    encryption key, the nonce and setup secrets, Origin's service identity, and the engine. Each
    step is idempotent."""
    from origin import config, service_identity
    from origin.db.session import init_engine
    from origin.key_manager import init_encryption_key, init_jwt_keys, init_nonce_secret, init_setup_token
    from origin.services import signing_keys

    config.load_env(Path(__file__).resolve().parent.parent)
    # kid="origin-1" matches the kid published in the authority manifest (key init writes
    # origin's JWKS with that kid) and the service identity's kid, until a rollover names another.
    init_jwt_keys(key_id=signing_keys.current_kid())
    init_encryption_key()
    init_nonce_secret()
    init_setup_token()
    # The same key signs service-to-service JWTs and user tokens (the OIDC issuer signing key).
    service_identity.init_service_identity("origin")
    init_engine()
