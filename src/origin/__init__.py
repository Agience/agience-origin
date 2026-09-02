"""Origin — identity, authority: OIDC, grants, passkeys, OTP, API keys, server credentials.

Origin runs as its own FastAPI process and owns its own database for identity-tier
state. It is the sole issuer of JWTs.
"""
