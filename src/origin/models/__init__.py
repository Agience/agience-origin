"""SQLAlchemy ORM models for Origin's tables.

Importing this module registers all models on the shared Base.metadata so
Alembic autogeneration sees them. Grants and API keys are not here: Origin holds
identity and platform settings only, and does no authorization.
"""

from origin.models.person import Person
from origin.models.platform_setting import PlatformSetting
from origin.models.passkey_credential import PasskeyCredential
from origin.models.person_identity import PersonIdentity
from origin.models.passkey_challenge import PasskeyChallenge
from origin.models.otp_code import OtpCode
from origin.models.server_credential import ServerCredential
from origin.models.oauth_client import OAuthClient

__all__ = [
    "Person",
    "PlatformSetting",
    "PasskeyCredential",
    "PersonIdentity",
    "PasskeyChallenge",
    "OtpCode",
    "ServerCredential",
    "OAuthClient",
]
