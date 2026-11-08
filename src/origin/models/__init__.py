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
from origin.models.password_reset import PasswordReset
from origin.models.person_step_up import PersonStepUp
from origin.models.refresh_token import RefreshToken
from origin.models.origin_session import OriginSession
from origin.models.sign_in_bounds import LinkAttempt, PersonNotBefore
from origin.models.service_account import ServiceAccount
from origin.models.narrow_hop import NarrowHop
from origin.models.billing_recipient import BillingRecipient, BillingRecipientLookup
from origin.models.credential_seal import CredentialSeal
from origin.models.key_custody import (
    DelegationRecord, SeedCredential, KeyCustodyBackground, KeyCustodyDelegation, KeyCustodyNonce,
    KeyCustodyRelease, KeyCustodyShare, UseNonce,
)
from origin.models.authority_ledger import (
    AuthorityBootstrapWindow, AuthorityEdge, AuthorityEntry, AuthorityGrant, AuthorityNode,
    AuthorityRoot, AuthoritySigningKey, OperatorAlert, AuthorityJobGrant,
)

__all__ = [
    "UseNonce",
    "CredentialSeal",
    "BillingRecipient",
    "BillingRecipientLookup",
    "NarrowHop",
    "Person",
    "PlatformSetting",
    "PasskeyCredential",
    "PersonIdentity",
    "PasskeyChallenge",
    "OtpCode",
    "ServerCredential",
    "OAuthClient",
    "PasswordReset",
    "PersonStepUp",
    "OriginSession",
    "PersonNotBefore",
    "LinkAttempt",
    "ServiceAccount",
    "RefreshToken",
    "KeyCustodyShare",
    "KeyCustodyNonce",
    "KeyCustodyDelegation",
    "KeyCustodyRelease",
    "KeyCustodyBackground",
    "AuthorityEntry",
    "AuthorityGrant",
    "AuthorityEdge",
    "AuthorityRoot",
    "AuthorityNode",
    "AuthorityBootstrapWindow",
    "AuthoritySigningKey",
    "OperatorAlert",
    "AuthorityJobGrant",
    "DelegationRecord",
    "SeedCredential",
]
