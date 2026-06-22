from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.crypto import (
    CryptoProfileRewrap,
    RecoveryProfileBase
)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    crypto_profile: CryptoProfileRewrap


class PasswordRecoveryRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)


class PasswordRecoveryVerify(BaseModel):
    verification_id: UUID
    otp: str = Field(pattern=r"^\d{6}$")


class PasswordRecoveryGrantResponse(BaseModel):
    recovery_token: str
    user_id: int
    recovery_profile: RecoveryProfileBase


class PasswordRecoveryComplete(BaseModel):
    recovery_token: str = Field(min_length=32)
    new_password: str = Field(min_length=8, max_length=128)
    crypto_profile: CryptoProfileRewrap


class RecoveryKeyRotateRequest(BaseModel):
    recovery_profile: RecoveryProfileBase
