import base64
import binascii
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def ensure_base64(value: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Value must be valid standard base64") from exc

    return value


class KdfParameters(BaseModel):
    opslimit: int = Field(ge=1, le=20)
    memlimit: int = Field(ge=8 * 1024 * 1024, le=512 * 1024 * 1024)


class CryptoProfileBase(BaseModel):
    version: Literal[1]
    kdf_algorithm: Literal["argon2id"]
    kdf_salt: str = Field(min_length=16, max_length=128)
    kdf_parameters: KdfParameters
    wrap_algorithm: Literal["xchacha20-poly1305-ietf"]
    wrapped_vault_key: str = Field(min_length=32, max_length=512)
    wrap_nonce: str = Field(min_length=16, max_length=128)

    @field_validator("kdf_salt", "wrapped_vault_key", "wrap_nonce")
    @classmethod
    def validate_base64_fields(cls, value: str) -> str:
        return ensure_base64(value)


class CryptoProfileCreate(CryptoProfileBase):
    pass


class CryptoProfileRewrap(CryptoProfileBase):
    pass


class CryptoProfileResponse(CryptoProfileBase):
    model_config = ConfigDict(from_attributes=True)
