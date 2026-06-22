from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.crypto import KdfParameters, ensure_base64


class ShareCreateRequest(BaseModel):
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: Literal[1]
    kdf_algorithm: Literal["argon2id"]
    kdf_salt: str = Field(min_length=16, max_length=128)
    kdf_parameters: KdfParameters
    wrap_algorithm: Literal["xchacha20-poly1305-ietf"]
    wrapped_file_key: str = Field(min_length=32, max_length=512)
    wrap_nonce: str = Field(min_length=16, max_length=128)
    password_verifier: str = Field(min_length=32, max_length=128)
    expires_at: datetime | None = None

    @field_validator(
        "kdf_salt",
        "wrapped_file_key",
        "wrap_nonce",
        "password_verifier"
    )
    @classmethod
    def validate_base64_fields(cls, value: str) -> str:
        return ensure_base64(value)


class FileShareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    file_id: int
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ShareAccessInfo(BaseModel):
    id: str
    version: Literal[1]
    kdf_algorithm: Literal["argon2id"]
    kdf_salt: str
    kdf_parameters: KdfParameters
    expires_at: datetime | None


class ShareUnlockRequest(BaseModel):
    password_verifier: str = Field(min_length=32, max_length=128)

    @field_validator("password_verifier")
    @classmethod
    def validate_verifier(cls, value: str) -> str:
        return ensure_base64(value)


class SharedFileEncryptionMetadata(BaseModel):
    version: Literal[1]
    cipher: Literal["xchacha20-poly1305-secretstream"]
    file_id: str
    chunk_size: int
    plaintext_size: int
    stream_header: str
    manifest_nonce: str


class ShareKeyEnvelope(BaseModel):
    version: Literal[1]
    wrap_algorithm: Literal["xchacha20-poly1305-ietf"]
    wrapped_file_key: str
    wrap_nonce: str


class ShareUnlockResponse(BaseModel):
    share_id: str
    encrypted_filename: str
    size_bytes: int
    encryption_metadata: SharedFileEncryptionMetadata
    share_envelope: ShareKeyEnvelope
    download_token: str
    download_expires_in_seconds: int
    expires_at: datetime | None
