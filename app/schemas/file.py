from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.crypto import ensure_base64


class EncryptionMetadataV1(BaseModel):
    version: Literal[1]
    cipher: Literal["xchacha20-poly1305-secretstream"]
    file_id: str = Field(min_length=16, max_length=128)
    chunk_size: int = Field(ge=64 * 1024, le=16 * 1024 * 1024)
    plaintext_size: int = Field(ge=0, le=100 * 1024 * 1024)
    stream_header: str = Field(min_length=16, max_length=128)
    wrapped_file_key: str = Field(min_length=32, max_length=512)
    wrapped_file_key_nonce: str = Field(min_length=16, max_length=128)
    manifest_nonce: str = Field(min_length=16, max_length=128)

    @field_validator(
        "stream_header",
        "file_id",
        "wrapped_file_key",
        "wrapped_file_key_nonce",
        "manifest_nonce"
    )
    @classmethod
    def validate_base64_fields(cls, value: str) -> str:
        return ensure_base64(value)


class FileMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    encrypted_filename: str
    content_type: str | None = None
    size_bytes: int
    encryption_metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime
