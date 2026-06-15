from datetime import datetime
from typing import Any

from pydantic import BaseModel


class FileMetadataResponse(BaseModel):
    id: int
    encrypted_filename: str
    content_type: str | None = None
    size_bytes: int
    encryption_metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
