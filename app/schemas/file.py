from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class FileMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    encrypted_filename: str
    content_type: str | None = None
    size_bytes: int
    encryption_metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime
