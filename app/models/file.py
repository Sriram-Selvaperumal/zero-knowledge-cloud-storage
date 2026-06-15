from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.models.base import Base


class FileMetadata(Base):
    __tablename__ = "file_metadata"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    encrypted_filename = Column(String(1024), nullable=False)
    storage_key = Column(String(255), unique=True, nullable=False, index=True)
    content_type = Column(String(255), nullable=True)
    size_bytes = Column(BigInteger, nullable=False)
    encryption_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    owner = relationship("User", back_populates="files")
