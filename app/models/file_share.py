from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.models.base import Base, utc_now


class FileShare(Base):
    __tablename__ = "file_shares"

    id = Column(String(36), primary_key=True)
    file_id = Column(
        Integer,
        ForeignKey("file_metadata.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    version = Column(Integer, nullable=False)
    kdf_algorithm = Column(String(50), nullable=False)
    kdf_salt = Column(String(128), nullable=False)
    kdf_parameters = Column(JSON, nullable=False)
    wrap_algorithm = Column(String(100), nullable=False)
    wrapped_file_key = Column(String(512), nullable=False)
    wrap_nonce = Column(String(128), nullable=False)
    password_verifier = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=True, index=True)
    revoked_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(
        DateTime,
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )

    file = relationship("FileMetadata", back_populates="shares")
