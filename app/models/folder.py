from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.models.base import Base, utc_now


class FolderMetadata(Base):
    __tablename__ = "folder_metadata"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    parent_id = Column(
        Integer,
        ForeignKey("folder_metadata.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    encrypted_name = Column(String(1024), nullable=False)
    encryption_metadata = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(
        DateTime,
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )

    owner = relationship("User", back_populates="folders")
    parent = relationship(
        "FolderMetadata",
        remote_side=[id],
        back_populates="children"
    )
    children = relationship(
        "FolderMetadata",
        back_populates="parent",
        cascade="all, delete-orphan",
        single_parent=True
    )
    files = relationship("FileMetadata", back_populates="folder")
