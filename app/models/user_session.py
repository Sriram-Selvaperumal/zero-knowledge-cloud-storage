from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.models.base import Base, utc_now


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4())
    )
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    refresh_token_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(), nullable=False, index=True)
    revoked_at = Column(DateTime(), nullable=True, index=True)
    created_at = Column(DateTime(), default=utc_now, nullable=False)
    last_used_at = Column(DateTime(), default=utc_now, nullable=False)

    user = relationship("User", back_populates="sessions")
