from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.models.base import Base, utc_now


class PasswordRecoveryVerification(Base):
    __tablename__ = "password_recovery_verifications"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4())
    )
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    identifier_hash = Column(String(64), unique=True, nullable=False)
    otp_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(), nullable=False, index=True)
    attempts_remaining = Column(Integer, nullable=False)
    verified_at = Column(DateTime(), nullable=True)
    grant_expires_at = Column(DateTime(), nullable=True)
    created_at = Column(DateTime(), default=utc_now, nullable=False)

    user = relationship("User", back_populates="password_recoveries")
