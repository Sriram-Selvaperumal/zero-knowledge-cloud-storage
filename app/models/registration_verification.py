from uuid import uuid4

from sqlalchemy import Column, DateTime, Integer, String

from app.models.base import Base, utc_now


class RegistrationVerification(Base):
    __tablename__ = "registration_verifications"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4())
    )
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    otp_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(), nullable=False, index=True)
    attempts_remaining = Column(Integer, nullable=False)
    created_at = Column(DateTime(), default=utc_now, nullable=False)
