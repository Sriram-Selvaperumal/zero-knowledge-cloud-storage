from sqlalchemy import Column, DateTime, Integer, String

from app.models.base import Base, utc_now


class AuthenticationThrottle(Base):
    __tablename__ = "authentication_throttles"

    key_hash = Column(String(64), primary_key=True)
    failures = Column(Integer, nullable=False, default=0)
    window_started_at = Column(DateTime(), nullable=False, default=utc_now)
    blocked_until = Column(DateTime(), nullable=True, index=True)
    updated_at = Column(
        DateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now
    )
