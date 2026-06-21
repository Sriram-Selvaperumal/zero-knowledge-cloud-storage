from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.models.base import Base, utc_now


class UserCryptoProfile(Base):
    __tablename__ = "user_crypto_profiles"

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True
    )
    version = Column(Integer, nullable=False)
    kdf_algorithm = Column(String(50), nullable=False)
    kdf_salt = Column(String(128), nullable=False)
    kdf_parameters = Column(JSON, nullable=False)
    wrap_algorithm = Column(String(100), nullable=False)
    wrapped_vault_key = Column(String(512), nullable=False)
    wrap_nonce = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(
        DateTime,
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )

    user = relationship("User", back_populates="crypto_profile")
