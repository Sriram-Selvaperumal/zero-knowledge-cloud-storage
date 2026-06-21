from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import relationship

from app.models.base import Base, utc_now
from app.models.crypto_profile import UserCryptoProfile
from app.models.file import FileMetadata


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(50), unique=True, nullable=False)

    email = Column(String(255), unique=True, nullable=False)

    password_hash = Column(String(255), nullable=False)

    created_at = Column(DateTime, default=utc_now)

    files = relationship(
        FileMetadata,
        back_populates="owner",
        cascade="all, delete-orphan"
    )
    crypto_profile = relationship(
        UserCryptoProfile,
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False
    )
