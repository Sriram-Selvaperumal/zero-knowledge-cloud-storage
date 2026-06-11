from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from app.models.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(50), unique=True, nullable=False)

    email = Column(String(255), unique=True, nullable=False)

    password_hash = Column(String(255), nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    
from pydantic import BaseModel, EmailStr


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        from_attributes = True