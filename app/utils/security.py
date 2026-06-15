from datetime import datetime, timedelta, timezone

from jose import jwt
from passlib.context import CryptContext

from app.config import settings


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    return pwd_context.verify(
        plain_password,
        hashed_password
    )


def _get_jwt_secret_key() -> str:
    if not settings.jwt_secret_key:
        raise RuntimeError("JWT_SECRET_KEY is not set. Add it to your .env file.")

    return settings.jwt_secret_key


def create_access_token(
    subject: int | str,
    expires_delta: timedelta | None = None
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(
            minutes=settings.access_token_expire_minutes
        )
    )
    payload = {
        "sub": str(subject),
        "exp": expire
    }

    return jwt.encode(
        payload,
        _get_jwt_secret_key(),
        algorithm=settings.jwt_algorithm
    )


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        _get_jwt_secret_key(),
        algorithms=[settings.jwt_algorithm]
    )
