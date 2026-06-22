from datetime import datetime, timedelta, timezone
from uuid import uuid4

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
    session_id: str,
    auth_version: int,
    expires_delta: timedelta | None = None
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(
            minutes=settings.access_token_expire_minutes
        )
    )
    payload = {
        "sub": str(subject),
        "sid": session_id,
        "ver": auth_version,
        "typ": "access",
        "jti": str(uuid4()),
        "exp": expire
    }

    return jwt.encode(
        payload,
        _get_jwt_secret_key(),
        algorithm=settings.jwt_algorithm
    )


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        _get_jwt_secret_key(),
        algorithms=[settings.jwt_algorithm]
    )

    if payload.get("typ") != "access":
        raise ValueError("Invalid token type")

    return payload


def create_password_recovery_token(
    user_id: int,
    verification_id: str
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.password_recovery_grant_expire_minutes
    )
    payload = {
        "sub": str(user_id),
        "rid": verification_id,
        "typ": "password_recovery",
        "exp": expire
    }

    return jwt.encode(
        payload,
        _get_jwt_secret_key(),
        algorithm=settings.jwt_algorithm
    )


def decode_password_recovery_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        _get_jwt_secret_key(),
        algorithms=[settings.jwt_algorithm]
    )

    if payload.get("typ") != "password_recovery":
        raise ValueError("Invalid token type")

    return payload


def create_share_download_token(share_id: str, token_hash: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.share_download_grant_expire_minutes
    )
    payload = {
        "sid": share_id,
        "th": token_hash,
        "typ": "share_download",
        "jti": str(uuid4()),
        "exp": expire
    }

    return jwt.encode(
        payload,
        _get_jwt_secret_key(),
        algorithm=settings.jwt_algorithm
    )


def decode_share_download_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        _get_jwt_secret_key(),
        algorithms=[settings.jwt_algorithm]
    )

    if payload.get("typ") != "share_download":
        raise ValueError("Invalid token type")

    return payload
