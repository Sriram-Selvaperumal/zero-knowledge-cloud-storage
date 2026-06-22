import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import settings
from app.models.base import utc_now
from app.models.user import User
from app.models.user_session import UserSession
from app.utils.security import create_access_token


class InvalidRefreshTokenError(Exception):
    pass


@dataclass(frozen=True)
class SessionTokens:
    access_token: str
    refresh_token: str


def _get_refresh_token_secret() -> bytes:
    if not settings.refresh_token_secret_key:
        raise RuntimeError(
            "REFRESH_TOKEN_SECRET_KEY is not set. Add it to your .env file."
        )

    return settings.refresh_token_secret_key.encode("utf-8")


def _hash_refresh_token(session_id: str, token_secret: str) -> str:
    payload = f"{session_id}:{token_secret}".encode("utf-8")
    return hmac.new(
        _get_refresh_token_secret(),
        payload,
        hashlib.sha256
    ).hexdigest()


def _new_refresh_token(session_id: str) -> tuple[str, str]:
    token_secret = secrets.token_urlsafe(48)
    cookie_value = f"{session_id}.{token_secret}"
    return cookie_value, _hash_refresh_token(session_id, token_secret)


def _parse_refresh_token(cookie_value: str) -> tuple[str, str]:
    try:
        session_id, token_secret = cookie_value.split(".", 1)
    except ValueError as exc:
        raise InvalidRefreshTokenError("Invalid refresh token") from exc

    if len(session_id) != 36 or len(token_secret) < 32:
        raise InvalidRefreshTokenError("Invalid refresh token")

    return session_id, token_secret


def create_user_session(db: Session, user: User) -> SessionTokens:
    session_id = str(uuid4())
    refresh_token, refresh_token_hash = _new_refresh_token(session_id)
    user_session = UserSession(
        id=session_id,
        user_id=user.id,
        refresh_token_hash=refresh_token_hash,
        expires_at=utc_now() + timedelta(
            days=settings.refresh_token_expire_days
        )
    )
    db.add(user_session)
    db.commit()

    return SessionTokens(
        access_token=create_access_token(
            subject=user.id,
            session_id=session_id,
            auth_version=user.auth_version
        ),
        refresh_token=refresh_token
    )


def rotate_refresh_token(
    db: Session,
    cookie_value: str
) -> tuple[User, SessionTokens]:
    session_id, token_secret = _parse_refresh_token(cookie_value)
    user_session = (
        db.query(UserSession)
        .filter(UserSession.id == session_id)
        .with_for_update()
        .first()
    )
    now = utc_now()

    if (
        user_session is None
        or user_session.revoked_at is not None
        or user_session.expires_at <= now
    ):
        raise InvalidRefreshTokenError("Refresh session is no longer valid")

    expected_hash = _hash_refresh_token(session_id, token_secret)

    if not hmac.compare_digest(
        user_session.refresh_token_hash,
        expected_hash
    ):
        user_session.revoked_at = now
        db.commit()
        raise InvalidRefreshTokenError("Invalid refresh token")

    user = user_session.user
    refresh_token, refresh_token_hash = _new_refresh_token(session_id)
    user_session.refresh_token_hash = refresh_token_hash
    user_session.last_used_at = now
    db.commit()

    return user, SessionTokens(
        access_token=create_access_token(
            subject=user.id,
            session_id=session_id,
            auth_version=user.auth_version
        ),
        refresh_token=refresh_token
    )


def rotate_current_session_after_password_change(
    db: Session,
    user: User,
    current_session: UserSession
) -> SessionTokens:
    now = utc_now()
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.id != current_session.id,
        UserSession.revoked_at.is_(None)
    ).update({UserSession.revoked_at: now}, synchronize_session=False)

    refresh_token, refresh_token_hash = _new_refresh_token(current_session.id)
    current_session.refresh_token_hash = refresh_token_hash
    current_session.last_used_at = now
    db.commit()

    return SessionTokens(
        access_token=create_access_token(
            subject=user.id,
            session_id=current_session.id,
            auth_version=user.auth_version
        ),
        refresh_token=refresh_token
    )


def revoke_session(db: Session, user_session: UserSession) -> None:
    if user_session.revoked_at is None:
        user_session.revoked_at = utc_now()
        db.commit()


def revoke_all_user_sessions(db: Session, user: User) -> None:
    user.auth_version += 1
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked_at.is_(None)
    ).update(
        {UserSession.revoked_at: utc_now()},
        synchronize_session=False
    )
    db.commit()
