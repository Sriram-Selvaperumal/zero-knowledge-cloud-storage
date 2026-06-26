from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import SessionLocal
from app.models.base import utc_now
from app.models.user import User
from app.models.user_session import UserSession
from app.utils.security import decode_access_token


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_prefix}/auth/login"
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_session(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> UserSession:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        auth_version = payload.get("ver")

        if (
            user_id is None
            or session_id is None
            or auth_version is None
        ):
            raise credentials_exception

        user_id = int(user_id)
        auth_version = int(auth_version)
    except (JWTError, TypeError, ValueError):
        raise credentials_exception

    user_session = (
        db.query(UserSession)
        .filter(
            UserSession.id == session_id,
            UserSession.user_id == user_id
        )
        .first()
    )

    if (
        user_session is None
        or user_session.revoked_at is not None
        or user_session.expires_at <= utc_now()
        or user_session.user.auth_version != auth_version
    ):
        raise credentials_exception

    return user_session


def get_current_user(
    user_session: UserSession = Depends(get_current_session)
) -> User:
    return user_session.user
