from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user import UserRegister
from app.utils.security import create_access_token, hash_password, verify_password


def get_user_by_username(db: Session, username: str) -> User | None:
    return (
        db.query(User)
        .filter(User.username == username)
        .first()
    )


def get_user_by_email(db: Session, email: str) -> User | None:
    return (
        db.query(User)
        .filter(User.email == email)
        .first()
    )


def get_user_by_username_or_email(db: Session, identifier: str) -> User | None:
    return (
        db.query(User)
        .filter(
            or_(
                User.username == identifier,
                User.email == identifier
            )
        )
        .first()
    )


def create_user(db: Session, user: UserRegister) -> User:
    new_user = User(
        username=user.username,
        email=str(user.email),
        password_hash=hash_password(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def authenticate_user(
    db: Session,
    username_or_email: str,
    password: str
) -> User | None:
    user = get_user_by_username_or_email(db, username_or_email)

    if user is None:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user


def create_user_access_token(user: User) -> str:
    return create_access_token(subject=user.id)
