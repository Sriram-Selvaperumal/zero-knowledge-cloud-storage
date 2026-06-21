import hashlib
import hmac
import secrets
from datetime import timedelta
from math import ceil
from uuid import uuid4

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.base import utc_now
from app.models.registration_verification import RegistrationVerification
from app.models.user import User
from app.schemas.registration import RegistrationOtpVerify
from app.schemas.user import UserRegister
from app.services.auth_service import get_user_by_email, get_user_by_username
from app.utils.security import hash_password


class RegistrationConflictError(Exception):
    pass


class RegistrationVerificationError(Exception):
    pass


class RegistrationVerificationExpiredError(Exception):
    pass


class RegistrationRateLimitError(Exception):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Request a new code in {retry_after_seconds} seconds"
        )


def _get_otp_secret_key() -> bytes:
    if not settings.registration_otp_secret_key:
        raise RuntimeError(
            "REGISTRATION_OTP_SECRET_KEY is not set. Add it to your .env file."
        )

    return settings.registration_otp_secret_key.encode("utf-8")


def _hash_otp(verification_id: str, otp: str) -> str:
    payload = f"{verification_id}:{otp}".encode("utf-8")
    return hmac.new(
        _get_otp_secret_key(),
        payload,
        hashlib.sha256
    ).hexdigest()


def _raise_if_user_exists(
    db: Session,
    username: str,
    email: str
) -> None:
    if get_user_by_username(db, username):
        raise RegistrationConflictError("Username already exists")

    if get_user_by_email(db, email):
        raise RegistrationConflictError("Email already exists")


def create_registration_verification(
    db: Session,
    registration: UserRegister
) -> tuple[RegistrationVerification, str]:
    username = registration.username.strip()
    email = str(registration.email).lower()
    _raise_if_user_exists(db, username, email)

    now = utc_now()
    db.query(RegistrationVerification).filter(
        RegistrationVerification.expires_at <= now
    ).delete(synchronize_session=False)
    existing_verification = db.query(RegistrationVerification).filter(
        or_(
            RegistrationVerification.username == username,
            RegistrationVerification.email == email
        )
    ).first()

    if existing_verification:
        resend_available_at = existing_verification.created_at + timedelta(
            seconds=settings.registration_otp_resend_cooldown_seconds
        )
        retry_after_seconds = ceil(
            (resend_available_at - now).total_seconds()
        )

        if retry_after_seconds > 0:
            raise RegistrationRateLimitError(retry_after_seconds)

    db.query(RegistrationVerification).filter(
        or_(
            RegistrationVerification.username == username,
            RegistrationVerification.email == email
        )
    ).delete(synchronize_session=False)

    verification_id = str(uuid4())
    otp = f"{secrets.randbelow(1_000_000):06d}"
    verification = RegistrationVerification(
        id=verification_id,
        username=username,
        email=email,
        password_hash=hash_password(registration.password),
        otp_hash=_hash_otp(verification_id, otp),
        expires_at=now + timedelta(
            minutes=settings.registration_otp_expire_minutes
        ),
        attempts_remaining=settings.registration_otp_max_attempts
    )

    try:
        db.add(verification)
        db.commit()
        db.refresh(verification)
    except IntegrityError as exc:
        db.rollback()
        raise RegistrationConflictError(
            "A registration verification is already pending"
        ) from exc

    return verification, otp


def cancel_registration_verification(
    db: Session,
    verification_id: str
) -> None:
    db.query(RegistrationVerification).filter(
        RegistrationVerification.id == verification_id
    ).delete(synchronize_session=False)
    db.commit()


def verify_registration(
    db: Session,
    verification_data: RegistrationOtpVerify
) -> User:
    verification_id = str(verification_data.verification_id)
    verification = (
        db.query(RegistrationVerification)
        .filter(RegistrationVerification.id == verification_id)
        .with_for_update()
        .first()
    )

    if verification is None:
        raise RegistrationVerificationError(
            "Invalid or already used verification code"
        )

    if verification.expires_at <= utc_now():
        db.delete(verification)
        db.commit()
        raise RegistrationVerificationExpiredError(
            "Verification code has expired"
        )

    supplied_hash = _hash_otp(verification_id, verification_data.otp)

    if not hmac.compare_digest(verification.otp_hash, supplied_hash):
        verification.attempts_remaining -= 1

        if verification.attempts_remaining <= 0:
            db.delete(verification)

        db.commit()
        raise RegistrationVerificationError("Invalid verification code")

    try:
        _raise_if_user_exists(
            db,
            verification.username,
            verification.email
        )
    except RegistrationConflictError:
        db.delete(verification)
        db.commit()
        raise

    user = User(
        username=verification.username,
        email=verification.email,
        password_hash=verification.password_hash
    )

    try:
        db.add(user)
        db.delete(verification)
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise RegistrationConflictError(
            "Username or email already exists"
        ) from exc

    return user
