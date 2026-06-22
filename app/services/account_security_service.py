import hashlib
import hmac
import secrets
from datetime import timedelta
from math import ceil
from uuid import uuid4

from jose import JWTError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.base import utc_now
from app.models.crypto_profile import UserCryptoProfile
from app.models.password_recovery import PasswordRecoveryVerification
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.account import (
    PasswordChangeRequest,
    PasswordRecoveryComplete,
    PasswordRecoveryVerify,
    RecoveryKeyRotateRequest
)
from app.schemas.crypto import CryptoProfileRewrap
from app.services.auth_service import get_user_by_username_or_email
from app.services.crypto_profile_service import get_crypto_profile
from app.services.session_service import (
    SessionTokens,
    create_user_session,
    rotate_current_session_after_password_change
)
from app.utils.security import (
    create_password_recovery_token,
    decode_password_recovery_token,
    hash_password,
    verify_password
)


class AccountPasswordError(Exception):
    pass


class PasswordRecoveryError(Exception):
    pass


class PasswordRecoveryExpiredError(Exception):
    pass


class PasswordRecoveryNotConfiguredError(Exception):
    pass


class PasswordRecoveryRateLimitError(Exception):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Request a new code in {retry_after_seconds} seconds"
        )


def _get_otp_secret() -> bytes:
    if not settings.registration_otp_secret_key:
        raise RuntimeError(
            "REGISTRATION_OTP_SECRET_KEY is not set. Add it to your .env file."
        )

    return settings.registration_otp_secret_key.encode("utf-8")


def _keyed_hash(purpose: str, value: str) -> str:
    payload = f"{purpose}:{value}".encode("utf-8")
    return hmac.new(
        _get_otp_secret(),
        payload,
        hashlib.sha256
    ).hexdigest()


def _hash_recovery_otp(verification_id: str, otp: str) -> str:
    return _keyed_hash("password-recovery-otp", f"{verification_id}:{otp}")


def _apply_password_profile(
    profile: UserCryptoProfile,
    data: CryptoProfileRewrap
) -> None:
    profile.version = data.version
    profile.kdf_algorithm = data.kdf_algorithm
    profile.kdf_salt = data.kdf_salt
    profile.kdf_parameters = data.kdf_parameters.model_dump()
    profile.wrap_algorithm = data.wrap_algorithm
    profile.wrapped_vault_key = data.wrapped_vault_key
    profile.wrap_nonce = data.wrap_nonce


def change_password(
    db: Session,
    user: User,
    current_session: UserSession,
    data: PasswordChangeRequest
) -> SessionTokens:
    if not verify_password(data.current_password, user.password_hash):
        raise AccountPasswordError("Current password is incorrect")

    if data.current_password == data.new_password:
        raise AccountPasswordError(
            "New password must be different from the current password"
        )

    profile = get_crypto_profile(db, user.id)

    if profile is None:
        raise PasswordRecoveryNotConfiguredError(
            "Crypto profile is not configured"
        )

    user.password_hash = hash_password(data.new_password)
    user.auth_version += 1
    _apply_password_profile(profile, data.crypto_profile)

    return rotate_current_session_after_password_change(
        db,
        user,
        current_session
    )


def rotate_recovery_key(
    db: Session,
    user: User,
    data: RecoveryKeyRotateRequest
) -> UserCryptoProfile:
    profile = get_crypto_profile(db, user.id)

    if profile is None:
        raise PasswordRecoveryNotConfiguredError(
            "Crypto profile is not configured"
        )

    recovery = data.recovery_profile
    profile.recovery_version = recovery.recovery_version
    profile.recovery_wrap_algorithm = recovery.recovery_wrap_algorithm
    profile.recovery_wrapped_vault_key = (
        recovery.recovery_wrapped_vault_key
    )
    profile.recovery_wrap_nonce = recovery.recovery_wrap_nonce
    db.commit()
    db.refresh(profile)
    return profile


def create_password_recovery_verification(
    db: Session,
    identifier: str
) -> tuple[PasswordRecoveryVerification, str, str | None]:
    normalized_identifier = identifier.strip().lower()
    identifier_hash = _keyed_hash(
        "password-recovery-identifier",
        normalized_identifier
    )
    now = utc_now()

    db.query(PasswordRecoveryVerification).filter(
        PasswordRecoveryVerification.expires_at <= now
    ).delete(synchronize_session=False)
    existing = db.query(PasswordRecoveryVerification).filter(
        PasswordRecoveryVerification.identifier_hash == identifier_hash
    ).first()

    if existing:
        resend_available_at = existing.created_at + timedelta(
            seconds=settings.registration_otp_resend_cooldown_seconds
        )
        retry_after = ceil((resend_available_at - now).total_seconds())

        if retry_after > 0:
            raise PasswordRecoveryRateLimitError(retry_after)

        db.delete(existing)

    user = get_user_by_username_or_email(db, identifier.strip())
    verification_id = str(uuid4())
    otp = f"{secrets.randbelow(1_000_000):06d}"
    verification = PasswordRecoveryVerification(
        id=verification_id,
        user_id=user.id if user else None,
        identifier_hash=identifier_hash,
        otp_hash=_hash_recovery_otp(verification_id, otp),
        expires_at=now + timedelta(
            minutes=settings.password_recovery_otp_expire_minutes
        ),
        attempts_remaining=settings.registration_otp_max_attempts
    )
    db.add(verification)
    db.commit()
    db.refresh(verification)

    return verification, otp, user.email if user else None


def cancel_password_recovery_verification(
    db: Session,
    verification_id: str
) -> None:
    db.query(PasswordRecoveryVerification).filter(
        PasswordRecoveryVerification.id == verification_id
    ).delete(synchronize_session=False)
    db.commit()


def verify_password_recovery_otp(
    db: Session,
    data: PasswordRecoveryVerify
) -> tuple[str, User, UserCryptoProfile]:
    verification = (
        db.query(PasswordRecoveryVerification)
        .filter(
            PasswordRecoveryVerification.id == str(data.verification_id)
        )
        .with_for_update()
        .first()
    )
    now = utc_now()

    if verification is None:
        raise PasswordRecoveryError("Invalid or already used recovery code")

    if verification.expires_at <= now:
        db.delete(verification)
        db.commit()
        raise PasswordRecoveryExpiredError("Recovery code has expired")

    supplied_hash = _hash_recovery_otp(verification.id, data.otp)

    if not hmac.compare_digest(verification.otp_hash, supplied_hash):
        verification.attempts_remaining -= 1

        if verification.attempts_remaining <= 0:
            db.delete(verification)

        db.commit()
        raise PasswordRecoveryError("Invalid recovery code")

    if verification.user is None:
        db.delete(verification)
        db.commit()
        raise PasswordRecoveryError("Invalid or already used recovery code")

    profile = get_crypto_profile(db, verification.user_id)

    if (
        profile is None
        or profile.recovery_version is None
        or profile.recovery_wrap_algorithm is None
        or profile.recovery_wrapped_vault_key is None
        or profile.recovery_wrap_nonce is None
    ):
        db.delete(verification)
        db.commit()
        raise PasswordRecoveryNotConfiguredError(
            "Recovery key is not configured for this account"
        )

    verification.verified_at = now
    verification.grant_expires_at = now + timedelta(
        minutes=settings.password_recovery_grant_expire_minutes
    )
    db.commit()

    token = create_password_recovery_token(
        verification.user_id,
        verification.id
    )
    return token, verification.user, profile


def complete_password_recovery(
    db: Session,
    data: PasswordRecoveryComplete
) -> tuple[User, SessionTokens]:
    try:
        payload = decode_password_recovery_token(data.recovery_token)
        user_id = int(payload["sub"])
        verification_id = str(payload["rid"])
    except (JWTError, KeyError, TypeError, ValueError) as exc:
        raise PasswordRecoveryError("Invalid recovery authorization") from exc

    verification = (
        db.query(PasswordRecoveryVerification)
        .filter(PasswordRecoveryVerification.id == verification_id)
        .with_for_update()
        .first()
    )
    now = utc_now()

    if (
        verification is None
        or verification.user_id != user_id
        or verification.verified_at is None
        or verification.grant_expires_at is None
        or verification.grant_expires_at <= now
    ):
        raise PasswordRecoveryError(
            "Recovery authorization has expired or was already used"
        )

    user = verification.user
    profile = get_crypto_profile(db, user_id)

    if user is None or profile is None:
        raise PasswordRecoveryError("Account recovery is unavailable")

    user.password_hash = hash_password(data.new_password)
    user.auth_version += 1
    _apply_password_profile(profile, data.crypto_profile)
    db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.revoked_at.is_(None)
    ).update({UserSession.revoked_at: now}, synchronize_session=False)
    db.delete(verification)
    db.commit()
    db.refresh(user)

    return user, create_user_session(db, user)
