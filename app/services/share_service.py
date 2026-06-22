import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from math import ceil
from uuid import uuid4

from jose import JWTError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.authentication_throttle import AuthenticationThrottle
from app.models.base import utc_now
from app.models.file import FileMetadata
from app.models.file_share import FileShare
from app.schemas.share import ShareCreateRequest
from app.utils.security import (
    create_share_download_token,
    decode_share_download_token
)


SHARE_TOKEN_PREFIX = "prototype-share-v1_"


class ShareError(Exception):
    pass


class ShareNotFoundError(ShareError):
    pass


class ShareInactiveError(ShareError):
    pass


class ShareConflictError(ShareError):
    pass


class SharePasswordError(ShareError):
    pass


class ShareRateLimitError(ShareError):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            "Too many password attempts. "
            f"Try again in {retry_after_seconds} seconds"
        )


def hash_share_token(token: str) -> str:
    if (
        not token.startswith(SHARE_TOKEN_PREFIX)
        or len(token) < len(SHARE_TOKEN_PREFIX) + 40
        or len(token) > 128
    ):
        raise ShareNotFoundError("Share not found")

    return hashlib.blake2b(token.encode("utf-8"), digest_size=32).hexdigest()


def _normalize_expiry(value: datetime | None) -> datetime | None:
    if value is None:
        return None

    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)

    now = utc_now()

    if value <= now:
        raise ShareError("Share expiration must be in the future")

    if value > now + timedelta(days=settings.share_max_expire_days):
        raise ShareError(
            f"Share expiration cannot exceed {settings.share_max_expire_days} days"
        )

    return value


def create_file_share(
    db: Session,
    file_metadata: FileMetadata,
    data: ShareCreateRequest
) -> FileShare:
    if not file_metadata.encryption_metadata:
        raise ShareError("Only encrypted files can be shared")

    share = FileShare(
        id=str(uuid4()),
        file_id=file_metadata.id,
        token_hash=data.token_hash,
        version=data.version,
        kdf_algorithm=data.kdf_algorithm,
        kdf_salt=data.kdf_salt,
        kdf_parameters=data.kdf_parameters.model_dump(),
        wrap_algorithm=data.wrap_algorithm,
        wrapped_file_key=data.wrapped_file_key,
        wrap_nonce=data.wrap_nonce,
        password_verifier=data.password_verifier,
        expires_at=_normalize_expiry(data.expires_at)
    )

    try:
        db.add(share)
        db.commit()
        db.refresh(share)
    except IntegrityError as exc:
        db.rollback()
        raise ShareConflictError("Share token already exists") from exc

    return share


def list_file_shares(db: Session, file_id: int) -> list[FileShare]:
    return (
        db.query(FileShare)
        .filter(FileShare.file_id == file_id)
        .order_by(FileShare.created_at.desc())
        .all()
    )


def revoke_file_share(db: Session, file_id: int, share_id: str) -> None:
    share = (
        db.query(FileShare)
        .filter(FileShare.id == share_id, FileShare.file_id == file_id)
        .first()
    )

    if share is None:
        raise ShareNotFoundError("Share not found")

    if share.revoked_at is None:
        share.revoked_at = utc_now()
        db.commit()


def get_share_by_token(db: Session, token: str) -> FileShare:
    token_hash = hash_share_token(token)
    share = (
        db.query(FileShare)
        .filter(FileShare.token_hash == token_hash)
        .first()
    )

    if share is None:
        raise ShareNotFoundError("Share not found")

    if share.revoked_at is not None:
        raise ShareInactiveError("This share has been revoked")

    if share.expires_at is not None and share.expires_at <= utc_now():
        raise ShareInactiveError("This share has expired")

    return share


def _get_throttle_secret() -> bytes:
    if not settings.auth_throttle_secret_key:
        raise RuntimeError(
            "AUTH_THROTTLE_SECRET_KEY is not set. Add it to your .env file."
        )

    return settings.auth_throttle_secret_key.encode("utf-8")


def share_throttle_key(share: FileShare, client_host: str) -> str:
    value = f"share:{share.token_hash}:{client_host}"
    return hmac.new(
        _get_throttle_secret(),
        value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def check_share_access_allowed(db: Session, key_hash: str) -> None:
    throttle = db.get(AuthenticationThrottle, key_hash)

    if throttle is None or throttle.blocked_until is None:
        return

    retry_after = ceil(
        (throttle.blocked_until - utc_now()).total_seconds()
    )

    if retry_after > 0:
        raise ShareRateLimitError(retry_after)

    db.delete(throttle)
    db.commit()


def _record_share_failure(db: Session, key_hash: str) -> None:
    now = utc_now()
    throttle = (
        db.query(AuthenticationThrottle)
        .filter(AuthenticationThrottle.key_hash == key_hash)
        .with_for_update()
        .first()
    )

    if throttle is None:
        throttle = AuthenticationThrottle(
            key_hash=key_hash,
            failures=1,
            window_started_at=now,
            updated_at=now
        )
        db.add(throttle)
    elif (
        throttle.window_started_at
        + timedelta(seconds=settings.share_attempt_window_seconds)
        <= now
    ):
        throttle.failures = 1
        throttle.window_started_at = now
        throttle.blocked_until = None
        throttle.updated_at = now
    else:
        throttle.failures += 1
        throttle.updated_at = now

    if throttle.failures >= settings.share_max_attempts:
        throttle.blocked_until = now + timedelta(
            seconds=settings.share_lockout_seconds
        )

    db.commit()


def verify_share_password(
    db: Session,
    share: FileShare,
    password_verifier: str,
    client_host: str
) -> str:
    key_hash = share_throttle_key(share, client_host)
    check_share_access_allowed(db, key_hash)

    if not hmac.compare_digest(share.password_verifier, password_verifier):
        _record_share_failure(db, key_hash)
        check_share_access_allowed(db, key_hash)
        raise SharePasswordError("Share password is incorrect")

    db.query(AuthenticationThrottle).filter(
        AuthenticationThrottle.key_hash == key_hash
    ).delete(synchronize_session=False)
    db.commit()
    return create_share_download_token(share.id, share.token_hash)


def authorize_share_download(
    db: Session,
    raw_share_token: str,
    download_token: str
) -> FileShare:
    share = get_share_by_token(db, raw_share_token)

    try:
        payload = decode_share_download_token(download_token)
    except (JWTError, TypeError, ValueError) as exc:
        raise SharePasswordError("Download authorization is invalid") from exc

    if (
        payload.get("sid") != share.id
        or payload.get("th") != share.token_hash
    ):
        raise SharePasswordError("Download authorization is invalid")

    return share
