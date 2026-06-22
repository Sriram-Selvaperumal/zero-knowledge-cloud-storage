import hashlib
import hmac
from datetime import timedelta
from math import ceil

from sqlalchemy.orm import Session

from app.config import settings
from app.models.authentication_throttle import AuthenticationThrottle
from app.models.base import utc_now


class LoginRateLimitError(Exception):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Too many login attempts. Try again in {retry_after_seconds} seconds"
        )


def _get_throttle_secret() -> bytes:
    if not settings.auth_throttle_secret_key:
        raise RuntimeError(
            "AUTH_THROTTLE_SECRET_KEY is not set. Add it to your .env file."
        )

    return settings.auth_throttle_secret_key.encode("utf-8")


def login_throttle_key(identifier: str, client_host: str) -> str:
    normalized = f"login:{identifier.strip().lower()}:{client_host}"
    return hmac.new(
        _get_throttle_secret(),
        normalized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def check_login_allowed(db: Session, key_hash: str) -> None:
    throttle = db.get(AuthenticationThrottle, key_hash)

    if throttle is None or throttle.blocked_until is None:
        return

    retry_after = ceil(
        (throttle.blocked_until - utc_now()).total_seconds()
    )

    if retry_after > 0:
        raise LoginRateLimitError(retry_after)

    db.delete(throttle)
    db.commit()


def record_login_failure(db: Session, key_hash: str) -> None:
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
        + timedelta(seconds=settings.login_attempt_window_seconds)
        <= now
    ):
        throttle.failures = 1
        throttle.window_started_at = now
        throttle.blocked_until = None
        throttle.updated_at = now
    else:
        throttle.failures += 1
        throttle.updated_at = now

    if throttle.failures >= settings.login_max_attempts:
        throttle.blocked_until = now + timedelta(
            seconds=settings.login_lockout_seconds
        )

    db.commit()


def clear_login_failures(db: Session, key_hash: str) -> None:
    db.query(AuthenticationThrottle).filter(
        AuthenticationThrottle.key_hash == key_hash
    ).delete(synchronize_session=False)
    db.commit()
