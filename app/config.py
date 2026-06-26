import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _get_positive_int_env(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        parsed_value = int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc

    if parsed_value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")

    return parsed_value


def _get_path_env(name: str, default: str) -> Path:
    path = Path(os.getenv(name, default)).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def _get_list_env(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _get_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    normalized_value = value.strip().lower()

    if normalized_value in {"1", "true", "yes", "on"}:
        return True

    if normalized_value in {"0", "false", "no", "off"}:
        return False

    raise RuntimeError(f"{name} must be a boolean")


def _get_path_prefix_env(name: str, default: str) -> str:
    value = os.getenv(name, default).strip()

    if not value:
        return ""

    return "/" + value.strip("/")


class Settings:
    api_prefix: str = _get_path_prefix_env("API_PREFIX", "/api")
    database_url: str | None = os.getenv("DATABASE_URL")
    jwt_secret_key: str | None = os.getenv("JWT_SECRET_KEY")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = _get_positive_int_env(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        30
    )
    refresh_token_secret_key: str | None = os.getenv(
        "REFRESH_TOKEN_SECRET_KEY"
    )
    refresh_token_expire_days: int = _get_positive_int_env(
        "REFRESH_TOKEN_EXPIRE_DAYS",
        30
    )
    refresh_token_reuse_grace_seconds: int = _get_positive_int_env(
        "REFRESH_TOKEN_REUSE_GRACE_SECONDS",
        10
    )
    refresh_cookie_name: str = os.getenv(
        "REFRESH_COOKIE_NAME",
        "prototype_refresh"
    )
    refresh_cookie_secure: bool = _get_bool_env(
        "REFRESH_COOKIE_SECURE",
        False
    )
    auth_throttle_secret_key: str | None = os.getenv(
        "AUTH_THROTTLE_SECRET_KEY"
    )
    login_max_attempts: int = _get_positive_int_env(
        "LOGIN_MAX_ATTEMPTS",
        5
    )
    login_attempt_window_seconds: int = _get_positive_int_env(
        "LOGIN_ATTEMPT_WINDOW_SECONDS",
        15 * 60
    )
    login_lockout_seconds: int = _get_positive_int_env(
        "LOGIN_LOCKOUT_SECONDS",
        15 * 60
    )
    share_max_attempts: int = _get_positive_int_env(
        "SHARE_MAX_ATTEMPTS",
        5
    )
    share_attempt_window_seconds: int = _get_positive_int_env(
        "SHARE_ATTEMPT_WINDOW_SECONDS",
        15 * 60
    )
    share_lockout_seconds: int = _get_positive_int_env(
        "SHARE_LOCKOUT_SECONDS",
        15 * 60
    )
    share_download_grant_expire_minutes: int = _get_positive_int_env(
        "SHARE_DOWNLOAD_GRANT_EXPIRE_MINUTES",
        5
    )
    share_max_expire_days: int = _get_positive_int_env(
        "SHARE_MAX_EXPIRE_DAYS",
        365
    )
    storage_root: Path = _get_path_env("STORAGE_ROOT", "storage")
    max_upload_size_bytes: int = _get_positive_int_env(
        "MAX_UPLOAD_SIZE_BYTES",
        100 * 1024 * 1024
    )
    cors_origins: list[str] = _get_list_env(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173"
    )
    registration_otp_secret_key: str | None = os.getenv(
        "REGISTRATION_OTP_SECRET_KEY"
    )
    registration_otp_expire_minutes: int = _get_positive_int_env(
        "REGISTRATION_OTP_EXPIRE_MINUTES",
        10
    )
    registration_otp_max_attempts: int = _get_positive_int_env(
        "REGISTRATION_OTP_MAX_ATTEMPTS",
        5
    )
    registration_otp_resend_cooldown_seconds: int = _get_positive_int_env(
        "REGISTRATION_OTP_RESEND_COOLDOWN_SECONDS",
        60
    )
    password_recovery_otp_expire_minutes: int = _get_positive_int_env(
        "PASSWORD_RECOVERY_OTP_EXPIRE_MINUTES",
        10
    )
    password_recovery_grant_expire_minutes: int = _get_positive_int_env(
        "PASSWORD_RECOVERY_GRANT_EXPIRE_MINUTES",
        10
    )
    smtp_host: str | None = os.getenv("SMTP_HOST")
    smtp_port: int = _get_positive_int_env("SMTP_PORT", 587)
    smtp_username: str | None = os.getenv("SMTP_USERNAME")
    smtp_password: str | None = os.getenv("SMTP_PASSWORD")
    smtp_from_email: str | None = os.getenv("SMTP_FROM_EMAIL")
    smtp_auth: bool = _get_bool_env("SMTP_AUTH", True)
    smtp_starttls: bool = _get_bool_env("SMTP_STARTTLS", True)
    smtp_timeout_seconds: int = _get_positive_int_env(
        "SMTP_TIMEOUT_SECONDS",
        10
    )


settings = Settings()
