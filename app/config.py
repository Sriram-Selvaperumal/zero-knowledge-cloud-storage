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


class Settings:
    database_url: str | None = os.getenv("DATABASE_URL")
    jwt_secret_key: str | None = os.getenv("JWT_SECRET_KEY")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = _get_positive_int_env(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        30
    )
    storage_root: Path = _get_path_env("STORAGE_ROOT", "storage")
    max_upload_size_bytes: int = _get_positive_int_env(
        "MAX_UPLOAD_SIZE_BYTES",
        100 * 1024 * 1024
    )


settings = Settings()
