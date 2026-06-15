import os

from dotenv import load_dotenv


load_dotenv()


def _get_int_env(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


class Settings:
    database_url: str | None = os.getenv("DATABASE_URL")
    jwt_secret_key: str | None = os.getenv("JWT_SECRET_KEY")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = _get_int_env(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        30
    )


settings = Settings()
