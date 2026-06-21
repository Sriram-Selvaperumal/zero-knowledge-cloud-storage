import os
import shutil
import tempfile
from collections.abc import Callable, Generator
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url


PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")

development_database_url = os.getenv("DATABASE_URL")
test_database_url = os.getenv("TEST_DATABASE_URL")
test_jwt_secret_key = os.getenv("TEST_JWT_SECRET_KEY")

if not development_database_url:
    raise pytest.UsageError("DATABASE_URL is not set")

if not test_database_url:
    raise pytest.UsageError("TEST_DATABASE_URL is not set")

if not test_jwt_secret_key:
    raise pytest.UsageError("TEST_JWT_SECRET_KEY is not set")

development_url = make_url(development_database_url)
test_url = make_url(test_database_url)

if test_url.database is None or "test" not in test_url.database.lower():
    raise pytest.UsageError(
        "TEST_DATABASE_URL must use a database whose name contains 'test'"
    )

if (
    development_url.host == test_url.host
    and development_url.port == test_url.port
    and development_url.database == test_url.database
):
    raise pytest.UsageError(
        "TEST_DATABASE_URL must not point to the development database"
    )

test_storage_root = Path(tempfile.mkdtemp(prefix="cloud-storage-tests-"))

os.environ["DATABASE_URL"] = test_database_url
os.environ["JWT_SECRET_KEY"] = test_jwt_secret_key
os.environ["STORAGE_ROOT"] = str(test_storage_root)
os.environ["MAX_UPLOAD_SIZE_BYTES"] = "64"

from app.config import settings
from app.database.database import SessionLocal
from app.main import app
from app.models.file import FileMetadata
from app.models.user import User


def clear_test_state() -> None:
    db = SessionLocal()

    try:
        db.query(FileMetadata).delete(synchronize_session=False)
        db.query(User).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    shutil.rmtree(settings.storage_root, ignore_errors=True)
    settings.storage_root.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session", autouse=True)
def migrated_test_database() -> Generator[None, None, None]:
    alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    command.upgrade(alembic_config, "head")

    yield

    clear_test_state()
    shutil.rmtree(settings.storage_root, ignore_errors=True)


@pytest.fixture(autouse=True)
def isolated_test_state(
    migrated_test_database: None
) -> Generator[None, None, None]:
    clear_test_state()
    yield
    clear_test_state()


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def create_authenticated_user(
    client: TestClient
) -> Callable[[str], dict[str, str | int]]:
    def create_user(prefix: str = "user") -> dict[str, str | int]:
        suffix = uuid4().hex[:12]
        username = f"{prefix}_{suffix}"
        email = f"{username}@example.com"
        password = f"StrongPassword-{uuid4().hex}"

        register_response = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password
            }
        )
        assert register_response.status_code == 200

        login_response = client.post(
            "/auth/login",
            data={"username": username, "password": password}
        )
        assert login_response.status_code == 200

        return {
            "id": register_response.json()["id"],
            "username": username,
            "email": email,
            "password": password,
            "token": login_response.json()["access_token"]
        }

    return create_user
