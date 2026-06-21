from fastapi.testclient import TestClient

from app.database.database import SessionLocal
from app.models.user import User
from app.utils.security import verify_password


def test_registration_hashes_password_and_hides_hash(
    client: TestClient
) -> None:
    password = "StrongPassword-123"
    response = client.post(
        "/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": password
        }
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": response.json()["id"],
        "username": "alice",
        "email": "alice@example.com"
    }
    assert "password_hash" not in response.json()

    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == "alice").one()
        assert user.password_hash != password
        assert verify_password(password, user.password_hash)
    finally:
        db.close()


def test_duplicate_username_and_email_are_rejected(
    client: TestClient
) -> None:
    user = {
        "username": "alice",
        "email": "alice@example.com",
        "password": "StrongPassword-123"
    }
    assert client.post("/auth/register", json=user).status_code == 200

    duplicate_username = client.post(
        "/auth/register",
        json={**user, "email": "other@example.com"}
    )
    duplicate_email = client.post(
        "/auth/register",
        json={**user, "username": "other-user"}
    )

    assert duplicate_username.status_code == 400
    assert duplicate_username.json()["detail"] == "Username already exists"
    assert duplicate_email.status_code == 400
    assert duplicate_email.json()["detail"] == "Email already exists"


def test_login_and_current_user_endpoint(
    client: TestClient,
    create_authenticated_user
) -> None:
    user = create_authenticated_user("login")
    headers = {"Authorization": f"Bearer {user['token']}"}

    response = client.get("/auth/me", headers=headers)

    assert response.status_code == 200
    assert response.json()["username"] == user["username"]
    assert response.json()["email"] == user["email"]
    assert "password_hash" not in response.json()


def test_invalid_credentials_and_missing_token_are_rejected(
    client: TestClient,
    create_authenticated_user
) -> None:
    user = create_authenticated_user("invalid")

    invalid_login = client.post(
        "/auth/login",
        data={"username": user["username"], "password": "wrong-password"}
    )
    missing_token = client.get("/auth/me")

    assert invalid_login.status_code == 401
    assert missing_token.status_code == 401
