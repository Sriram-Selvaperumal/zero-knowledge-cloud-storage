import base64
from datetime import timedelta

from fastapi.testclient import TestClient

from app.database.database import SessionLocal
from app.models.base import utc_now
from app.models.registration_verification import RegistrationVerification
from app.models.user import User
from app.utils.security import verify_password


def crypto_profile_payload(seed: int = 1) -> dict:
    return {
        "version": 1,
        "kdf_algorithm": "argon2id",
        "kdf_salt": base64.b64encode(bytes([seed]) * 16).decode(),
        "kdf_parameters": {
            "opslimit": 3,
            "memlimit": 64 * 1024 * 1024
        },
        "wrap_algorithm": "xchacha20-poly1305-ietf",
        "wrapped_vault_key": base64.b64encode(
            bytes([seed + 1]) * 48
        ).decode(),
        "wrap_nonce": base64.b64encode(bytes([seed + 2]) * 24).decode()
    }


def test_registration_hashes_password_and_hides_hash(
    client: TestClient,
    sent_registration_otps: dict[str, str]
) -> None:
    password = "StrongPassword-123"
    request_response = client.post(
        "/auth/register/request-otp",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": password
        }
    )

    assert request_response.status_code == 202
    assert "otp" not in request_response.json()
    resend_response = client.post(
        "/auth/register/request-otp",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": password
        }
    )
    assert resend_response.status_code == 429
    assert int(resend_response.headers["Retry-After"]) > 0

    db = SessionLocal()

    try:
        assert db.query(User).count() == 0
        pending = db.query(RegistrationVerification).one()
        assert pending.password_hash != password
        assert verify_password(password, pending.password_hash)
        assert pending.otp_hash != sent_registration_otps["alice@example.com"]
    finally:
        db.close()

    response = client.post(
        "/auth/register/verify",
        json={
            "verification_id": request_response.json()["verification_id"],
            "otp": sent_registration_otps["alice@example.com"]
        }
    )

    assert response.status_code == 201
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
    client: TestClient,
    sent_registration_otps: dict[str, str]
) -> None:
    user = {
        "username": "alice",
        "email": "alice@example.com",
        "password": "StrongPassword-123"
    }
    request_response = client.post(
        "/auth/register/request-otp",
        json=user
    )
    assert request_response.status_code == 202
    assert client.post(
        "/auth/register/verify",
        json={
            "verification_id": request_response.json()["verification_id"],
            "otp": sent_registration_otps[user["email"]]
        }
    ).status_code == 201

    duplicate_username = client.post(
        "/auth/register/request-otp",
        json={**user, "email": "other@example.com"}
    )
    duplicate_email = client.post(
        "/auth/register/request-otp",
        json={**user, "username": "other-user"}
    )

    assert duplicate_username.status_code == 409
    assert duplicate_username.json()["detail"] == "Username already exists"
    assert duplicate_email.status_code == 409
    assert duplicate_email.json()["detail"] == "Email already exists"


def test_registration_rejects_wrong_and_expired_otp(
    client: TestClient,
    sent_registration_otps: dict[str, str]
) -> None:
    email = "otp@example.com"
    request_response = client.post(
        "/auth/register/request-otp",
        json={
            "username": "otp-user",
            "email": email,
            "password": "StrongPassword-123"
        }
    )
    verification_id = request_response.json()["verification_id"]
    delivered_otp = sent_registration_otps[email]
    wrong_otp = "000000" if delivered_otp != "000000" else "111111"

    wrong_response = client.post(
        "/auth/register/verify",
        json={"verification_id": verification_id, "otp": wrong_otp}
    )
    assert wrong_response.status_code == 400
    assert client.post(
        "/auth/login",
        data={"username": "otp-user", "password": "StrongPassword-123"}
    ).status_code == 401

    db = SessionLocal()

    try:
        pending = db.query(RegistrationVerification).one()
        pending.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    expired_response = client.post(
        "/auth/register/verify",
        json={
            "verification_id": verification_id,
            "otp": delivered_otp
        }
    )
    assert expired_response.status_code == 410
    assert expired_response.json()["detail"] == (
        "Verification code has expired"
    )
    with SessionLocal() as db:
        assert db.query(User).count() == 0


def test_registration_invalidates_code_after_attempt_limit(
    client: TestClient,
    sent_registration_otps: dict[str, str]
) -> None:
    email = "attempts@example.com"
    request_response = client.post(
        "/auth/register/request-otp",
        json={
            "username": "attempt-user",
            "email": email,
            "password": "StrongPassword-123"
        }
    )
    verification_id = request_response.json()["verification_id"]
    delivered_otp = sent_registration_otps[email]
    wrong_otp = "000000" if delivered_otp != "000000" else "111111"

    for _ in range(5):
        response = client.post(
            "/auth/register/verify",
            json={"verification_id": verification_id, "otp": wrong_otp}
        )
        assert response.status_code == 400

    used_response = client.post(
        "/auth/register/verify",
        json={"verification_id": verification_id, "otp": delivered_otp}
    )
    assert used_response.status_code == 400
    assert used_response.json()["detail"] == (
        "Invalid or already used verification code"
    )

    with SessionLocal() as db:
        assert db.query(RegistrationVerification).count() == 0
        assert db.query(User).count() == 0


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


def test_crypto_profile_create_read_and_rewrap(
    client: TestClient,
    create_authenticated_user
) -> None:
    user = create_authenticated_user("crypto")
    other_user = create_authenticated_user("other-crypto")
    headers = {"Authorization": f"Bearer {user['token']}"}
    other_headers = {"Authorization": f"Bearer {other_user['token']}"}
    initial_profile = crypto_profile_payload(1)

    create_response = client.post(
        "/auth/crypto-profile",
        headers=headers,
        json=initial_profile
    )

    assert create_response.status_code == 201
    assert create_response.json() == initial_profile
    assert client.post(
        "/auth/crypto-profile",
        headers=headers,
        json=initial_profile
    ).status_code == 409

    read_response = client.get("/auth/crypto-profile", headers=headers)
    assert read_response.status_code == 200
    assert read_response.json() == initial_profile
    assert client.get(
        "/auth/crypto-profile",
        headers=other_headers
    ).status_code == 404

    rewrapped_profile = crypto_profile_payload(4)
    rewrap_response = client.put(
        "/auth/crypto-profile/rewrap",
        headers=headers,
        json=rewrapped_profile
    )

    assert rewrap_response.status_code == 200
    assert rewrap_response.json() == rewrapped_profile


def test_crypto_profile_rejects_invalid_base64(
    client: TestClient,
    create_authenticated_user
) -> None:
    user = create_authenticated_user("invalid-crypto")
    headers = {"Authorization": f"Bearer {user['token']}"}
    profile = crypto_profile_payload()
    profile["kdf_salt"] = "not-base64!"

    response = client.post(
        "/auth/crypto-profile",
        headers=headers,
        json=profile
    )

    assert response.status_code == 422
