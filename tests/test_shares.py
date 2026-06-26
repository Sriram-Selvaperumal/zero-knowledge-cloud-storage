import base64
import json
from collections.abc import Callable
from datetime import timedelta

from fastapi.testclient import TestClient

from app.database.database import SessionLocal
from app.models.base import utc_now
from app.models.file_share import FileShare
from app.services.share_service import hash_share_token
from tests.test_files import auth_headers, upload_file


def b64(length: int, offset: int = 0) -> str:
    return base64.b64encode(
        bytes((index + offset) % 256 for index in range(length))
    ).decode()


def share_token(suffix: str = "A") -> str:
    return f"prototype-share-v1_{suffix * 43}"


def share_payload(token: str, verifier: str, expires_at=None) -> dict:
    return {
        "token_hash": hash_share_token(token),
        "version": 1,
        "kdf_algorithm": "argon2id",
        "kdf_salt": b64(16),
        "kdf_parameters": {
            "opslimit": 2,
            "memlimit": 64 * 1024 * 1024
        },
        "wrap_algorithm": "xchacha20-poly1305-ietf",
        "wrapped_file_key": b64(48),
        "wrap_nonce": b64(24, 24),
        "password_verifier": verifier,
        "expires_at": expires_at
    }


def create_uploaded_file(
    client: TestClient,
    create_authenticated_user: Callable,
    prefix: str
) -> tuple[dict, int, bytes]:
    user = create_authenticated_user(prefix)
    ciphertext = b"encrypted shared content"
    response = upload_file(client, user, ciphertext)
    assert response.status_code == 201
    return user, response.json()["id"], ciphertext


def test_create_unlock_download_list_and_revoke_share(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner, file_id, ciphertext = create_uploaded_file(
        client,
        create_authenticated_user,
        "share_owner"
    )
    token = share_token()
    verifier = b64(32, 40)
    expires_at = (utc_now() + timedelta(days=7)).isoformat() + "Z"

    create_response = client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=share_payload(token, verifier, expires_at)
    )

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["file_id"] == file_id
    assert "token_hash" not in created
    assert "password_verifier" not in created
    assert "wrapped_file_key" not in created

    list_response = client.get(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner)
    )
    assert list_response.status_code == 200
    assert [share["id"] for share in list_response.json()] == [created["id"]]

    inspect_response = client.get(f"/api/shares/{token}")
    assert inspect_response.status_code == 200
    assert inspect_response.json()["kdf_algorithm"] == "argon2id"
    assert "password_verifier" not in inspect_response.json()

    assert client.post(
        f"/api/shares/{token}/unlock",
        json={"password_verifier": b64(32, 41)}
    ).status_code == 401

    unlock_response = client.post(
        f"/api/shares/{token}/unlock",
        json={"password_verifier": verifier}
    )
    assert unlock_response.status_code == 200
    unlocked = unlock_response.json()
    assert unlocked["share_envelope"]["wrapped_file_key"] == b64(48)
    assert "wrapped_file_key" not in unlocked["encryption_metadata"]
    assert unlocked["download_token"]

    assert client.get(f"/api/shares/{token}/download").status_code == 401
    download_response = client.get(
        f"/api/shares/{token}/download",
        headers={"Authorization": f"Share {unlocked['download_token']}"}
    )
    assert download_response.status_code == 200
    assert download_response.content == ciphertext

    revoke_response = client.delete(
        f"/api/files/{file_id}/shares/{created['id']}",
        headers=auth_headers(owner)
    )
    assert revoke_response.status_code == 204
    assert client.get(f"/api/shares/{token}").status_code == 410
    assert client.get(
        f"/api/shares/{token}/download",
        headers={"Authorization": f"Share {unlocked['download_token']}"}
    ).status_code == 410


def test_share_ownership_expiration_and_file_delete_cascade(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner, file_id, _ = create_uploaded_file(
        client,
        create_authenticated_user,
        "share_access"
    )
    other = create_authenticated_user("share_other")
    token = share_token("B")
    verifier = b64(32, 50)
    create_response = client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=share_payload(token, verifier)
    )
    share_id = create_response.json()["id"]

    assert client.get(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(other)
    ).status_code == 404
    assert client.delete(
        f"/api/files/{file_id}/shares/{share_id}",
        headers=auth_headers(other)
    ).status_code == 404

    past_expiry = (utc_now() - timedelta(minutes=1)).isoformat() + "Z"
    assert client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=share_payload(share_token("C"), verifier, past_expiry)
    ).status_code == 400

    db = SessionLocal()
    try:
        share = db.get(FileShare, share_id)
        assert share is not None
        share.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    assert client.get(f"/api/shares/{token}").status_code == 410

    assert client.delete(
        f"/api/files/{file_id}",
        headers=auth_headers(owner)
    ).status_code == 204

    db = SessionLocal()
    try:
        assert db.get(FileShare, share_id) is None
    finally:
        db.close()


def test_share_password_attempts_are_throttled(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner, file_id, _ = create_uploaded_file(
        client,
        create_authenticated_user,
        "share_throttle"
    )
    token = share_token("D")
    verifier = b64(32, 60)
    assert client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=share_payload(token, verifier)
    ).status_code == 201

    wrong_verifier = b64(32, 61)

    for _ in range(4):
        response = client.post(
            f"/api/shares/{token}/unlock",
            json={"password_verifier": wrong_verifier}
        )
        assert response.status_code == 401

    locked_response = client.post(
        f"/api/shares/{token}/unlock",
        json={"password_verifier": wrong_verifier}
    )
    assert locked_response.status_code == 429
    assert "Retry-After" in locked_response.headers

    correct_during_lockout = client.post(
        f"/api/shares/{token}/unlock",
        json={"password_verifier": verifier}
    )
    assert correct_during_lockout.status_code == 429


def test_share_routes_validate_authentication_and_payloads(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner, file_id, _ = create_uploaded_file(
        client,
        create_authenticated_user,
        "share_validation"
    )
    token = share_token("E")
    verifier = b64(32, 70)

    assert client.get(f"/api/files/{file_id}/shares").status_code == 401
    assert client.post(
        f"/api/files/{file_id}/shares",
        json=share_payload(token, verifier)
    ).status_code == 401
    assert client.get(f"/api/shares/{share_token('Z')}").status_code == 404

    duplicate_payload = share_payload(token, verifier)
    assert client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=duplicate_payload
    ).status_code == 201
    assert client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=duplicate_payload
    ).status_code == 409

    malformed = duplicate_payload | {"token_hash": "not-a-hash"}
    assert client.post(
        f"/api/files/{file_id}/shares",
        headers=auth_headers(owner),
        json=malformed
    ).status_code == 422
