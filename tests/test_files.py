import base64
import json
from collections.abc import Callable

from fastapi.testclient import TestClient

from app.config import settings
from app.database.database import SessionLocal
from app.models.file import FileMetadata


ENCRYPTED_MANIFEST = base64.b64encode(bytes(range(32))).decode()


def valid_encryption_metadata(plaintext_size: int = 32) -> dict:
    return {
        "version": 1,
        "cipher": "xchacha20-poly1305-secretstream",
        "file_id": base64.b64encode(bytes(range(16))).decode(),
        "chunk_size": 4 * 1024 * 1024,
        "plaintext_size": plaintext_size,
        "stream_header": base64.b64encode(bytes(range(24))).decode(),
        "wrapped_file_key": base64.b64encode(bytes(range(48))).decode(),
        "wrapped_file_key_nonce": base64.b64encode(
            bytes(range(24, 48))
        ).decode(),
        "manifest_nonce": base64.b64encode(bytes(range(48, 72))).decode()
    }


def auth_headers(user: dict[str, str | int]) -> dict[str, str]:
    return {"Authorization": f"Bearer {user['token']}"}


def upload_file(
    client: TestClient,
    user: dict[str, str | int],
    content: bytes,
    encryption_metadata: str | None = None
):
    data = {"encrypted_filename": ENCRYPTED_MANIFEST}

    data["encryption_metadata"] = (
        encryption_metadata
        if encryption_metadata is not None
        else json.dumps(valid_encryption_metadata(len(content)))
    )

    return client.post(
        "/files/upload",
        headers=auth_headers(user),
        files={
            "file": (
                "ciphertext.enc",
                content,
                "application/octet-stream"
            )
        },
        data=data
    )


def test_upload_list_download_and_delete(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    user = create_authenticated_user("files")
    ciphertext = bytes(range(32))
    metadata = valid_encryption_metadata(len(ciphertext))

    upload_response = upload_file(
        client,
        user,
        ciphertext,
        json.dumps(metadata)
    )

    assert upload_response.status_code == 201
    uploaded = upload_response.json()
    assert uploaded["encrypted_filename"] == ENCRYPTED_MANIFEST
    assert uploaded["size_bytes"] == len(ciphertext)
    assert uploaded["encryption_metadata"] == metadata
    assert "storage_key" not in uploaded
    assert "owner_id" not in uploaded

    db = SessionLocal()

    try:
        stored_metadata = db.get(FileMetadata, uploaded["id"])
        assert stored_metadata is not None
        storage_path = settings.storage_root / stored_metadata.storage_key
    finally:
        db.close()

    assert storage_path.read_bytes() == ciphertext

    list_response = client.get("/files", headers=auth_headers(user))
    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [uploaded["id"]]

    download_response = client.get(
        f"/files/{uploaded['id']}/download",
        headers=auth_headers(user)
    )
    assert download_response.status_code == 200
    assert download_response.content == ciphertext

    delete_response = client.delete(
        f"/files/{uploaded['id']}",
        headers=auth_headers(user)
    )
    assert delete_response.status_code == 204
    assert not storage_path.exists()
    assert client.get("/files", headers=auth_headers(user)).json() == []


def test_users_cannot_access_each_others_files(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner = create_authenticated_user("owner")
    other_user = create_authenticated_user("other")
    upload_response = upload_file(client, owner, b"encrypted content")
    file_id = upload_response.json()["id"]

    other_list = client.get("/files", headers=auth_headers(other_user))
    other_download = client.get(
        f"/files/{file_id}/download",
        headers=auth_headers(other_user)
    )
    other_delete = client.delete(
        f"/files/{file_id}",
        headers=auth_headers(other_user)
    )

    assert other_list.status_code == 200
    assert other_list.json() == []
    assert other_download.status_code == 404
    assert other_delete.status_code == 404


def test_upload_validation(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    user = create_authenticated_user("validation")

    empty_upload = upload_file(client, user, b"")
    oversized_upload = upload_file(client, user, bytes(range(65)))
    invalid_metadata = upload_file(client, user, b"content", "not-json")
    missing_metadata = client.post(
        "/files/upload",
        headers=auth_headers(user),
        files={
            "file": (
                "ciphertext.enc",
                b"content",
                "application/octet-stream"
            )
        },
        data={"encrypted_filename": ENCRYPTED_MANIFEST}
    )

    assert empty_upload.status_code == 400
    assert oversized_upload.status_code == 413
    assert invalid_metadata.status_code == 422
    assert missing_metadata.status_code == 422
    assert client.get("/files", headers=auth_headers(user)).json() == []


def test_file_routes_require_authentication(client: TestClient) -> None:
    assert client.get("/files").status_code == 401
    assert client.get("/files/1/download").status_code == 401
    assert client.delete("/files/1").status_code == 401
