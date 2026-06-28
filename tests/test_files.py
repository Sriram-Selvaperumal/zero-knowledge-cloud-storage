import base64
import json
from collections.abc import Callable

from fastapi.testclient import TestClient

from app.config import settings
from app.database.database import SessionLocal
from app.models.file import FileMetadata


ENCRYPTED_MANIFEST = base64.b64encode(bytes(range(32))).decode()
ENCRYPTED_FOLDER_NAME = base64.b64encode(bytes(range(32, 64))).decode()


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


def valid_folder_encryption_metadata() -> dict:
    return {
        "version": 1,
        "cipher": "xchacha20-poly1305-folder",
        "folder_id": base64.b64encode(bytes(range(16))).decode(),
        "wrapped_folder_key": base64.b64encode(bytes(range(48))).decode(),
        "wrapped_folder_key_nonce": base64.b64encode(
            bytes(range(24, 48))
        ).decode(),
        "name_nonce": base64.b64encode(bytes(range(48, 72))).decode()
    }


def auth_headers(user: dict[str, str | int]) -> dict[str, str]:
    return {"Authorization": f"Bearer {user['token']}"}


def upload_file(
    client: TestClient,
    user: dict[str, str | int],
    content: bytes,
    encryption_metadata: str | None = None,
    folder_id: int | None = None
):
    data = {"encrypted_filename": ENCRYPTED_MANIFEST}

    data["encryption_metadata"] = (
        encryption_metadata
        if encryption_metadata is not None
        else json.dumps(valid_encryption_metadata(len(content)))
    )

    if folder_id is not None:
        data["folder_id"] = str(folder_id)

    return client.post(
        "/api/files/upload",
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


def create_folder(
    client: TestClient,
    user: dict[str, str | int],
    parent_id: int | None = None
):
    return client.post(
        "/api/folders",
        headers=auth_headers(user),
        json={
            "encrypted_name": ENCRYPTED_FOLDER_NAME,
            "encryption_metadata": valid_folder_encryption_metadata(),
            "parent_id": parent_id
        }
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
    assert uploaded["folder_id"] is None
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

    list_response = client.get("/api/files", headers=auth_headers(user))
    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [uploaded["id"]]

    download_response = client.get(
        f"/api/files/{uploaded['id']}/download",
        headers=auth_headers(user)
    )
    assert download_response.status_code == 200
    assert download_response.content == ciphertext

    delete_response = client.delete(
        f"/api/files/{uploaded['id']}",
        headers=auth_headers(user)
    )
    assert delete_response.status_code == 204
    assert not storage_path.exists()
    assert client.get("/api/files", headers=auth_headers(user)).json() == []


def test_folder_listing_upload_move_copy_and_recursive_delete(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    user = create_authenticated_user("folders")
    folder_response = create_folder(client, user)

    assert folder_response.status_code == 201
    folder = folder_response.json()
    assert folder["encrypted_name"] == ENCRYPTED_FOLDER_NAME
    assert folder["parent_id"] is None

    root_folders = client.get(
        "/api/folders?parent_id=root",
        headers=auth_headers(user)
    )
    assert root_folders.status_code == 200
    assert [item["id"] for item in root_folders.json()] == [folder["id"]]

    ciphertext = b"encrypted folder payload"
    uploaded = upload_file(
        client,
        user,
        ciphertext,
        folder_id=folder["id"]
    )
    assert uploaded.status_code == 201
    file_record = uploaded.json()
    assert file_record["folder_id"] == folder["id"]

    root_files = client.get(
        "/api/files?folder_id=root",
        headers=auth_headers(user)
    )
    folder_files = client.get(
        f"/api/files?folder_id={folder['id']}",
        headers=auth_headers(user)
    )

    assert root_files.status_code == 200
    assert root_files.json() == []
    assert folder_files.status_code == 200
    assert [item["id"] for item in folder_files.json()] == [file_record["id"]]

    move_to_root = client.patch(
        f"/api/files/{file_record['id']}/move",
        headers=auth_headers(user),
        json={"folder_id": None}
    )
    assert move_to_root.status_code == 200
    assert move_to_root.json()["folder_id"] is None

    copy_to_folder = client.post(
        f"/api/files/{file_record['id']}/copy",
        headers=auth_headers(user),
        json={"folder_id": folder["id"]}
    )
    assert copy_to_folder.status_code == 201
    copied = copy_to_folder.json()
    assert copied["id"] != file_record["id"]
    assert copied["folder_id"] == folder["id"]
    assert copied["encrypted_filename"] == file_record["encrypted_filename"]

    copied_download = client.get(
        f"/api/files/{copied['id']}/download",
        headers=auth_headers(user)
    )
    assert copied_download.status_code == 200
    assert copied_download.content == ciphertext

    delete_folder = client.delete(
        f"/api/folders/{folder['id']}",
        headers=auth_headers(user)
    )
    assert delete_folder.status_code == 204

    assert client.get(
        f"/api/files/{copied['id']}/download",
        headers=auth_headers(user)
    ).status_code == 404

    remaining = client.get(
        "/api/files?folder_id=root",
        headers=auth_headers(user)
    )
    assert [item["id"] for item in remaining.json()] == [file_record["id"]]


def test_users_cannot_manage_each_others_folders(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner = create_authenticated_user("folder_owner")
    other_user = create_authenticated_user("folder_other")
    folder = create_folder(client, owner).json()

    upload_to_other_folder = upload_file(
        client,
        other_user,
        b"encrypted content",
        folder_id=folder["id"]
    )
    list_other_folder = client.get(
        f"/api/folders?parent_id={folder['id']}",
        headers=auth_headers(other_user)
    )
    delete_other_folder = client.delete(
        f"/api/folders/{folder['id']}",
        headers=auth_headers(other_user)
    )

    assert upload_to_other_folder.status_code == 404
    assert list_other_folder.status_code == 404
    assert delete_other_folder.status_code == 404


def test_users_cannot_access_each_others_files(
    client: TestClient,
    create_authenticated_user: Callable
) -> None:
    owner = create_authenticated_user("owner")
    other_user = create_authenticated_user("other")
    upload_response = upload_file(client, owner, b"encrypted content")
    file_id = upload_response.json()["id"]

    other_list = client.get("/api/files", headers=auth_headers(other_user))
    other_download = client.get(
        f"/api/files/{file_id}/download",
        headers=auth_headers(other_user)
    )
    other_delete = client.delete(
        f"/api/files/{file_id}",
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
        "/api/files/upload",
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
    assert client.get("/api/files", headers=auth_headers(user)).json() == []


def test_file_routes_require_authentication(client: TestClient) -> None:
    assert client.get("/api/files").status_code == 401
    assert client.get("/api/files/1/download").status_code == 401
    assert client.delete("/api/files/1").status_code == 401
